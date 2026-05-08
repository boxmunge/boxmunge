# SPDX-License-Identifier: Apache-2.0
"""Container auto-update — pull, recreate, healthcheck, and rollback for image: services.

This module is invoked by `boxmunge container-update` (CLI) on a daily timer.
For each enrolled target (Caddy + opt-in user projects), it captures the
current image digest, pulls, recreates, and waits for healthcheck. On failure
it applies the configured strategy (leave_broken or rollback_to_previous).
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from boxmunge.fileutil import atomic_write_text
from boxmunge.manifest import load_manifest, ManifestError
from boxmunge.docker import (
    DockerError, compose_pull, compose_up,
    container_image_digest, image_digest, tag_image, container_health,
    container_running,
)
from boxmunge.commands.backup_cmd import run_backup
from boxmunge.lifecycle import is_blocked
from boxmunge.log import log_operation, log_warning, log_error

if TYPE_CHECKING:
    from pathlib import Path
    from boxmunge.paths import BoxPaths


VALID_STRATEGIES = {"leave_broken", "rollback_to_previous"}


@dataclass
class UpdateTarget:
    """A single target for container update — Caddy or a user project."""
    name: str
    project_dir: "Path"
    compose_files: list[str]
    strategy: str
    has_backup: bool
    is_caddy: bool = False


def resolve_strategy(box: dict[str, Any], project: dict[str, Any] | None) -> str:
    """Resolve effective strategy: project override wins over box default."""
    if project and "strategy" in project:
        return project["strategy"]
    return box.get("strategy", "leave_broken")


def _build_caddy_target(paths: "BoxPaths", box_cu: dict[str, Any]) -> UpdateTarget:
    return UpdateTarget(
        name="caddy",
        project_dir=paths.caddy,
        compose_files=["compose.yml"],
        strategy=resolve_strategy(box_cu, project=None),
        has_backup=False,
        is_caddy=True,
    )


def _build_project_target(
    paths: "BoxPaths", box_cu: dict[str, Any], project_dir: "Path"
) -> UpdateTarget | None:
    """Build a target for a user project, or None if it should be skipped."""
    manifest_path = project_dir / "manifest.yml"
    if not manifest_path.exists():
        return None
    try:
        manifest = load_manifest(manifest_path)
    except ManifestError:
        return None

    proj_cu = manifest.get("container_updates", {})
    if proj_cu.get("enabled") is False:
        return None

    name = manifest.get("project", project_dir.name)
    compose_files = ["compose.yml"]
    override = paths.project_compose_override(name)
    if override.exists():
        compose_files.append("compose.boxmunge.yml")

    has_backup = bool(manifest.get("backup", {}).get("dump_command"))

    return UpdateTarget(
        name=name,
        project_dir=project_dir,
        compose_files=compose_files,
        strategy=resolve_strategy(box_cu, proj_cu),
        has_backup=has_backup,
    )


def build_targets(paths: "BoxPaths", config: dict[str, Any]) -> list[UpdateTarget]:
    """Build the ordered list of update targets: Caddy first, then projects.

    Returns an empty list if container_updates.enabled is False at the box level.
    """
    box_cu = config.get("container_updates", {})
    if not box_cu.get("enabled", True):
        return []

    targets: list[UpdateTarget] = [_build_caddy_target(paths, box_cu)]

    if paths.projects.exists():
        for project_dir in sorted(paths.projects.iterdir()):
            if not project_dir.is_dir():
                continue
            target = _build_project_target(paths, box_cu, project_dir)
            if target is not None:
                targets.append(target)

    return targets


def read_target_state(paths: "BoxPaths", name: str) -> dict[str, Any] | None:
    """Read state file. None if missing. Raises on corrupt JSON."""
    import logging
    state_path = paths.container_update_target_state(name)
    if not state_path.exists():
        return None
    try:
        return json.loads(state_path.read_text())
    except json.JSONDecodeError as e:
        logging.getLogger("boxmunge").error("Corrupt JSON in %s: %s", state_path, e)
        raise


def write_target_state(paths: "BoxPaths", name: str, state: dict[str, Any]) -> None:
    """Write the state file for a target atomically."""
    paths.container_update_state.mkdir(parents=True, exist_ok=True)
    state_path = paths.container_update_target_state(name)
    atomic_write_text(state_path, json.dumps(state, indent=2) + "\n")


# ---------------------------------------------------------------------------
# Per-target update flow
# ---------------------------------------------------------------------------

_HEALTHCHECK_TIMEOUT_SEC = 90
_HEALTHCHECK_POLL_INTERVAL_SEC = 3
_NO_HEALTHCHECK_GRACE_SEC = 30


def _services_with_image(target: UpdateTarget) -> dict[str, str]:
    """Return {service_name: container_name} for image: services in this target.

    For Caddy, returns {"caddy": "boxmunge-caddy"}.
    For user projects, parses the compose file(s) for services with `image:`
    directives and uses the configured container_name (or "<project>_<service>_1"
    convention if not set).
    """
    import yaml
    services: dict[str, str] = {}
    for cf in target.compose_files:
        path = target.project_dir / cf
        if not path.exists():
            continue
        try:
            data = yaml.safe_load(path.read_text()) or {}
        except yaml.YAMLError:
            continue
        for svc_name, svc in (data.get("services") or {}).items():
            if not isinstance(svc, dict):
                continue
            if "image" not in svc:
                continue  # build: services excluded in phase 1
            cname = svc.get("container_name") or f"{target.name}-{svc_name}-1"
            services[svc_name] = cname
    return services


def _capture_service_digests(target: UpdateTarget) -> dict[str, str]:
    """Snapshot the current image digest of each image: service in the target."""
    digests: dict[str, str] = {}
    for svc_name, container_name in _services_with_image(target).items():
        d = container_image_digest(container_name)
        if d:
            digests[svc_name] = d
    return digests


def _wait_healthy(target: UpdateTarget, timeout_sec: int = _HEALTHCHECK_TIMEOUT_SEC) -> tuple[bool, list[str]]:
    """Poll until all image: services report healthy or timeout.

    Returns (all_healthy, list_of_unhealthy_service_names). Services with no
    healthcheck defined are treated as healthy if the container has been
    running for at least _NO_HEALTHCHECK_GRACE_SEC.
    """
    deadline = time.monotonic() + timeout_sec
    services = _services_with_image(target)
    grace_start = time.monotonic()
    while time.monotonic() < deadline:
        unhealthy: list[str] = []
        all_ok = True
        for svc_name, container_name in services.items():
            status = container_health(container_name)
            if status is None:
                # None means either no healthcheck or container doesn't exist.
                if not container_running(container_name):
                    # Container is gone or never started — treat as unhealthy.
                    unhealthy.append(svc_name)
                    all_ok = False
                else:
                    # Container is running but has no healthcheck — apply grace period.
                    if time.monotonic() - grace_start < _NO_HEALTHCHECK_GRACE_SEC:
                        all_ok = False
                    # After grace, treat as healthy.
            elif status == "healthy":
                pass
            elif status in ("starting", "unhealthy"):
                if status == "unhealthy":
                    unhealthy.append(svc_name)
                all_ok = False
        if all_ok and not unhealthy:
            return True, []
        if unhealthy:
            # An unhealthy verdict is final
            return False, unhealthy
        time.sleep(_HEALTHCHECK_POLL_INTERVAL_SEC)
    # Timed out — collect final status
    final_unhealthy = [
        svc for svc, cn in services.items()
        if container_health(cn) != "healthy" and container_health(cn) is not None
    ]
    return False, final_unhealthy or list(services.keys())


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _detect_image_changes(
    target: UpdateTarget,
    before: dict[str, str],
) -> dict[str, str]:
    """Return {service_name: new_digest} for services whose locally-pulled
    image digest differs from the running container's digest.

    Compares the post-pull local image digest (image_digest of the compose
    file's `image:` ref) against the pre-pull running container digest.
    A pull does NOT restart containers, so we cannot detect changes by
    re-snapshotting running containers — we must inspect the local image.
    """
    import yaml
    changed: dict[str, str] = {}
    for cf in target.compose_files:
        path = target.project_dir / cf
        if not path.exists():
            continue
        try:
            data = yaml.safe_load(path.read_text()) or {}
        except yaml.YAMLError:
            continue
        for svc_name, svc in (data.get("services") or {}).items():
            if not isinstance(svc, dict) or "image" not in svc:
                continue
            local_digest = image_digest(svc["image"])
            previous = before.get(svc_name)
            if local_digest and local_digest != previous:
                changed[svc_name] = local_digest
    return changed


def _maybe_rollback(
    paths: "BoxPaths", target: UpdateTarget,
    result: dict[str, Any], before: dict[str, str],
) -> None:
    """If strategy is rollback_to_previous, retag previous digests and recreate."""
    if target.strategy != "rollback_to_previous":
        return

    result["rollback_attempted"] = True
    log_warning("container-update", f"Rolling back {target.name} to previous digests", paths, project=target.name)

    import yaml
    for cf in target.compose_files:
        path = target.project_dir / cf
        if not path.exists():
            continue
        data = yaml.safe_load(path.read_text()) or {}
        for svc_name, svc in (data.get("services") or {}).items():
            if not isinstance(svc, dict) or "image" not in svc:
                continue
            prev_digest = before.get(svc_name)
            if not prev_digest:
                continue
            # Retag: image_ref:tag -> previous digest
            try:
                tag_image(prev_digest, svc["image"])
            except DockerError as e:
                log_error("container-update", f"Retag failed for {svc_name}: {e}", paths, project=target.name)
                result["rollback_succeeded"] = False
                return

    # Recreate from the now-retagged local images
    try:
        compose_up(target.project_dir, compose_files=target.compose_files, build=False)
    except DockerError as e:
        log_error("container-update", f"Rollback recreate failed: {e}", paths, project=target.name)
        result["rollback_succeeded"] = False
        return

    healthy, _ = _wait_healthy(target)
    result["rollback_succeeded"] = healthy
    if not healthy:
        log_error("container-update", f"Rollback unhealthy for {target.name}", paths, project=target.name)
    else:
        log_operation("container-update", f"Rollback succeeded for {target.name}", paths, project=target.name)


def _persist_result(
    paths: "BoxPaths", target: UpdateTarget,
    result: dict[str, Any], before: dict[str, str] | None,
) -> None:
    """Update the per-target state file with this run's outcome.

    previous_digests is only updated when a successful change occurred —
    we preserve the prior previous_digests on no-change or failed runs so
    that any future rollback can still find the older digest.
    """
    existing = read_target_state(paths, target.name) or {}
    state = {
        "last_check": result["ts"],
        "last_change": result["ts"] if result["status"] == "succeeded" else existing.get("last_change"),
        "last_status": result["status"],
        "current_digests": result.get("current_digests") or before or {},
        "previous_digests": (
            before
            if result["status"] == "succeeded" and before != result.get("current_digests")
            else existing.get("previous_digests", before or {})
        ),
    }
    write_target_state(paths, target.name, state)


def update_target(paths: "BoxPaths", target: UpdateTarget) -> dict[str, Any]:
    """Update a single target. Returns a result dict suitable for logging."""
    result: dict[str, Any] = {
        "name": target.name,
        "ts": _now(),
        "status": "succeeded",
        "rollback_attempted": False,
        "rollback_succeeded": None,
        "previous_digests": {},
        "current_digests": {},
        "reason": None,
    }

    # Defense-in-depth: callers of update_target SHOULD already filter
    # blocked projects (see container_update_cmd's run_container_update).
    # If a future direct caller forgets, refuse to pull/recreate here
    # too — Caddy targets are exempt because they are not user projects
    # and have no lifecycle state.
    if not target.is_caddy:
        block = is_blocked(target.name, paths)
        if block:
            log_operation(
                "container-update",
                f"Refused to update {block.reason.value} project "
                f"'{target.name}'",
                paths, project=target.name,
            )
            result["status"] = block.reason.value
            return result

    # Step 1: Pre-update backup (if applicable)
    if target.has_backup:
        rc = run_backup(target.name, paths)
        if rc != 0:
            result["status"] = "failed"
            result["reason"] = "backup_failed"
            log_error(
                "container-update", f"Backup failed for {target.name}, aborting update",
                paths, project=target.name,
                detail={"strategy": target.strategy, "reason": "backup_failed"},
            )
            _persist_result(paths, target, result, before=None)
            return result

    # Step 2: Capture current digests
    before = _capture_service_digests(target)
    result["previous_digests"] = before

    # Step 3: Pull
    try:
        compose_pull(target.project_dir, compose_files=target.compose_files)
    except DockerError as e:
        result["status"] = "failed"
        result["reason"] = f"pull_failed: {e}"
        log_error(
            "container-update", f"Pull failed for {target.name}: {e}",
            paths, project=target.name,
            detail={"strategy": target.strategy, "reason": str(e), "previous_digests": before},
        )
        _persist_result(paths, target, result, before=before)
        return result

    # Step 4: Detect what changed (compares local image digest vs running digest)
    changed = _detect_image_changes(target, before)
    if not changed:
        result["status"] = "no_change"
        result["current_digests"] = before
        log_operation("container-update", f"No updates available for {target.name}", paths, project=target.name)
        _persist_result(paths, target, result, before=before)
        return result

    # Step 5: Recreate
    try:
        compose_up(target.project_dir, compose_files=target.compose_files, build=False)
    except DockerError as e:
        result["status"] = "failed"
        result["reason"] = f"recreate_failed: {e}"
        log_error(
            "container-update", f"Recreate failed for {target.name}: {e}",
            paths, project=target.name,
            detail={"strategy": target.strategy, "reason": str(e), "previous_digests": before},
        )
        _maybe_rollback(paths, target, result, before)
        _persist_result(paths, target, result, before=before)
        return result

    # Step 6: Healthcheck wait
    healthy, unhealthy = _wait_healthy(target)
    # Capture digests after recreate — containers are now running the new images.
    new_digests = _capture_service_digests(target)
    result["current_digests"] = new_digests

    if not healthy:
        result["status"] = "failed"
        result["reason"] = f"unhealthy: {','.join(unhealthy)}"
        _maybe_rollback(paths, target, result, before)
        log_error(
            "container-update",
            f"Healthcheck failed for {target.name} services: {unhealthy}",
            paths, project=target.name,
            detail={
                "strategy": target.strategy,
                "failed_services": unhealthy,
                "previous_digests": before,
                "current_digests": new_digests,
                "rollback_attempted": result["rollback_attempted"],
                "rollback_succeeded": result["rollback_succeeded"],
            },
        )
    else:
        log_operation(
            "container-update", f"Updated {target.name}", paths, project=target.name,
            detail={"previous": before, "current": new_digests},
        )

    _persist_result(paths, target, result, before=before)
    return result
