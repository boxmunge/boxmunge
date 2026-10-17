# SPDX-License-Identifier: Apache-2.0
"""Container auto-update — pull, recreate, healthcheck, and rollback for image: services.

This module is invoked by `boxmunge container-update` (CLI) on a daily timer.
For each enrolled target (Caddy + opt-in user projects), it records the image
each service's containers run, pulls, recreates, and waits for healthcheck.
On failure it applies the configured strategy (leave_broken or
rollback_to_previous).

Services and containers come from the deployed inventory: the resolved
Compose model (so `include:`, `extends:` and `${VAR:-image}` resolve as `up`
resolves them) and containers found by their Compose labels. Images are
compared and restored by local image ID, the identity Docker commands
accept; registry digests are kept for display only.
"""
from __future__ import annotations

import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from boxmunge import docker_containers
from boxmunge.container_update_targets import UpdateTarget, persist_result
from boxmunge.compose_guard import ComposeRefused, compose_up_checked, compose_up_platform
from boxmunge.deployed_inventory import (
    DeployedService, InventoryError, load_deployed_inventory, pulled_services,
)
from boxmunge.docker import DockerError, compose_pull, tag_image
from boxmunge.docker_containers import ProjectContainer
from boxmunge.backup import BackupKind
from boxmunge.commands.backup_cmd import backup_locked
from boxmunge.commands.health_state import is_monitor_stopped
from boxmunge.lifecycle import is_blocked
from boxmunge.log import log_operation, log_warning, log_error
from boxmunge.notify import notify
from boxmunge.run_as import RunAsError, image_user_drift

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


# ---------------------------------------------------------------------------
# Per-target update flow
# ---------------------------------------------------------------------------

# Result status for a user project whose project lock was held.
SKIPPED_LOCKED = "skipped_locked"
# Result status for a user project the health monitor stopped.
SKIPPED_MONITOR_STOPPED = "monitor_stopped"

_HEALTHCHECK_TIMEOUT_SEC = 90
_HEALTHCHECK_POLL_INTERVAL_SEC = 3
_NO_HEALTHCHECK_GRACE_SEC = 30


class UpdateError(Exception):
    """A service the update covers has no identifiable image."""


def image_services(target: UpdateTarget) -> dict[str, DeployedService]:
    """The services an update pulls and recreates: those `up` starts from a
    registry image (deployed_inventory.pulled_services).

    Raises InventoryError when the deployed model or containers cannot be read.
    """
    return pulled_services(
        load_deployed_inventory(target.project_dir, target.compose_files, target.name))


def _managed(containers: tuple[ProjectContainer, ...] | list[ProjectContainer]) -> list[ProjectContainer]:
    """Containers `up` manages; `compose run` one-offs are not recreated."""
    return [c for c in containers if not c.oneoff]


def running_images(services: dict[str, DeployedService]) -> dict[str, ProjectContainer]:
    """For each service, a container standing for the image all its replicas run.

    Raises UpdateError when a service has no container, or its replicas run
    different images: then there is nothing reliable to compare a pull
    against or to roll back to, and treating it as "no change" would hide it.
    """
    running: dict[str, ProjectContainer] = {}
    for name, svc in services.items():
        managed = _managed(svc.containers)
        if not managed:
            raise UpdateError(
                f"service {name!r} has no container, so the image it runs is "
                f"unknown. Deploy or resume the project, then update again."
            )
        ids = sorted({c.image_id for c in managed})
        if len(ids) > 1:
            raise UpdateError(
                f"the containers of service {name!r} run different images "
                f"({', '.join(ids)}). Redeploy the project so they agree."
            )
        running[name] = managed[0]
    return running


def display_images(running: dict[str, ProjectContainer]) -> dict[str, str]:
    """{service: readable image reference} for logs and the state file."""
    return {name: c.image_ref for name, c in running.items()}


def detect_image_changes(
    services: dict[str, DeployedService], running: dict[str, ProjectContainer],
) -> dict[str, str]:
    """{service: pulled image reference} for services whose image reference
    now names a different image than their containers run.

    A pull does not restart containers, so the pulled image is read from the
    local image store and compared with the running one by image ID.
    """
    changed: dict[str, str] = {}
    for name, svc in services.items():
        assert svc.image is not None  # image_services keeps image services only
        pulled = docker_containers.local_image(svc.image)
        if pulled is None:
            raise UpdateError(
                f"service {name!r}: image {svc.image} is not in the local image "
                f"store after the pull."
            )
        if pulled.image_id != running[name].image_id:
            changed[name] = pulled.image_ref
    return changed


def one_shot_services(services: dict[str, DeployedService]) -> frozenset[str]:
    """Services whose containers had all run to completion before the update
    (exited 0, not restarted by their policy): a migration, say.

    Judged on the pre-update snapshot, because Compose's default restart
    policy is "no": a long-running service that an update makes exit 0 (a
    wrong CMD, a help text) looks the same afterwards, and must fail.
    """
    return frozenset(
        name for name, svc in services.items()
        if (managed := _managed(svc.containers))
        and all(c.finished_cleanly for c in managed)
    )


def _health_round(
    target: UpdateTarget, services: list[str], one_shots: frozenset[str],
    *, in_grace: bool,
) -> tuple[list[str], list[str]]:
    """One look at the services' containers: (still settling, unhealthy).

    A service without a container, or with one that is not running or
    reports unhealthy, is unhealthy, except a container of a one-shot
    service that ran to completion again. One without a healthcheck
    settles once the no-healthcheck grace period is over.
    """
    by_service: dict[str, list[ProjectContainer]] = defaultdict(list)
    for container in _managed(docker_containers.project_containers(target.name)):
        by_service[container.service].append(container)
    settling: list[str] = []
    unhealthy: list[str] = []
    for name in services:
        containers = [c for c in by_service.get(name, [])
                      if not (name in one_shots and c.finished_cleanly)]
        if not by_service.get(name):
            unhealthy.append(name)
        elif any(not c.running or c.health == "unhealthy" for c in containers):
            unhealthy.append(name)
        elif any(c.health == "starting" or (c.health is None and in_grace)
                 for c in containers):
            settling.append(name)
    return settling, unhealthy


def _wait_healthy(
    target: UpdateTarget, services: list[str], one_shots: frozenset[str] = frozenset(),
    timeout_sec: int = _HEALTHCHECK_TIMEOUT_SEC,
) -> tuple[bool, list[str]]:
    """Poll until every service's containers are healthy, or timeout.

    Returns (all_healthy, list_of_unhealthy_service_names). An unhealthy
    verdict is final; services still settling at the deadline count as
    unhealthy.
    """
    start = time.monotonic()
    deadline = start + timeout_sec
    settling = list(services)
    while time.monotonic() < deadline:
        in_grace = time.monotonic() - start < _NO_HEALTHCHECK_GRACE_SEC
        settling, unhealthy = _health_round(target, services, one_shots, in_grace=in_grace)
        if unhealthy:
            return False, unhealthy
        if not settling:
            return True, []
        time.sleep(_HEALTHCHECK_POLL_INTERVAL_SEC)
    return False, settling


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _recreate(paths: "BoxPaths", target: UpdateTarget) -> None:
    """Recreate the target's containers from its local images. A user
    project goes through the start checks. Raises DockerError."""
    if target.is_caddy:
        compose_up_platform(target.project_dir, target.compose_files, target.name, build=False)
    else:
        compose_up_checked(paths, target.name, component="container-update",
                           compose_files=target.compose_files, build=False)


def _maybe_rollback(
    paths: "BoxPaths", target: UpdateTarget, result: dict[str, Any],
    services: dict[str, DeployedService], running: dict[str, ProjectContainer],
    changed: dict[str, str],
) -> None:
    """If strategy is rollback_to_previous, point each changed service's image
    reference back at the image its containers ran before, and recreate."""
    if target.strategy != "rollback_to_previous":
        return

    result["rollback_attempted"] = True
    log_warning("container-update", f"Rolling back {target.name} to previous images", paths, project=target.name)

    for svc_name in changed:
        image = services[svc_name].image
        assert image is not None  # image_services keeps image services only
        try:
            tag_image(running[svc_name].image_id, image)
        except DockerError as e:
            log_error("container-update", f"Retag failed for {svc_name}: {e}", paths, project=target.name)
            result["rollback_succeeded"] = False
            return

    # Recreate from the now-retagged local images
    try:
        _recreate(paths, target)
        healthy, _ = _wait_healthy(target, list(services), one_shot_services(services))
    except DockerError as e:
        log_error("container-update", f"Rollback recreate failed: {e}", paths, project=target.name)
        result["rollback_succeeded"] = False
        return

    result["rollback_succeeded"] = healthy
    if not healthy:
        log_error("container-update", f"Rollback unhealthy for {target.name}", paths, project=target.name)
    else:
        log_operation("container-update", f"Rollback succeeded for {target.name}", paths, project=target.name)


def _new_result(target: UpdateTarget) -> dict[str, Any]:
    return {
        "name": target.name,
        "ts": _now(),
        "status": "succeeded",
        "rollback_attempted": False,
        "rollback_succeeded": None,
        "previous_digests": {},
        "current_digests": {},
        "reason": None,
    }


def lock_skipped(paths: "BoxPaths", target: UpdateTarget) -> dict[str, Any]:
    """The result for a user project whose project lock is held.

    Contention with a deploy, scan, or health tick is routine on a busy
    box, not a failure: skip (the caller retries once) and record nothing,
    so a project skipped day after day goes stale in the container-updates
    health check.
    """
    result = _new_result(target)
    result["status"] = SKIPPED_LOCKED
    result["reason"] = "project lock held by another operation"
    log_warning(
        "container-update",
        f"Skipped {target.name}: project lock held by another operation",
        paths, project=target.name,
    )
    return result


def update_target_locked(paths: "BoxPaths", target: UpdateTarget) -> dict[str, Any]:
    """Update a single target. Returns a result dict suitable for logging.

    The update core: for a user project the caller holds its project lock
    for the whole update (lifecycle check, pre-update backup, pull,
    recreate, health wait, rollback), so it cannot interleave with a
    deploy, stage, restore, CVE quarantine, or health tick
    (container_update_cmd.update_project). Caddy is not a project and has
    no project lock.
    """
    return _update_locked(paths, target, _new_result(target))


def _update_locked(
    paths: "BoxPaths", target: UpdateTarget, result: dict[str, Any],
) -> dict[str, Any]:
    """The update flow. Caller holds the project lock (user projects)."""
    # Checked under the lock: a CVE scan may have quarantined the project,
    # or the operator paused it, while this run was working on earlier
    # targets. Caddy targets are exempt because they are not user projects
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
        if is_monitor_stopped(target.name, paths):
            # A recreate would undo the health monitor's critical stop.
            log_operation(
                "container-update",
                f"Refused to update '{target.name}': stopped by the health monitor",
                paths, project=target.name,
            )
            result["status"] = SKIPPED_MONITOR_STOPPED
            return result

    # Step 1: What the target runs: its image services and the image each
    # one's containers were created from.
    try:
        services = image_services(target)
        running = running_images(services)
    except (InventoryError, UpdateError) as e:
        return _fail(paths, target, result, f"inventory_failed: {e}", before={})

    # Build-only projects (no image: services) have nothing to pull or
    # update. A `docker compose pull` on them errors ("no image to pull"),
    # which previously recorded the run as `failed` and surfaced a misleading
    # container-updates health warning. Record no_change with a fresh
    # timestamp — neither failed nor stale — and skip the pull/recreate. The
    # Caddy target always has an image: service, so it never short-circuits.
    if not services:
        result["status"] = "no_change"
        result["current_digests"] = {}
        log_operation(
            "container-update",
            f"No image: services in {target.name} (build-only) — nothing to pull",
            paths, project=target.name,
        )
        persist_result(paths, target, result, before={})
        return result

    before = display_images(running)
    result["previous_digests"] = before

    # Step 2: Pull
    try:
        compose_pull(target.project_dir, compose_files=target.compose_files,
                     project_name=target.name, services=sorted(services))
    except DockerError as e:
        return _fail(paths, target, result, f"pull_failed: {e}", before=before)

    # Step 3: Detect what changed (pulled local image vs running image, by ID)
    try:
        changed = detect_image_changes(services, running)
    except (UpdateError, DockerError) as e:
        return _fail(paths, target, result, f"inventory_failed: {e}", before=before)
    if not changed:
        result["status"] = "no_change"
        result["current_digests"] = before
        log_operation("container-update", f"No updates available for {target.name}", paths, project=target.name)
        persist_result(paths, target, result, before=before)
        return result

    # Step 3b: a service that runs as its image's own user would change who
    # writes its data with the new image; only a deploy decides that.
    if not target.is_caddy:
        try:
            drift = image_user_drift(paths, target.name, changed)
        except (DockerError, RunAsError) as e:
            return _fail(paths, target, result, f"inventory_failed: {e}", before=before)
        if drift:
            # The pull moved the tags; point them back, or the next restart of
            # any kind would recreate the services from the new images.
            try:
                for svc_name in changed:
                    tag_image(running[svc_name].image_id, str(services[svc_name].image))
            except DockerError as e:
                return _fail(paths, target, result, f"user_changed, and pointing the "
                             f"tags back failed: {e}", before=before)
            body = (f"Not updating {target.name}: {'; '.join(drift)}. These services run as "
                    f"their image's own user, so the new image would change who owns and "
                    f"writes their data; its tags point at the running images again. Review "
                    f"it, declare security.user if needed, and deploy {target.name}.")
            notify(paths, f"{target.name}: image user changed", body,
                   component="container-update", project=target.name, priority=1)
            return _fail(paths, target, result, "user_changed: " + "; ".join(drift),
                         before=before, message=body)

    # Step 4: Pre-update backup, only now that a recreate will happen. Pulling
    # leaves running containers untouched, so this still captures the data
    # as the current images left it; a no-change run takes no backup.
    if target.has_backup:
        rc = backup_locked(target.name, paths, kind=BackupKind.PREUPDATE)
        if rc != 0:
            return _fail(paths, target, result, "backup_failed", before=before,
                         message=f"Backup failed for {target.name}, aborting update")

    # Step 5: Recreate
    try:
        _recreate(paths, target)
    except ComposeRefused as e:
        # Nothing was recreated, so there is nothing to roll back.
        return _fail(paths, target, result, f"refused: {e}", before=before)
    except DockerError as e:
        result["status"] = "failed"
        result["reason"] = f"recreate_failed: {e}"
        log_error(
            "container-update", f"Recreate failed for {target.name}: {e}",
            paths, project=target.name,
            detail={"strategy": target.strategy, "reason": str(e), "previous_digests": before},
        )
        _maybe_rollback(paths, target, result, services, running, changed)
        persist_result(paths, target, result, before=before)
        return result

    # Step 6: Healthcheck wait, then record what the containers now run.
    try:
        healthy, unhealthy = _wait_healthy(target, list(services), one_shot_services(services))
        new_digests = _current_images(target, services)
    except DockerError as e:
        healthy, unhealthy, new_digests = False, [f"(docker: {e})"], {}
    result["current_digests"] = new_digests

    if not healthy:
        result["status"] = "failed"
        result["reason"] = f"unhealthy: {','.join(unhealthy)}"
        _maybe_rollback(paths, target, result, services, running, changed)
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

    persist_result(paths, target, result, before=before)
    return result


def _current_images(
    target: UpdateTarget, services: dict[str, DeployedService],
) -> dict[str, str]:
    """{service: readable image reference} the services' containers run now."""
    current: dict[str, str] = {}
    for container in _managed(docker_containers.project_containers(target.name)):
        if container.service in services:
            current.setdefault(container.service, container.image_ref)
    return current


def _fail(
    paths: "BoxPaths", target: UpdateTarget, result: dict[str, Any], reason: str,
    *, before: dict[str, str], message: str | None = None,
) -> dict[str, Any]:
    """Record a failed run that changed nothing, and return its result."""
    result["status"] = "failed"
    result["reason"] = reason
    log_error(
        "container-update", message or f"Update failed for {target.name}: {reason}",
        paths, project=target.name,
        detail={"strategy": target.strategy, "reason": reason, "previous_digests": before},
    )
    persist_result(paths, target, result, before=before)
    return result
