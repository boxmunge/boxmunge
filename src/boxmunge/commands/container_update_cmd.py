# SPDX-License-Identifier: Apache-2.0
"""boxmunge container-update — daily container patch orchestrator."""

import fcntl
import sys
from typing import Any

from boxmunge.config import load_config, ConfigError
from boxmunge.container_update import (
    UpdateTarget, build_targets, update_target, read_target_state,
)
from boxmunge.log import log_operation, log_warning, log_error
from boxmunge.pause import is_paused
from boxmunge.paths import BoxPaths


def _dry_run_target(paths: BoxPaths, target: UpdateTarget) -> dict[str, Any]:
    """Pull and report what WOULD change for this target. No recreate.

    Returns a result dict with status='would_change' or 'no_change' or 'failed'.
    """
    from boxmunge.container_update import (
        _capture_service_digests, _detect_image_changes,
    )
    from boxmunge.docker import compose_pull, DockerError
    before = _capture_service_digests(target)
    try:
        compose_pull(target.project_dir, compose_files=target.compose_files)
    except DockerError as e:
        return {"name": target.name, "status": "failed", "reason": f"pull_failed: {e}",
                "previous_digests": before, "current_digests": before}
    changed = _detect_image_changes(target, before)
    if changed:
        return {"name": target.name, "status": "would_change",
                "previous_digests": before, "current_digests": changed}
    return {"name": target.name, "status": "no_change",
            "previous_digests": before, "current_digests": before}


def _send_summary_alert(paths: BoxPaths, results: list[dict[str, Any]]) -> None:
    """Send a single Pushover alert summarizing failed targets.

    Pushover is the operator's only out-of-band signal. If sending fails
    (config missing, network issue, etc.), log it loudly so the failure
    surfaces in the operational log and the next health run.
    """
    failed = [r for r in results if r["status"] == "failed"]
    if not failed:
        return
    try:
        from boxmunge.config import load_config
        from boxmunge.pushover import send_notification
        cfg = load_config(paths)
        po = cfg.get("pushover", {})
        names = ", ".join(r["name"] for r in failed)
        details = "; ".join(
            f"{r['name']}: {r.get('reason', 'failed')}" for r in failed
        )
        send_notification(
            po.get("user_key", ""), po.get("app_token", ""),
            "boxmunge container-update FAILURES",
            f"Failed targets: {names}\n\n{details}",
        )
    except Exception as e:
        log_error(
            "container-update", f"Pushover summary alert failed: {e}", paths,
            detail={"failed": [r["name"] for r in failed]},
        )


def run_container_update(
    paths: BoxPaths, *, force: bool = False, only: str | None = None,
    dry_run: bool = False,
) -> int:
    """Run the container update flow. Returns 0 on full success, 1 on any failure.

    When dry_run is True, captures digests and pulls but does NOT recreate
    containers. Reports which targets WOULD change. The pulled images remain
    in local Docker storage (harmless — they'll be used the next real run).
    """
    # Step 0: Lock
    paths.container_update_state.mkdir(parents=True, exist_ok=True)
    lock_file = open(paths.container_update_lock, "w")
    try:
        try:
            fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            log_operation("container-update", "Skipped: another container-update is in progress", paths)
            print("Another container-update is in progress, skipping.")
            return 0

        # Step 1: Probation gate (unless --force)
        if not force and paths.probation.exists():
            log_operation("container-update", "Skipped: platform in probation", paths)
            print("Platform is in probation, skipping container update.")
            return 0

        # Step 2: Load config
        try:
            config = load_config(paths)
        except ConfigError as e:
            log_error("container-update", f"Config error: {e}", paths)
            print(f"ERROR: {e}", file=sys.stderr)
            return 1

        cu = config.get("container_updates", {})
        if not cu.get("enabled", True):
            log_operation("container-update", "Skipped: container updates disabled", paths)
            print("Container updates disabled in config, skipping.")
            return 0

        # Step 3: Build target list
        targets = build_targets(paths, config)
        if only:
            targets = [t for t in targets if t.name == only]
            if not targets:
                print(f"ERROR: target '{only}' not found or not enrolled", file=sys.stderr)
                return 1

        # Step 4: Update Caddy first; abort cascade on failure
        results: list[dict[str, Any]] = []
        for target in targets:
            if target.is_caddy:
                result = (
                    _dry_run_target(paths, target) if dry_run
                    else update_target(paths, target)
                )
                results.append(result)
                if result["status"] == "failed":
                    log_error("container-update", "Aborted: Caddy update failed", paths)
                    _send_summary_alert(paths, results)
                    return 1

        # Step 5: Update user projects independently
        for target in targets:
            if target.is_caddy:
                continue
            if is_paused(target.name, paths):
                log_operation(
                    "container-update", "Skipped paused project", paths,
                    project=target.name,
                )
                continue
            try:
                if dry_run:
                    results.append(_dry_run_target(paths, target))
                else:
                    results.append(update_target(paths, target))
            except Exception as e:
                # Should not happen — update_target catches its own errors
                # but defense in depth: don't let one project crash the loop.
                log_error("container-update", f"Unhandled exception updating {target.name}: {e}", paths, project=target.name)
                results.append({"name": target.name, "status": "failed", "reason": f"exception: {e}"})

        # Step 6: Summary
        succeeded = [r["name"] for r in results if r["status"] == "succeeded"]
        failed = [r["name"] for r in results if r["status"] == "failed"]
        no_change = [r["name"] for r in results if r["status"] == "no_change"]
        log_operation(
            "container-update", "Run complete", paths,
            detail={"succeeded": succeeded, "failed": failed, "no_change": no_change},
        )
        if failed:
            _send_summary_alert(paths, results)
        print(f"\nSummary: {len(succeeded)} succeeded, {len(failed)} failed, {len(no_change)} no-change")
        return 0 if not failed else 1

    finally:
        try:
            fcntl.flock(lock_file, fcntl.LOCK_UN)
        except Exception:
            pass
        lock_file.close()


def cmd_container_update(args: list[str]) -> None:
    """CLI entry point."""
    force = "--force" in args
    dry_run = "--dry-run" in args
    # Positional target
    only = None
    for a in args:
        if a.startswith("-"):
            continue
        only = a
        break

    paths = BoxPaths()
    sys.exit(run_container_update(paths, force=force, only=only, dry_run=dry_run))
