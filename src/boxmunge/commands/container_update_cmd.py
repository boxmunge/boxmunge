# SPDX-License-Identifier: Apache-2.0
"""boxmunge container-update — daily container patch orchestrator."""

import fcntl
import os
import sys
from typing import Any

from boxmunge.config import load_config, ConfigError
from boxmunge.commands.health_state import is_monitor_stopped
from boxmunge.container_update import (
    SKIPPED_LOCKED, SKIPPED_MONITOR_STOPPED, lock_skipped, update_target_locked,
)
from boxmunge.container_update_targets import UpdateTarget, build_targets
from boxmunge.fileutil import LockError, open_regular_nofollow, project_lock
from boxmunge.lifecycle import BlockReason, is_blocked
from boxmunge.log import log_operation, log_error, log_warning
from boxmunge.notify import notify
from boxmunge.pause import pause_incomplete
from boxmunge.paths import BoxPaths


def _dry_run_target(paths: BoxPaths, target: UpdateTarget) -> dict[str, Any]:
    """Pull and report what WOULD change for this target. No recreate.

    Returns a result dict with status='would_change' or 'no_change' or 'failed'.
    """
    from boxmunge.container_update import (
        UpdateError, detect_image_changes, display_images, image_services,
        running_images,
    )
    from boxmunge.deployed_inventory import InventoryError
    from boxmunge.docker import compose_pull, DockerError
    try:
        services = image_services(target)
        running = running_images(services)
    except (InventoryError, UpdateError) as e:
        return {"name": target.name, "status": "failed",
                "reason": f"inventory_failed: {e}",
                "previous_digests": {}, "current_digests": {}}
    # Build-only projects have no image: services to pull — a pull would
    # error. Report no_change without attempting it (mirrors update_target_locked).
    if not services:
        return {"name": target.name, "status": "no_change",
                "previous_digests": {}, "current_digests": {}}
    before = display_images(running)
    try:
        compose_pull(target.project_dir, compose_files=target.compose_files,
                     project_name=target.name)
    except DockerError as e:
        return {"name": target.name, "status": "failed", "reason": f"pull_failed: {e}",
                "previous_digests": before, "current_digests": before}
    try:
        changed = detect_image_changes(services, running)
    except (UpdateError, DockerError) as e:
        return {"name": target.name, "status": "failed",
                "reason": f"inventory_failed: {e}",
                "previous_digests": before, "current_digests": before}
    if changed:
        return {"name": target.name, "status": "would_change",
                "previous_digests": before, "current_digests": changed}
    return {"name": target.name, "status": "no_change",
            "previous_digests": before, "current_digests": before}


def _send_summary_alert(paths: BoxPaths, results: list[dict[str, Any]]) -> None:
    """Send a single Pushover alert summarizing failed targets.

    Pushover is the operator's only out-of-band signal; ``notify`` logs
    any non-delivery so it surfaces in the log and the next health run.
    """
    failed = [r for r in results if r["status"] == "failed"]
    if not failed:
        return
    names = ", ".join(r["name"] for r in failed)
    details = "; ".join(f"{r['name']}: {r.get('reason', 'failed')}" for r in failed)
    notify(
        paths, "boxmunge container-update FAILURES",
        f"Failed targets: {names}\n\n{details}",
        component="container-update",
    )


def _update_one(paths: BoxPaths, target: UpdateTarget, dry_run: bool) -> dict[str, Any]:
    try:
        if dry_run:
            return _dry_run_target(paths, target)
        return update_target_locked(paths, target)
    except Exception as e:
        # Should not happen — update_target_locked catches its own errors
        # but defense in depth: don't let one project crash the loop.
        log_error("container-update", f"Unhandled exception updating {target.name}: {e}",
                  paths, project=target.name)
        return {"name": target.name, "status": "failed", "reason": f"exception: {e}"}


def update_project(paths: BoxPaths, target: UpdateTarget, dry_run: bool) -> dict[str, Any]:
    """One user project, entirely under its project lock: its lifecycle state
    is read while the lock is held, so a pause or quarantine that lands while
    the run works on other targets is honoured."""
    try:
        with project_lock(target.name, paths):
            return _update_project_locked(paths, target, dry_run)
    except LockError:
        return lock_skipped(paths, target)


def _update_project_locked(paths: BoxPaths, target: UpdateTarget,
                        dry_run: bool) -> dict[str, Any]:
    # A CVE-quarantined project must NOT be pulled or recreated by the
    # daily container-update cron — that would silently un-quarantine on
    # the next image change. Skip entirely (no dry-run pre-fetch either;
    # the project is intentionally stopped, not paused for resume).
    #
    # Paused projects DO get a dry-run pre-fetch so resume time stays short
    # and the operator sees pending updates in the log.
    block = is_blocked(target.name, paths)
    if block and block.reason is BlockReason.QUARANTINED:
        log_operation("container-update", block.skip_message, paths, project=target.name)
        return {"name": target.name, "status": "quarantined",
                "previous_digests": {}, "current_digests": {}}
    if block and block.reason is BlockReason.PAUSED:
        return _prefetch_paused(paths, target)
    if is_monitor_stopped(target.name, paths):
        # Pulling and recreating would undo the health monitor's critical
        # stop; `recover` is the way back.
        log_operation("container-update", "Skipped project stopped by the health monitor",
                      paths, project=target.name)
        return {"name": target.name, "status": SKIPPED_MONITOR_STOPPED,
                "previous_digests": {}, "current_digests": {}}
    return _update_one(paths, target, dry_run)


def _prefetch_paused(paths: BoxPaths, target: UpdateTarget) -> dict[str, Any]:
    """Dry-run pull for a paused project: nothing is recreated. Failures
    are non-fatal (e.g. registry outage): this is best-effort visibility."""
    if pause_incomplete(target.name, paths):
        # Its containers may still be serving on the current images, and
        # nothing here updates them: say so rather than call it paused.
        log_warning("container-update", "Pause incomplete: the project may still be "
                    "serving on its current images, which are not updated while it "
                    f"is paused; run `pause {target.name}` again to finish, or "
                    f"`resume {target.name}`", paths, project=target.name)
    try:
        result = _dry_run_target(paths, target)
    except Exception as e:
        result = {
            "name": target.name, "status": "failed",
            "reason": f"dry_run_exception: {e}",
            "previous_digests": {}, "current_digests": {},
        }
    pending = sorted((result.get("current_digests") or {}).keys()
                     if result.get("status") == "would_change" else [])
    checked = result.get("status") != "failed"
    # Reframe status to 'paused' so the run summary doesn't count it as failed.
    result["status"] = "paused"
    result["pending_services"] = pending
    if not checked:
        log_warning(
            "container-update",
            f"Skipped paused project; could not check for pending "
            f"updates: {result.get('reason')}",
            paths, project=target.name,
        )
        return result
    msg = (f"Skipped paused project (pending updates: {', '.join(pending)})" if pending
           else "Skipped paused project (no pending updates)")
    log_operation("container-update", msg, paths, project=target.name,
                  detail={"pending_services": pending})
    return result


def _retry_locked(
    paths: BoxPaths, targets: list[UpdateTarget], results: list[dict[str, Any]],
    dry_run: bool,
) -> list[dict[str, Any]]:
    """Retry each lock-skipped project once; report any still busy."""
    by_name = {t.name: t for t in targets}
    retried: list[dict[str, Any]] = []
    for result in results:
        if result["status"] == SKIPPED_LOCKED:
            result = update_project(paths, by_name[result["name"]], dry_run)
            if result["status"] == SKIPPED_LOCKED:
                print(
                    f"Skipped {result['name']}: another operation holds its "
                    f"project lock. It will be updated on the next run."
                )
        retried.append(result)
    return retried


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
    # state/ is deploy-writable: open("w") would follow a planted symlink and
    # truncate its target as root. Same lock file and mode as before.
    lock_file = os.fdopen(open_regular_nofollow(
        paths.container_update_lock, os.O_WRONLY | os.O_CREAT, 0o644), "w")
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
                    else update_target_locked(paths, target)
                )
                results.append(result)
                if result["status"] == "failed":
                    log_error("container-update", "Aborted: Caddy update failed", paths)
                    _send_summary_alert(paths, results)
                    return 1

        # Step 5: Update user projects independently
        for target in targets:
            if not target.is_caddy:
                results.append(update_project(paths, target, dry_run))

        # Step 5b: a project whose lock was held (a deploy, scan, or health
        # tick in progress) gets one more try now the others are done.
        results = _retry_locked(paths, targets, results, dry_run)

        # Step 6: Summary
        succeeded = [r["name"] for r in results if r["status"] == "succeeded"]
        failed = [r["name"] for r in results if r["status"] == "failed"]
        no_change = [r["name"] for r in results if r["status"] == "no_change"]
        skipped = [r["name"] for r in results if r["status"] == SKIPPED_LOCKED]
        log_operation(
            "container-update", "Run complete", paths,
            detail={"succeeded": succeeded, "failed": failed,
                    "no_change": no_change, "skipped_locked": skipped},
        )
        if failed:
            _send_summary_alert(paths, results)
        print(
            f"\nSummary: {len(succeeded)} succeeded, {len(failed)} failed, "
            f"{len(no_change)} no-change, {len(skipped)} skipped (busy)"
        )
        return 0 if not failed else 1

    finally:
        try:
            fcntl.flock(lock_file, fcntl.LOCK_UN)
        except OSError:
            pass
        lock_file.close()


def cmd_container_update(args: list[str]) -> None:
    """CLI entry point."""
    from boxmunge.commands.argv import parse_args
    parsed = parse_args(
        "container-update", args, flags={"--force", "--dry-run"},
        max_positional=1,
    )
    only = parsed.positional[0] if parsed.positional else None
    paths = BoxPaths()
    sys.exit(run_container_update(
        paths, force=parsed.has("--force"), only=only,
        dry_run=parsed.has("--dry-run"),
    ))
