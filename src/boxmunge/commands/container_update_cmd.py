# SPDX-License-Identifier: Apache-2.0
"""boxmunge container-update — daily container patch orchestrator."""

import fcntl
import sys
from typing import Any

from boxmunge.config import load_config, ConfigError
from boxmunge.container_update import SKIPPED_LOCKED, update_target
from boxmunge.container_update_targets import UpdateTarget, build_targets
from boxmunge.lifecycle import BlockReason, is_blocked
from boxmunge.log import log_operation, log_error
from boxmunge.notify import notify
from boxmunge.paths import BoxPaths


def _dry_run_target(paths: BoxPaths, target: UpdateTarget) -> dict[str, Any]:
    """Pull and report what WOULD change for this target. No recreate.

    Returns a result dict with status='would_change' or 'no_change' or 'failed'.
    """
    from boxmunge.container_update import (
        _capture_service_digests, _detect_image_changes, _services_with_image,
    )
    from boxmunge.docker import compose_pull, DockerError
    # Build-only projects have no image: services to pull — a pull would
    # error. Report no_change without attempting it (mirrors update_target).
    if not _services_with_image(target):
        return {"name": target.name, "status": "no_change",
                "previous_digests": {}, "current_digests": {}}
    before = _capture_service_digests(target)
    try:
        compose_pull(target.project_dir, compose_files=target.compose_files,
                     project_name=target.name)
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
        return update_target(paths, target)
    except Exception as e:
        # Should not happen — update_target catches its own errors
        # but defense in depth: don't let one project crash the loop.
        log_error("container-update", f"Unhandled exception updating {target.name}: {e}",
                  paths, project=target.name)
        return {"name": target.name, "status": "failed", "reason": f"exception: {e}"}


def _retry_locked(
    paths: BoxPaths, targets: list[UpdateTarget], results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Retry each lock-skipped project once; report any still busy."""
    by_name = {t.name: t for t in targets}
    retried: list[dict[str, Any]] = []
    for result in results:
        if result["status"] == SKIPPED_LOCKED:
            result = _update_one(paths, by_name[result["name"]], dry_run=False)
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
            # A CVE-quarantined project must NOT be pulled or
            # recreated by the daily container-update cron — that would
            # silently un-quarantine on the next image change. Skip
            # entirely (no dry-run pre-fetch either; the project is
            # intentionally stopped, not paused for resume).
            #
            # Paused projects DO get a dry-run pre-fetch so resume time
            # stays short and the operator sees pending updates in the
            # log. Different action per reason — dispatch on block.reason.
            block = is_blocked(target.name, paths)
            if block and block.reason is BlockReason.QUARANTINED:
                log_operation(
                    "container-update", block.skip_message,
                    paths, project=target.name,
                )
                results.append({
                    "name": target.name, "status": "quarantined",
                    "previous_digests": {}, "current_digests": {},
                })
                continue
            if block and block.reason is BlockReason.PAUSED:
                # Pre-fetch images for paused projects: dry-run pulls (no
                # apply) so resume time stays short, and we surface what's
                # pending so the operator can see queued updates in the log.
                # Failures here MUST be non-fatal (e.g. registry outage) —
                # this is best-effort visibility, not a hard requirement.
                try:
                    paused_result = _dry_run_target(paths, target)
                except Exception as e:
                    paused_result = {
                        "name": target.name, "status": "failed",
                        "reason": f"dry_run_exception: {e}",
                        "previous_digests": {}, "current_digests": {},
                    }
                pending = sorted((paused_result.get("current_digests") or {}).keys()
                                 if paused_result.get("status") == "would_change" else [])
                # Reframe status to 'paused' so the run summary doesn't count it as failed.
                paused_result["status"] = "paused"
                paused_result["pending_services"] = pending
                results.append(paused_result)
                if pending:
                    msg = f"Skipped paused project (pending updates: {', '.join(pending)})"
                else:
                    msg = "Skipped paused project (no pending updates)"
                log_operation(
                    "container-update", msg, paths,
                    project=target.name,
                    detail={"pending_services": pending},
                )
                continue
            results.append(_update_one(paths, target, dry_run))

        # Step 5b: a project whose lock was held (a deploy, scan, or health
        # tick in progress) gets one more try now the others are done.
        results = _retry_locked(paths, targets, results)

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
