# SPDX-License-Identifier: Apache-2.0
"""boxmunge recover <project> — bring a health-monitor-stopped prod back up.

When the health monitor sees a critical smoke result it stops+removes the
project's containers and records ``status: critical_stopped``. Until now the
only way back was a full ``prod-deploy`` (re-upload the bundle, force a fresh
build live). ``recover`` is the missing first-class un-stop: it restarts the
*same* build the monitor stopped — no image pull, no rebuild — restores Caddy
routing, runs the smoke test, and resets health state.

Precondition: the project is in ``critical_stopped``, or staging's data
copy stopped it and crashed (the slot's production_stopped marker: recover
starts it again, as the health tick would). A *paused* project uses
``resume``; a CVE-*quarantined* project uses ``security resume`` (both have
their own safety checks) — recover refuses and points at the right command
rather than silently doing the wrong thing.
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from enum import Enum

from boxmunge.caddy import prepare_caddy_config
from boxmunge.compose import prepare_compose_override
from boxmunge.compose_guard import compose_up_checked
from boxmunge.docker import caddy_reload, DockerError
from boxmunge.fileutil import LockError, project_lock
from boxmunge.health_checks.smoke import run_smoke
from boxmunge.lifecycle import BlockReason, is_blocked
from boxmunge.legacy_stage import refuse_if_legacy_stage
from boxmunge.log import log_operation, log_error, log_warning
from boxmunge.manifest import load_manifest, ManifestError
from boxmunge.pause import is_paused
from boxmunge.paths import BoxPaths
from boxmunge.production_stopped import ProductionDownError, start_again_from
from boxmunge.staged_release import SlotError, load_slot
from boxmunge.state import read_state, write_state


class CopyStop(Enum):
    """What recover found of a staging copy's stop (_start_after_copy)."""
    NONE = "none"              # the slot records no stop
    RESTARTED = "restarted"    # production was started again
    UNREADABLE = "unreadable"  # the slot cannot name what was stopped
    FAILED = "failed"          # the start failed, said loudly; the marker is kept


def _held_by_lift(project_name: str, paths: BoxPaths) -> bool:
    """Paused / quarantined projects are routed to their dedicated recovery
    paths rather than restarted here (which would bypass those checks).
    Prints why when held."""
    if is_paused(project_name, paths):
        print(
            f"ERROR: Project '{project_name}' is paused, not monitor-stopped. "
            f"Use: boxmunge resume {project_name}",
            file=sys.stderr,
        )
        return True
    block = is_blocked(project_name, paths)
    if block and block.reason in (BlockReason.QUARANTINED, BlockReason.MIGRATING):
        print(f"ERROR: {block.refuse_message}", file=sys.stderr)
        return True
    return False


def _monitor_stopped_health(project_name: str, paths: BoxPaths, *,
                            quiet: bool = False) -> dict | None:
    """Return the health state if the project can be recovered, else None.

    Prints why on refusal; ``quiet`` leaves out "not monitor-stopped" (the
    caller has already started production for another reason).
    """
    if _held_by_lift(project_name, paths):
        return None
    health = read_state(paths.project_health_state(project_name))
    status = health.get("status", "unknown")
    if status != "critical_stopped":
        if not quiet:
            print(
                f"ERROR: Project '{project_name}' is not in a monitor-stopped "
                f"state (health status: {status}). Nothing to recover.",
                file=sys.stderr,
            )
        return None
    return health


def _copy_stop_pending(project_name: str, paths: BoxPaths) -> CopyStop | None:
    """Before the lock: UNREADABLE when the slot cannot say whether
    staging's data copy stopped production, RESTARTED when it says it did
    (recover would start it again), None otherwise."""
    try:
        meta = load_slot(paths, project_name)
    except SlotError:
        return CopyStop.UNREADABLE
    if meta is not None and meta.production_stopped is not None:
        return CopyStop.RESTARTED
    return None


def _start_after_copy(project_name: str, paths: BoxPaths) -> CopyStop:
    """Start production first if staging's data copy left it stopped. With
    an unreadable slot nothing can be named, so recover goes on to start
    production with its compose files, as the slot's messages tell the
    operator."""
    try:
        meta = load_slot(paths, project_name)
    except SlotError as e:
        print(f"  WARN: {project_name}'s staged slot cannot be read ({e}), so whether "
              f"staging's data copy stopped production cannot be told; starting "
              f"production with its compose files.")
        return CopyStop.UNREADABLE
    try:
        # A restart records last_started_at itself (the grace window).
        restarted = start_again_from(paths, project_name, meta, component="recover",
                                     alert=True)
    except ProductionDownError:
        return CopyStop.FAILED
    return CopyStop.RESTARTED if restarted else CopyStop.NONE


def run_recover(project_name: str, paths: BoxPaths, yes: bool = False) -> int:
    """Un-stop a health-monitor-stopped project. Returns 0 on success.

    Preconditions are checked before the prompt and again under the
    project lock, which the recovery holds throughout.
    """
    project_dir = paths.project_dir(project_name)
    if not project_dir.exists() or not (project_dir / "manifest.yml").exists():
        print(f"ERROR: Project not found: {project_name}", file=sys.stderr)
        return 1
    copy_stop = _copy_stop_pending(project_name, paths)
    health = {} if copy_stop else _monitor_stopped_health(project_name, paths)
    if health is None:
        return 1

    if not yes:
        reason = health.get("failure_reason", "")
        print(f"This will recover stopped '{project_name}':")
        if copy_stop is CopyStop.RESTARTED:
            print("  - Start the production containers that staging's data copy stopped")
        elif copy_stop is CopyStop.UNREADABLE:
            print("  - Bring production up with its compose files (the staged slot cannot "
                  "be read to name what staging's data copy stopped)")
        if reason:
            print(f"  - Stopped for: {reason}")
        print("  - Restart the SAME build (no image pull, no rebuild)")
        print("  - Restore Caddy routing + run smoke test")
        response = input("\nProceed? [y/N] ")
        if response.lower() != "y":
            print("Aborted.")
            return 1

    try:
        with project_lock(project_name, paths):
            return recover_locked(project_name, paths)
    except LockError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


def recover_locked(project_name: str, paths: BoxPaths) -> int:
    """Restart the stopped build. Caller holds the project lock."""
    if refuse_if_legacy_stage(paths, project_name):
        return 1
    copy = _start_after_copy(project_name, paths)
    if copy is CopyStop.FAILED:
        return 1
    if copy is CopyStop.UNREADABLE:
        if _held_by_lift(project_name, paths):
            return 1
        health = read_state(paths.project_health_state(project_name))
    else:
        restarted = copy is CopyStop.RESTARTED
        health = _monitor_stopped_health(project_name, paths, quiet=restarted)
        if health is None:
            if not restarted:
                return 1
            print(f"{project_name}: production started again after staging's data copy.")
            return 0
    try:
        manifest = load_manifest(paths.project_manifest(project_name))
    except ManifestError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    compose_files = ["compose.yml"]
    if paths.project_compose_override(project_name).exists():
        compose_files.append("compose.boxmunge.yml")

    # Start containers — no pull/rebuild, so the exact build the monitor
    # stopped comes back (recovery must be a faithful un-stop, not a silent
    # version change).
    print("  Starting containers...")
    try:
        compose_up_checked(paths, project_name, component="recover",
                           compose_files=compose_files, build=False)
    except DockerError as e:
        print(f"ERROR: compose up failed: {e}", file=sys.stderr)
        log_error("recover", f"compose up failed: {e}", paths,
                  project=project_name)
        return 1

    # Restore Caddy routing (site config was left intact by the monitor stop,
    # but regenerate + reload so routing re-resolves the fresh container).
    print("  Restoring Caddy routing...")
    try:
        prepare_caddy_config(paths, manifest)
        prepare_compose_override(paths, manifest, component="recover")
        caddy_reload(paths.caddy, paths.state)
    except (DockerError, OSError) as e:
        print(f"ERROR: Caddy restore failed: {e}", file=sys.stderr)
        log_error("recover", f"Caddy restore failed: {e}", paths,
                  project=project_name)
        return 1

    # Smoke test.
    print("  Running smoke test...")
    smoke_ok, smoke_msg = run_smoke(project_name, paths)

    now = datetime.now(timezone.utc).isoformat()
    if smoke_ok:
        # Clear the critical_stopped state so `status` reflects reality.
        write_state(paths.project_health_state(project_name), {
            "last_check": now,
            "status": "ok",
            "consecutive_failures": 0,
            "alerted": False,
            "last_alert": health.get("last_alert", ""),
            "last_success": now,
            "failure_reason": "",
        })
    else:
        print(f"  WARN: Smoke test failed: {smoke_msg}")
        log_warning("recover", f"Smoke failed after recover: {smoke_msg}",
                    paths, project=project_name)

    # Bump last_started_at so the health-check grace window suppresses the
    # 1-second start-up race (mirrors deploy/resume).
    deploy_state_path = paths.project_deploy_state(project_name)
    deploy_state = read_state(deploy_state_path)
    deploy_state["last_started_at"] = now
    write_state(deploy_state_path, deploy_state)

    log_operation("recover", "Recovered monitor-stopped project", paths,
                  project=project_name,
                  detail={"smoke_ok": smoke_ok, "smoke_msg": smoke_msg})

    if smoke_ok:
        print(f"Project '{project_name}' recovered. Smoke: PASS")
        return 0
    # Container is back up, but smoke still fails — report honestly so the
    # operator keeps investigating rather than assuming a clean recovery.
    print(f"Project '{project_name}' restarted, but smoke still FAILS: {smoke_msg}")
    return 1


def cmd_recover(args: list[str]) -> None:
    from boxmunge.commands.argv import parse_args, require_project_name
    parsed = parse_args(
        "recover", args, flags={"--yes"}, min_positional=1, max_positional=1,
    )
    project = require_project_name("recover", parsed.positional[0])
    yes = parsed.has("--yes")
    paths = BoxPaths()
    sys.exit(run_recover(project, paths, yes=yes))
