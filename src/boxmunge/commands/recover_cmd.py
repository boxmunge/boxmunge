# SPDX-License-Identifier: Apache-2.0
"""boxmunge recover <project> — bring a health-monitor-stopped prod back up.

When the health monitor sees a critical smoke result it stops+removes the
project's containers and records ``status: critical_stopped``. Until now the
only way back was a full ``prod-deploy`` (re-upload the bundle, force a fresh
build live). ``recover`` is the missing first-class un-stop: it restarts the
*same* build the monitor stopped — no image pull, no rebuild — restores Caddy
routing, runs the smoke test, and resets health state.

Precondition: the project is in ``critical_stopped``. A *paused* project uses
``resume``; a CVE-*quarantined* project uses ``security resume`` (both have
their own safety checks) — recover refuses and points at the right command
rather than silently doing the wrong thing.
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone

from boxmunge.caddy import prepare_caddy_config
from boxmunge.compose import prepare_compose_override
from boxmunge.docker import compose_up, caddy_reload, DockerError
from boxmunge.fileutil import LockError, project_lock
from boxmunge.health_checks.smoke import run_smoke
from boxmunge.lifecycle import BlockReason, is_blocked
from boxmunge.log import log_operation, log_error, log_warning
from boxmunge.manifest import load_manifest, ManifestError
from boxmunge.pause import is_paused
from boxmunge.paths import BoxPaths
from boxmunge.state import read_state, write_state


def _monitor_stopped_health(project_name: str, paths: BoxPaths) -> dict | None:
    """Return the health state if the project can be recovered, else None.

    Prints why on refusal. Paused / quarantined projects are routed to
    their dedicated recovery paths rather than restarted here (which would
    bypass those checks).
    """
    if is_paused(project_name, paths):
        print(
            f"ERROR: Project '{project_name}' is paused, not monitor-stopped. "
            f"Use: boxmunge resume {project_name}",
            file=sys.stderr,
        )
        return None
    block = is_blocked(project_name, paths)
    if block and block.reason is BlockReason.QUARANTINED:
        print(f"ERROR: {block.refuse_message}", file=sys.stderr)
        return None

    health = read_state(paths.project_health_state(project_name))
    status = health.get("status", "unknown")
    if status != "critical_stopped":
        print(
            f"ERROR: Project '{project_name}' is not in a monitor-stopped "
            f"state (health status: {status}). Nothing to recover.",
            file=sys.stderr,
        )
        return None
    return health


def run_recover(project_name: str, paths: BoxPaths, yes: bool = False) -> int:
    """Un-stop a health-monitor-stopped project. Returns 0 on success.

    Preconditions are checked before the prompt and again under the
    project lock, which the recovery holds throughout.
    """
    project_dir = paths.project_dir(project_name)
    if not project_dir.exists() or not (project_dir / "manifest.yml").exists():
        print(f"ERROR: Project not found: {project_name}", file=sys.stderr)
        return 1
    health = _monitor_stopped_health(project_name, paths)
    if health is None:
        return 1

    if not yes:
        reason = health.get("failure_reason", "")
        print(f"This will recover monitor-stopped '{project_name}':")
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
    health = _monitor_stopped_health(project_name, paths)
    if health is None:
        return 1
    project_dir = paths.project_dir(project_name)
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
        compose_up(project_dir, compose_files=compose_files,
                   project_name=project_name)
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
