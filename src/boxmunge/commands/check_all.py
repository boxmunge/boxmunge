"""boxmunge check-all: the five-minute health tick over every project.

Each project is checked under its lock unless it is blocked, held or
stopped by the monitor; its one smoke run (boxmunge.commands.check) decides
the status that the health state machine records and alerts on.
"""

import functools
import sys
from typing import TYPE_CHECKING

from boxmunge import compose_inventory, host_config_alert
from boxmunge.commands import check
from boxmunge.commands.argv import parse_args
from boxmunge.commands.check_holds import tick_hold
from boxmunge.commands.health_state import (
    record_still_stopped, tick_sees_stop, update_health_state,
)
from boxmunge.config import ConfigError
from boxmunge.fileutil import project_lock, LockError
from boxmunge.fleet import PROJECT_INPUT_ERRORS, report_project_failure
from boxmunge.lifecycle import BlockReason, is_blocked
from boxmunge.pause import awaiting_deploy
from boxmunge.log import log_error, log_operation
from boxmunge.manifest import load_manifest, ManifestError
from boxmunge.paths import BoxPaths
from boxmunge.redeploy_hint import deploy_ways

if TYPE_CHECKING:
    from boxmunge.commands.check import TickListing


def run_check_all(paths: BoxPaths, *, read_only: bool) -> int:
    """Run health checks across every project.

    Default mode (mutator): writes health state, may call ``compose_down``
    on critical results, and emits Pushover notifications. This is the
    form the systemd timer drives.

    ``read_only``: run the same per-project checks and print the report,
    but skip every side effect — no state writes, no container stops,
    no notifications. The exit code still reflects the worst severity.

    A project whose inputs cannot be read (manifest, state files) is
    reported on stderr and in the log, and the loop carries on with the
    rest. A host config that cannot be loaded is reported the same way.

    Returns the worst per-project status (0 ok, 1 warning, 2 critical),
    at least 1 if any project could not be checked, and 2 if docker-userns
    reports an error (broken remapping).
    """
    worst = 0
    failed: list[str] = []
    if not read_only and not _host_config_usable(paths):
        worst = 1
    if not read_only:
        from boxmunge.health_checks.userns import alert_docker_userns
        if alert_docker_userns(paths).status == "error":
            worst = 2
        from boxmunge.backup_alerts import alert_backups
        alert_backups(paths)
    projects_dir = paths.projects
    if not projects_dir.exists():
        print("No projects directory.")
        return worst

    projects = sorted(
        p.name for p in projects_dir.iterdir()
        if p.is_dir() and (p / "manifest.yml").exists()
    )

    if not projects:
        print("No projects to check.")
        return worst

    # One `docker ps` answers every project's "which containers run each
    # service", taken at the first smoke that needs it. A failed listing is
    # not cached: the next project asks again and reports its own failure.
    tick = functools.cache(compose_inventory.running_inventory)
    for name in projects:
        try:
            worst = max(worst, _check_project(name, paths, read_only, tick))
        except PROJECT_INPUT_ERRORS as e:
            report_project_failure("check-all", name, e, paths)
            failed.append(name)

    if failed:
        print(
            f"ERROR: check-all: {len(failed)} project(s) could not be "
            f"checked: {', '.join(failed)}",
            file=sys.stderr,
        )
        worst = max(worst, 1)
    return worst


def _host_config_usable(paths: BoxPaths) -> bool:
    """Report a host config that cannot be loaded loudly: no alert can be
    sent without it. One that loads with a wrong setting is the operator's
    to correct, not this tick's failure: host_config_alert tells them once,
    and the `host-config` health check keeps saying so."""
    try:
        host_config_alert.report(paths, "check-all")
    except ConfigError as e:
        print(f"ERROR: check-all: alerts cannot be sent: {e}", file=sys.stderr)
        log_error("check-all", f"alerts cannot be sent: {e}", paths)
        return False
    return True


def _check_project(name: str, paths: BoxPaths, read_only: bool,
                   tick: "TickListing | None" = None) -> int:
    """Check one project unless it is blocked or locked. Returns its status."""
    # Maintenance window: a deploy/stage/promote/restore in progress
    # holds the project lock. Stage transiently stops the prod container
    # to snapshot its data; a smoke run racing that transient state
    # escalates to CRITICAL and calls compose_down, leaving production
    # OFFLINE until the next promote. Hold the lock for the whole check
    # so we either skip (op in progress) or run with no lifecycle op
    # able to start underneath us — never act on a transient state.
    try:
        with project_lock(name, paths):
            return _check_one(name, paths, read_only, tick)
    except LockError:
        log_operation(
            "check-all",
            "skipped — lifecycle operation in progress (lock held)",
            paths, project=name,
        )
        return 0


def _check_one(name: str, paths: BoxPaths, read_only: bool,
               tick: "TickListing | None" = None) -> int:
    """Run a single project's check (caller holds the project lock).

    An unreadable manifest is fed to the health state machine as a
    warning carrying the cause (so the normal threshold alert fires
    instead of the project silently dropping out of monitoring), then
    re-raised for the fleet loop to report.
    """
    # A blocked (paused or CVE-quarantined) project is intentionally
    # stopped. Running smoke (which depends on a live container)
    # would fail, escalate to alerts via update_health_state, and
    # possibly call compose_down on an already-stopped project. Checked
    # under the lock, so a pause that completed while this tick waited
    # is seen. Quarantine adds a structured log entry; paused
    # historically did not (preserved).
    block = is_blocked(name, paths)
    if block:
        if block.reason is BlockReason.QUARANTINED:
            log_operation(
                "check-all", block.skip_message,
                paths, project=name,
            )
        elif awaiting_deploy(name, paths):
            print(f"{name}: PAUSED (awaiting deploy; down behind its maintenance page "
                  f"until a deploy: {deploy_ways(paths, name)})")
        return 0
    held = tick_hold(name, paths, read_only)
    if held is not None:
        return held
    # The monitor removed this project's containers after a critical
    # result. Running smoke now would only report "No such container" and
    # overwrite the real stop reason; the stop stands until recover or a
    # successful deploy (audit C-04).
    if tick_sees_stop(name, paths):
        print(f"{name}: CRITICAL (stopped by the health monitor; "
              f"run 'boxmunge recover {name}' or redeploy)")
        if not read_only:
            record_still_stopped(name, paths)
        return 2
    try:
        load_manifest(paths.project_manifest(name))
    except ManifestError as e:
        if not read_only:
            update_health_state(name, 1, str(e), paths)
        raise

    # One smoke run: its status decides, its message is what is recorded
    # and alerted (a second run could pass and leave the reason empty).
    result, message = check.check_with_reason(name, paths, periodic=True, tick=tick)
    if not read_only:
        update_health_state(name, result, message if result != 0 else "", paths)
    return result


def cmd_check_all(args: list[str]) -> None:
    """CLI entry point for check-all command.

    Without --read-only this is the timer-driven mutator: it writes per-
    project health state, can call compose_down on critical results, and
    emits Pushover notifications. With --read-only it only prints the
    report; no side effects. Any other argument is a usage error, so a
    mistyped --read-only can never fall through to the mutator (audit D-04).
    """
    parsed = parse_args("check-all", args, flags={"--read-only"})
    paths = BoxPaths()
    sys.exit(run_check_all(paths, read_only=parsed.has("--read-only")))
