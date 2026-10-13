"""Health-state machine and alerting for boxmunge check-all.

Separated from ``commands.check`` (which handles smoke-test execution) so
the timer-driven mutator path — read state, increment failure counters,
fire Pushover, stop containers on critical — lives in one focused module.
"""
from __future__ import annotations

from datetime import datetime, timezone

from boxmunge.config import ConfigError, load_config
from boxmunge.docker import DockerError, compose_down
from boxmunge.log import log_error, log_operation, log_warning
from boxmunge.paths import BoxPaths
from boxmunge.pushover import format_alert, format_recovery, send_notification
from boxmunge.state import read_state, write_state


# Window after deploy/resume during which warning-level failures are masked.
# A health timer firing in the second between deploy completion and the
# container becoming responsive is a false alarm — the next 15-minute check
# is the real verdict. Critical failures are NOT masked.
DEPLOY_GRACE_SECONDS = 60

# Health status written when a critical smoke result made the monitor stop
# the project's containers.
MONITOR_STOPPED = "critical_stopped"


def _parse_ts(value: str) -> datetime | None:
    """Parse an ISO timestamp from state; None if absent or malformed."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _last_started(project_name: str, paths: BoxPaths) -> datetime | None:
    deploy_state = read_state(paths.project_deploy_state(project_name))
    return _parse_ts(deploy_state.get("last_started_at", ""))


def _within_deploy_grace(project_name: str, paths: BoxPaths, now_iso: str) -> bool:
    """True if the project was started within DEPLOY_GRACE_SECONDS.

    Reads `last_started_at` from the deploy state, written by deploy
    and resume. Missing field (e.g. project not started since this code
    rolled out) returns False — fall through to normal failure handling.
    """
    started_dt = _last_started(project_name, paths)
    if started_dt is None:
        return False
    now_dt = _parse_ts(now_iso)
    assert now_dt is not None, f"bad timestamp for now: {now_iso!r}"
    return (now_dt - started_dt).total_seconds() < DEPLOY_GRACE_SECONDS


def _stop_stands(state: dict, project_name: str, paths: BoxPaths) -> bool:
    """True if ``state`` is a monitor stop that no later start has superseded."""
    if state.get("status") != MONITOR_STOPPED:
        return False
    stopped = _parse_ts(state.get("stopped_at", ""))
    started = _last_started(project_name, paths)
    # A stop recorded without stopped_at cannot be shown to have been
    # restarted, so it stands until `recover`.
    if stopped is None or started is None:
        return True
    return started <= stopped


def is_monitor_stopped(project_name: str, paths: BoxPaths) -> bool:
    """True while the health monitor's critical stop of the project stands.

    The stop is sticky. Health ticks leave it alone (no smoke run against
    the removed containers, no state rewrite, no alert) until ``recover``
    clears it, or a later successful deploy, rollback, or resume starts the
    project again (deploy state ``last_started_at`` newer than the stop's
    ``stopped_at``); the next tick then judges the project afresh.
    """
    state = read_state(paths.project_health_state(project_name))
    return _stop_stands(state, project_name, paths)


def record_still_stopped(project_name: str, paths: BoxPaths) -> None:
    """Note a health tick that left a monitor-stopped project alone."""
    state_path = paths.project_health_state(project_name)
    state = read_state(state_path)
    write_state(state_path, {**state, "last_check": datetime.now(timezone.utc).isoformat()})
    log_operation(
        "health",
        f"Still stopped by the health monitor ({state.get('failure_reason', '')}); "
        f"run 'boxmunge recover {project_name}' or redeploy",
        paths, project=project_name,
    )


def update_health_state(
    project_name: str,
    check_result: int,
    message: str,
    paths: BoxPaths,
) -> None:
    """Update health state and send alerts as needed.

    check_result: 0=ok, 1=warning, 2=critical
    """
    state_path = paths.project_health_state(project_name)
    state = read_state(state_path)
    now = datetime.now(timezone.utc).isoformat()

    # A standing monitor stop is sticky: leave status, reason, and alert
    # state alone. (check-all skips stopped projects before running smoke;
    # this guards any other caller.)
    if _stop_stands(state, project_name, paths):
        record_still_stopped(project_name, paths)
        return

    try:
        config = load_config(paths)
    except ConfigError:
        config = {}

    threshold = config.get("health", {}).get("alert_threshold", 3)
    pushover = config.get("pushover", {})
    user_key = pushover.get("user_key", "")
    app_token = pushover.get("app_token", "")

    prev_status = state.get("status", "ok")
    prev_message = state.get("failure_reason", "")
    consecutive = state.get("consecutive_failures", 0)
    alerted = state.get("alerted", False)

    # Warning during deploy/resume grace: log it, update last_check, but
    # don't escalate to FAILING and don't increment the failure counter.
    # Critical (check_result == 2) is NOT masked — it stops containers
    # which is too serious to silence.
    if check_result == 1 and _within_deploy_grace(project_name, paths, now):
        log_operation(
            "health",
            f"Skipped warning during deploy/resume grace window: {message}",
            paths, project=project_name,
        )
        write_state(state_path, {
            **state,
            "last_check": now,
        })
        return

    if check_result == 0:
        # Recovery
        if prev_status != "ok" and alerted:
            title, body = format_recovery(project_name)
            send_notification(user_key, app_token, title, body)
            log_operation("health", "Recovered — alert cleared", paths, project=project_name)

        write_state(state_path, {
            "last_check": now,
            "status": "ok",
            "consecutive_failures": 0,
            "alerted": False,
            "last_alert": state.get("last_alert", ""),
            "last_success": now,
            "failure_reason": "",
        })
        return

    # Failure path
    consecutive += 1

    if check_result == 2:
        # Critical — alert immediately, stop containers
        title, body = format_alert(project_name, "critical", message)
        if user_key and app_token:
            send_notification(user_key, app_token, title, body, priority=1)
        else:
            log_error("health", "CRITICAL but Pushover not configured — alert dropped",
                      paths, project=project_name)
        log_error("health", f"CRITICAL: {message} — stopping containers", paths, project=project_name)

        project_dir = paths.project_dir(project_name)
        try:
            compose_down(project_dir)
        except DockerError as e:
            log_error("health", f"compose down failed during critical: {e}",
                      paths, project=project_name)

        write_state(state_path, {
            "last_check": now,
            "status": MONITOR_STOPPED,
            "stopped_at": now,
            "consecutive_failures": consecutive,
            "alerted": True,
            "last_alert": now,
            "last_success": state.get("last_success", ""),
            "failure_reason": message,
        })
        return

    # Warning — alert after threshold
    should_alert = False
    if consecutive >= threshold and not alerted:
        should_alert = True
    elif alerted and message != prev_message:
        should_alert = True  # Message changed — re-alert

    if should_alert:
        title, body = format_alert(project_name, "warning", message)
        send_notification(user_key, app_token, title, body)
        log_warning("health", f"Alert sent: {message}", paths, project=project_name)

    write_state(state_path, {
        "last_check": now,
        "status": "failing",
        "consecutive_failures": consecutive,
        "alerted": alerted or should_alert,
        "last_alert": now if should_alert else state.get("last_alert", ""),
        "last_success": state.get("last_success", ""),
        "failure_reason": message,
    })
