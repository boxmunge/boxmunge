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


def _within_deploy_grace(project_name: str, paths: BoxPaths, now_iso: str) -> bool:
    """True if the project was started within DEPLOY_GRACE_SECONDS.

    Reads `last_started_at` from the deploy state, written by deploy
    and resume. Missing field (e.g. project not started since this code
    rolled out) returns False — fall through to normal failure handling.
    """
    deploy_state = read_state(paths.project_deploy_state(project_name))
    last_started = deploy_state.get("last_started_at", "")
    if not last_started:
        return False
    try:
        started_dt = datetime.fromisoformat(last_started.replace("Z", "+00:00"))
    except ValueError:
        return False
    if started_dt.tzinfo is None:
        started_dt = started_dt.replace(tzinfo=timezone.utc)
    now_dt = datetime.fromisoformat(now_iso.replace("Z", "+00:00"))
    if now_dt.tzinfo is None:
        now_dt = now_dt.replace(tzinfo=timezone.utc)
    return (now_dt - started_dt).total_seconds() < DEPLOY_GRACE_SECONDS


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
            "status": "critical_stopped",
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
