"""Health-state machine and alerting for boxmunge check-all.

Separated from ``commands.check`` (which handles smoke-test execution) so
the timer-driven mutator path — read state, increment failure counters,
fire Pushover, stop containers on critical — lives in one focused module.
"""
from __future__ import annotations

from datetime import datetime, timezone

from boxmunge import pending_snapshot
from boxmunge.config import DEFAULTS, ConfigError, load_config
from boxmunge.health_record import read_health_record
from boxmunge.docker import DockerError, compose_down
from boxmunge.log import log_error, log_operation, log_warning
from boxmunge.notify import notify
from boxmunge.paths import BoxPaths
from boxmunge.pushover import format_alert, format_recovery
from boxmunge.state import StateError, read_state, write_state


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
        dt = datetime.fromisoformat(value)
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
    state = read_health_record(paths.project_health_state(project_name))
    return _stop_stands(state, project_name, paths)


def tick_sees_stop(project_name: str, paths: BoxPaths) -> bool:
    """is_monitor_stopped for the health tick. A damaged record cannot say
    whether a stop stands, so the tick judges the project afresh (False) and
    update_health_state applies the damaged-record policy: a critical verdict
    is still enforced. Every other caller lets the StateError surface."""
    try:
        return is_monitor_stopped(project_name, paths)
    except StateError:
        return False


def _send_alert(
    project_name: str, paths: BoxPaths, title: str, body: str, priority: int = 0,
) -> bool:
    return notify(paths, title, body, component="health",
                  project=project_name, priority=priority)


def _alert_threshold(project_name: str, paths: BoxPaths) -> int:
    """The configured alert threshold: a whole number, the one setting
    read here, so no other stops it being honoured. A wrong one, or a
    config that cannot be loaded, is logged as an error naming the setting
    or the file at fault; the state machine still runs, on the
    documented default threshold, so a critical result still stops the
    project and a warning still alerts (notify says so itself if the config
    is too broken to send one)."""
    try:
        config = load_config(paths, reads=("health.alert_threshold",))
        return config["health"]["alert_threshold"]
    except ConfigError as e:
        default = DEFAULTS["health"]["alert_threshold"]
        log_error(
            "health",
            f"Cannot load config ({e}); the default alert threshold "
            f"({default}) is in use until it is corrected",
            paths, project=project_name,
        )
        return default


def record_still_stopped(project_name: str, paths: BoxPaths) -> None:
    """Note a health tick that left a monitor-stopped project alone.

    Retries the critical alert if it was never delivered.
    """
    state_path = paths.project_health_state(project_name)
    state = read_health_record(state_path)
    now = datetime.now(timezone.utc).isoformat()
    reason = state.get("failure_reason", "")
    updates: dict = {"last_check": now}
    if not state.get("alerted", False):
        title, body = format_alert(project_name, "critical", reason)
        if _send_alert(project_name, paths, title, body, priority=1):
            updates.update(alerted=True, alerted_reason=reason, last_alert=now)
    write_state(state_path, {**state, **updates})
    log_operation(
        "health",
        f"Still stopped by the health monitor ({reason}); "
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

    ``alerted`` (and ``alerted_reason``, ``last_alert``) record only alerts
    Pushover accepted. An alert that was not delivered is logged by
    ``notify`` and retried on the next tick. With ``status: ok``,
    ``alerted: True`` means the RECOVERED notice is still owed.

    Damaged record policy: a record whose fields have the wrong types (see
    health_record) never defeats a critical verdict. The damage is logged as
    an error, the stop and alert go ahead from fresh bookkeeping, and the
    recorded failure reason names the damage; the rewritten record is valid.
    An ok or warning verdict raises StateError naming the field instead,
    leaving the record for the operator: the fleet loop reports it every tick
    and still checks the other projects.
    """
    state_path = paths.project_health_state(project_name)
    damage: StateError | None = None
    try:
        state = read_health_record(state_path)
    except StateError as e:
        if check_result != 2:
            raise
        damage = e
        state = {}
        log_error("health", f"{e}; the health record is damaged and is reset, "
                  f"the critical stop goes ahead", paths, project=project_name)
    now = datetime.now(timezone.utc).isoformat()

    # A standing monitor stop is sticky: leave status, reason, and alert
    # state alone. (check-all skips stopped projects before running smoke;
    # this guards any other caller.)
    if _stop_stands(state, project_name, paths):
        record_still_stopped(project_name, paths)
        return

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
        write_state(state_path, {**state, "last_check": now})
        return

    if check_result == 0:
        _record_ok(project_name, paths, state, now)
    elif check_result == 2:
        if damage is not None:
            message = f"{message} (health record was damaged and reset: {damage})"
        _record_critical(project_name, paths, state, now, message)
    else:
        _record_warning(project_name, paths, state, now, message)


def _record_ok(project_name: str, paths: BoxPaths, state: dict, now: str) -> None:
    alerted = state.get("alerted", False)
    last_alert = state.get("last_alert", "")
    if alerted:
        title, body = format_recovery(project_name)
        if _send_alert(project_name, paths, title, body):
            alerted, last_alert = False, now
            log_operation("health", "Recovered — alert cleared", paths, project=project_name)
    write_state(paths.project_health_state(project_name), {
        "last_check": now,
        "status": "ok",
        "consecutive_failures": 0,
        "alerted": alerted,
        "alerted_reason": state.get("alerted_reason", "") if alerted else "",
        "last_alert": last_alert,
        "last_success": now,
        "failure_reason": "",
    })


def _note_pending_removal(project_name: str, paths: BoxPaths) -> None:
    """The stop removes every container: a data chown snapshot pending for
    the next deploy must not take that for a run of its service."""
    try:
        pending_snapshot.note_removal(paths, project_name)
    except (DockerError, StateError) as e:
        log_warning("health", f"Could not note the containers this stop removes for the "
                    f"data chown snapshot pending for the next deploy ({e}); that deploy "
                    f"may not use it, and takes its own", paths, project=project_name)


def _record_critical(
    project_name: str, paths: BoxPaths, state: dict, now: str, message: str,
) -> None:
    """Critical: stop the containers, then alert at priority 1."""
    log_error("health", f"CRITICAL: {message} — stopping containers", paths, project=project_name)
    consecutive = state.get("consecutive_failures", 0) + 1
    _note_pending_removal(project_name, paths)
    try:
        compose_down(paths.project_dir(project_name), project_name=project_name)
        stopped = True
        reason = message
    except DockerError as e:
        # Not stopped, so not monitor-stopped: record it as failing so the
        # next tick re-runs smoke and retries the stop.
        log_error("health", f"compose down failed during critical: {e}",
                  paths, project=project_name)
        stopped = False
        reason = f"{message} (critical; stopping containers failed: {e})"

    alerted = state.get("alerted", False)
    alerted_reason = state.get("alerted_reason", "")
    last_alert = state.get("last_alert", "")
    if not (alerted and alerted_reason == reason):
        title, body = format_alert(project_name, "critical", reason)
        if _send_alert(project_name, paths, title, body, priority=1):
            alerted, alerted_reason, last_alert = True, reason, now
        else:
            alerted = False

    new_state = {
        "last_check": now,
        "status": MONITOR_STOPPED if stopped else "failing",
        "consecutive_failures": consecutive,
        "alerted": alerted,
        "alerted_reason": alerted_reason,
        "last_alert": last_alert,
        "last_success": state.get("last_success", ""),
        "failure_reason": reason,
    }
    if stopped:
        new_state["stopped_at"] = now
    write_state(paths.project_health_state(project_name), new_state)


def _record_warning(
    project_name: str, paths: BoxPaths, state: dict, now: str, message: str,
) -> None:
    """Warning: alert once the threshold is reached, and again if the
    reason changes; an undelivered alert is retried every tick."""
    consecutive = state.get("consecutive_failures", 0) + 1
    alerted = state.get("alerted", False)
    alerted_reason = state.get("alerted_reason", "")
    last_alert = state.get("last_alert", "")
    threshold = _alert_threshold(project_name, paths)
    if consecutive >= threshold and not (alerted and alerted_reason == message):
        title, body = format_alert(project_name, "warning", message)
        if _send_alert(project_name, paths, title, body):
            alerted, alerted_reason, last_alert = True, message, now
            log_warning("health", f"Alert sent: {message}", paths, project=project_name)

    write_state(paths.project_health_state(project_name), {
        "last_check": now,
        "status": "failing",
        "consecutive_failures": consecutive,
        "alerted": alerted,
        "alerted_reason": alerted_reason,
        "last_alert": last_alert,
        "last_success": state.get("last_success", ""),
        "failure_reason": message,
    })
