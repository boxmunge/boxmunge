# SPDX-License-Identifier: Apache-2.0
"""The nightly CVE scan finishes before the container update starts: both
run, in that order, inside one maintenance unit fired by one timer. Two
independent timers could not guarantee the order."""
from __future__ import annotations

import configparser
from datetime import timedelta
from pathlib import Path

UNITS = Path(__file__).resolve().parent.parent / "systemd"


def _unit(name: str) -> configparser.ConfigParser:
    parser = configparser.ConfigParser(strict=False, interpolation=None)
    parser.optionxform = str  # keep systemd's key case
    parser.read(UNITS / name)
    return parser


def _window(timer: str) -> tuple[timedelta, timedelta]:
    """(earliest, latest) time of day the daily timer fires."""
    section = _unit(timer)["Timer"]
    clock = section["OnCalendar"].removeprefix("*-*-* ")
    h, m, s = (int(part) for part in clock.split(":"))
    start = timedelta(hours=h, minutes=m, seconds=s)
    return start, start + timedelta(seconds=int(section.get("RandomizedDelaySec", "0")))


def _steps() -> list[str]:
    text = (UNITS / "boxmunge-maintenance.service").read_text()
    return [line.split("=", 1)[1] for line in text.splitlines()
            if line.startswith("ExecStart=")]


def test_scan_runs_before_container_update_in_one_unit() -> None:
    assert _steps() == ["-/opt/boxmunge/bin/boxmunge security scan",
                        "-/opt/boxmunge/bin/boxmunge container-update"]
    service = _unit("boxmunge-maintenance.service")["Service"]
    assert service["Type"] == "oneshot" and service["User"] == "root"
    assert service["TimeoutStartSec"] == "5h"


def test_maintenance_starts_30min_after_backup() -> None:
    backup, _ = _window("boxmunge-backup.timer")
    earliest, _ = _window("boxmunge-maintenance.timer")
    assert earliest - backup >= timedelta(minutes=30)
    timer = _unit("boxmunge-maintenance.timer")["Timer"]
    assert timer["OnCalendar"] == "*-*-* 02:30:00"
    assert timer["RandomizedDelaySec"] == "1800"


def test_the_old_timers_are_gone_and_the_services_have_no_ordering_on_each_other() -> None:
    assert not (UNITS / "boxmunge-cve-scan.timer").exists()
    assert not (UNITS / "boxmunge-container-update.timer").exists()
    assert "boxmunge-container-update.service" not in _unit("boxmunge-cve-scan.service")["Unit"]["After"]


def test_the_kev_watch_tick_is_bounded_so_the_nightly_scan_cannot_wait_long() -> None:
    """The fleet scan blocks on the fleet lock the watch holds; the service
    timeout is the bound, and scan plus update must still fit the 5h unit."""
    service = _unit("boxmunge-kev-watch.service")["Service"]
    assert service["TimeoutStartSec"] == "1h"
    timer = _unit("boxmunge-kev-watch.timer")["Timer"]
    assert (timer["OnCalendar"], timer["RandomizedDelaySec"]) == ("*:00/30", "120")


def test_the_autofix_unit_runs_the_queue_as_root_outside_the_scan_units() -> None:
    """Started by the scans (no timer), bounded well past one patch attempt."""
    service = _unit("boxmunge-autofix.service")["Service"]
    assert (service["Type"], service["User"], service["TimeoutStartSec"]) == (
        "oneshot", "root", "6h")
    assert service["ExecStart"] == "/opt/boxmunge/bin/boxmunge security autofix-queue"
    assert not (UNITS / "boxmunge-autofix.timer").exists()
    unit = _unit("boxmunge-autofix.service")["Unit"]   # a patch pulls and scans
    assert "network-online.target" in unit["After"] and unit["Wants"] == "network-online.target"


def test_the_maintenance_unit_fits_a_waited_scan_and_the_autofix_window() -> None:
    """Up to 1h waiting on a KEV watch tick, the scan, and container-update's
    3h nightly autofix window all fit the unit's limit."""
    from boxmunge.cve.autofix_policy import NIGHTLY_AUTOFIX_WINDOW
    limit = int(_unit("boxmunge-maintenance.service")["Service"]["TimeoutStartSec"][:-1])
    watch = int(_unit("boxmunge-kev-watch.service")["Service"]["TimeoutStartSec"][:-1])
    assert timedelta(hours=limit) > timedelta(hours=watch) + NIGHTLY_AUTOFIX_WINDOW


def test_rotate_timer_is_monthly_and_root() -> None:
    """The audit log's rotation clears and sets the append-only attribute,
    which only root can do."""
    timer = _unit("boxmunge-audit-rotate.timer")["Timer"]
    assert (timer["OnCalendar"], timer["Persistent"]) == ("*-*-01 00:15:00", "true")
    service = _unit("boxmunge-audit-rotate.service")["Service"]
    assert (service["Type"], service["User"]) == ("oneshot", "root")
    assert service["ExecStart"] == "/opt/boxmunge/bin/boxmunge-server _audit-rotate"


def test_path_unit_watches_the_queue() -> None:
    """Any record in queue/ starts the runner; it is the runner's boot start too."""
    unit = _unit("boxmunge-jobs.path")
    assert dict(unit["Path"]) == {"DirectoryNotEmpty": "/opt/boxmunge/state/jobs/queue",
                                  "Unit": "boxmunge-jobs.service"}
    assert unit["Install"]["WantedBy"] == "paths.target"


def test_jobs_service_sets_explicit_start_limits_and_runs_as_deploy() -> None:
    """A runner that cannot start is rate-limited at a known rate, which the
    jobs-runner health check reports; it has no [Install] of its own."""
    unit = _unit("boxmunge-jobs.service")
    assert (unit["Unit"]["After"], unit["Unit"]["StartLimitIntervalSec"],
            unit["Unit"]["StartLimitBurst"]) == ("docker.service", "600", "20")
    service = unit["Service"]
    assert (service["Type"], service["User"], service["Group"]) == ("exec", "deploy", "deploy")
    assert service["ExecStart"] == "/opt/boxmunge/bin/boxmunge-server _job-runner"
    assert service["TimeoutStopSec"] == "300"
    assert (service["StandardOutput"], service["StandardError"]) == ("journal", "journal")
    assert not unit.has_section("Install")


def test_jobs_service_stops_every_worker_and_is_one_unit() -> None:
    """A stop's SIGTERM reaches each worker, not only the runner (the default
    control-group kill mode), and one non-templated unit is what keeps two
    runners from running at once."""
    service = _unit("boxmunge-jobs.service")["Service"]
    assert service.get("KillMode", "control-group") == "control-group"
    assert sorted(p.name for p in UNITS.glob("boxmunge-jobs*")) == [
        "boxmunge-jobs.path", "boxmunge-jobs.service"]
