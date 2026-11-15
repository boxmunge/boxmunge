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
    assert service["TimeoutStartSec"] == "4h"


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
    timeout is the bound, and scan plus update must still fit the 4h unit."""
    service = _unit("boxmunge-kev-watch.service")["Service"]
    assert service["TimeoutStartSec"] == "1h"
    timer = _unit("boxmunge-kev-watch.timer")["Timer"]
    assert (timer["OnCalendar"], timer["RandomizedDelaySec"]) == ("*:00/30", "120")
