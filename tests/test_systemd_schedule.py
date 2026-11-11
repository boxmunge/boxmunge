# SPDX-License-Identifier: Apache-2.0
"""The nightly CVE scan runs after the container update (deep review E-3):
the update's timer always fires first, and a scan due while it still runs
waits for it, so the scan judges the images the update left running and
never finds a project the update has locked."""
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


def test_the_scan_is_ordered_after_the_container_update() -> None:
    after = _unit("boxmunge-cve-scan.service")["Unit"]["After"].split()
    assert "boxmunge-container-update.service" in after


def test_the_container_update_always_fires_before_the_scan() -> None:
    _, update_latest = _window("boxmunge-container-update.timer")
    scan_earliest, _ = _window("boxmunge-cve-scan.timer")
    assert update_latest <= scan_earliest


def test_the_update_does_not_start_alongside_the_backup() -> None:
    backup, _ = _window("boxmunge-backup.timer")
    update_earliest, _ = _window("boxmunge-container-update.timer")
    assert update_earliest - backup >= timedelta(minutes=30)
