"""Log queries read the rotated archives their time window reaches into."""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from boxmunge.commands.health_cmd import check_recent_errors
from boxmunge.commands.log_cmd import query_log
from boxmunge.commands.logs import _show_boxmunge_logs
from boxmunge.log_rotation import archive_path
from boxmunge.paths import BoxPaths


def _entry(when: datetime, msg: str, level: str = "info") -> str:
    return json.dumps({
        "ts": when.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), "level": level,
        "component": "test", "project": None, "msg": msg,
    }) + "\n"


@pytest.fixture
def paths(tmp_path: Path) -> BoxPaths:
    p = BoxPaths(tmp_path)
    p.logs.mkdir(parents=True)
    return p


@pytest.fixture
def midnight() -> datetime:
    return datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)


def _write_days(paths: BoxPaths, midnight: datetime, level: str = "info") -> None:
    """Three days of entries, rotated as the handler would leave them.

    The archived entries sit one second before a midnight, so whatever the
    time of day, day-1's is under 24h old and day-2's is over.
    """
    for age in (2, 1):
        day = midnight - timedelta(days=age)
        archive_path(paths.log_file, day.date()).write_text(
            _entry(day + timedelta(hours=23, minutes=59, seconds=59), f"day-{age}", level))
    paths.log_file.write_text(_entry(datetime.now(timezone.utc), "today", level))


def test_since_window_reaches_into_archives(paths: BoxPaths, midnight: datetime) -> None:
    _write_days(paths, midnight)
    assert [e["msg"] for e in query_log(paths, since="24h")] == ["day-1", "today"]
    assert [e["msg"] for e in query_log(paths, since="7d")] == ["day-2", "day-1", "today"]


def test_tail_without_since_continues_into_archives(paths: BoxPaths, midnight: datetime) -> None:
    _write_days(paths, midnight)
    assert [e["msg"] for e in query_log(paths, tail=2)] == ["day-1", "today"]
    assert [e["msg"] for e in query_log(paths)] == ["day-2", "day-1", "today"]
    assert query_log(paths, tail=0) == []


def test_recent_errors_count_yesterdays_archive(paths: BoxPaths, midnight: datetime) -> None:
    _write_days(paths, midnight, level="error")
    check = check_recent_errors(paths)
    assert check.detail.startswith("2 error(s) in last 24h"), check.detail


def test_boxmunge_logs_tail_spans_rotation(paths: BoxPaths, midnight: datetime, capsys) -> None:
    _write_days(paths, midnight)
    _show_boxmunge_logs(paths, tail=2)
    shown = [json.loads(line)["msg"] for line in capsys.readouterr().out.splitlines()]
    assert shown == ["day-1", "today"]
