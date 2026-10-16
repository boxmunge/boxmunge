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
    assert [e["msg"] for e in query_log(paths, since="24h").entries] == ["day-1", "today"]
    assert [e["msg"] for e in query_log(paths, since="7d").entries] == ["day-2", "day-1", "today"]


def test_tail_without_since_continues_into_archives(paths: BoxPaths, midnight: datetime) -> None:
    _write_days(paths, midnight)
    assert [e["msg"] for e in query_log(paths, tail=2).entries] == ["day-1", "today"]
    assert [e["msg"] for e in query_log(paths).entries] == ["day-2", "day-1", "today"]
    assert query_log(paths, tail=0).entries == []


def test_recent_errors_count_yesterdays_archive(paths: BoxPaths, midnight: datetime) -> None:
    _write_days(paths, midnight, level="error")
    check = check_recent_errors(paths)
    assert check.detail.startswith("2 error(s) in last 24h"), check.detail


def test_torn_lines_make_recent_errors_warn(paths: BoxPaths, midnight: datetime) -> None:
    """A torn line may have been an error entry: the count is not trustworthy."""
    _write_days(paths, midnight, level="error")
    with paths.log_file.open("a") as log:
        log.write('{"ts": "2026-\n')
    check = check_recent_errors(paths)
    assert check.status == "warn"
    assert f"{paths.log_file}:2: " in check.detail


def test_mcp_log_tool_reports_torn_lines(paths: BoxPaths, midnight: datetime, monkeypatch) -> None:
    from boxmunge import mcp_tools
    _write_days(paths, midnight)
    with paths.log_file.open("a") as log:
        log.write("garbage\n")
    monkeypatch.setattr(mcp_tools, "_get_paths", lambda: paths)
    result = mcp_tools._tool_log(since="24h")
    assert result["success"] is False and result["exit_code"] == 1
    assert [e["msg"] for e in result["data"]["entries"]] == ["day-1", "today"]
    [warning] = result["messages"]
    assert warning.startswith(f"WARNING: {paths.log_file}:2: ")


def test_boxmunge_logs_tail_spans_rotation(paths: BoxPaths, midnight: datetime, capsys) -> None:
    _write_days(paths, midnight)
    _show_boxmunge_logs(paths, tail=2)
    shown = [json.loads(line)["msg"] for line in capsys.readouterr().out.splitlines()]
    assert shown == ["day-1", "today"]
