"""Tests for the boxmunge log command — filtering and output."""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from boxmunge.commands.log_cmd import _parse_since, filter_log_entries, parse_log_file


def _write_log_entries(log_file: Path, entries: list[dict]) -> None:
    log_file.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(e) for e in entries]
    log_file.write_text("\n".join(lines) + "\n")


SAMPLE_ENTRIES = [
    {"ts": "2026-04-15T10:00:00Z", "level": "info", "component": "deploy",
     "project": "myapp", "msg": "Deploy completed"},
    {"ts": "2026-04-15T10:05:00Z", "level": "error", "component": "backup",
     "project": "myapp", "msg": "Backup failed"},
    {"ts": "2026-04-15T10:10:00Z", "level": "info", "component": "deploy",
     "project": "other", "msg": "Deploy completed"},
    {"ts": "2026-04-15T10:15:00Z", "level": "warn", "component": "health",
     "project": "myapp", "msg": "Check failed"},
]


class TestParseLogFile:
    def test_parses_all_entries(self, tmp_path: Path) -> None:
        log_file = tmp_path / "boxmunge.log"
        _write_log_entries(log_file, SAMPLE_ENTRIES)
        read = parse_log_file(log_file)
        assert len(read.entries) == 4 and read.torn == []

    def test_reports_each_torn_line_by_file_and_line(self, tmp_path: Path) -> None:
        """A line torn by a crash, or hand-edited, is reported, never dropped."""
        log_file = tmp_path / "boxmunge.log"
        log_file.write_text('{"level": "info", "msg": "ok"}\nnot json\n\n[1]\n{"msg": "x"}\n')
        read = parse_log_file(log_file)
        assert [e["msg"] for e in read.entries] == ["ok", "x"]
        assert [t.split(": ")[0] for t in read.torn] == [f"{log_file}:2", f"{log_file}:4"]
        assert "not json" in read.torn[0]

    def test_empty_file(self, tmp_path: Path) -> None:
        log_file = tmp_path / "boxmunge.log"
        log_file.write_text("")
        assert parse_log_file(log_file).entries == []

    def test_missing_file(self, tmp_path: Path) -> None:
        assert parse_log_file(tmp_path / "nope.log").entries == []


class TestFilterLogEntries:
    def test_filter_by_project(self) -> None:
        result = filter_log_entries(SAMPLE_ENTRIES, project="myapp")
        assert len(result) == 3
        assert all(e["project"] == "myapp" for e in result)

    def test_filter_by_component(self) -> None:
        result = filter_log_entries(SAMPLE_ENTRIES, component="deploy")
        assert len(result) == 2

    def test_filter_by_level(self) -> None:
        result = filter_log_entries(SAMPLE_ENTRIES, level="error")
        assert len(result) == 1
        assert result[0]["msg"] == "Backup failed"

    def test_filter_combined(self) -> None:
        result = filter_log_entries(SAMPLE_ENTRIES, project="myapp",
                                    component="deploy")
        assert len(result) == 1

    def test_no_filters_returns_all(self) -> None:
        result = filter_log_entries(SAMPLE_ENTRIES)
        assert len(result) == 4

    def test_tail_limit(self) -> None:
        result = filter_log_entries(SAMPLE_ENTRIES, tail=2)
        assert len(result) == 2
        assert result[0]["msg"] == "Deploy completed"  # third entry (project=other)
        assert result[1]["msg"] == "Check failed"  # fourth entry

    def test_filter_by_since(self) -> None:
        """Test that entries are filtered by timestamp cutoff using _parse_since."""
        # Use a large window to include all entries
        result = filter_log_entries(SAMPLE_ENTRIES, since="9999d")
        assert len(result) == 4  # All entries included

        # Use "0m" to exclude entries older than now (should filter all past entries)
        result = filter_log_entries(SAMPLE_ENTRIES, since="0m")
        assert len(result) == 0  # No entries are newer than "now"

        # Test that _parse_since returns a datetime object with timezone
        cutoff = _parse_since("1d")
        assert isinstance(cutoff, datetime)
        assert cutoff.tzinfo is not None
        # Verify it's in the past (1 day ago)
        now = datetime.now(timezone.utc)
        assert cutoff < now
        # Verify it's approximately 1 day ago (within 5 seconds tolerance for test speed)
        expected_diff = 24 * 60 * 60
        actual_diff = (now - cutoff).total_seconds()
        assert abs(actual_diff - expected_diff) < 5

    def test_parse_since_invalid(self) -> None:
        """Test that _parse_since raises ValueError for invalid input."""
        with pytest.raises(ValueError, match="Invalid duration"):
            _parse_since("abc")

    def test_parse_since_unknown_unit(self) -> None:
        """Test that _parse_since raises ValueError for unknown unit."""
        with pytest.raises(ValueError, match="Unknown unit"):
            _parse_since("5x")


class TestRunLogTornLines:
    """`log` warns once per torn line and exits 1, after showing every entry
    it could read; stdout stays parseable for --json."""

    def _box(self, tmp_path: Path):
        from boxmunge.paths import BoxPaths
        paths = BoxPaths(root=tmp_path)
        paths.log_file.parent.mkdir(parents=True)
        good = json.dumps(SAMPLE_ENTRIES[0])
        paths.log_file.write_text(f"{good}\n{{\"ts\": \"2026-04-15T10:0\n{good}\n")
        return paths

    @pytest.mark.parametrize("as_json", [False, True])
    def test_warns_per_torn_line_and_exits_1(self, tmp_path: Path, capsys, as_json) -> None:
        from boxmunge.commands.log_cmd import run_log
        paths = self._box(tmp_path)
        assert run_log(paths, as_json=as_json) == 1
        captured = capsys.readouterr()
        assert captured.out.count("Deploy completed") == 2
        if as_json:
            assert all(json.loads(line) for line in captured.out.splitlines())
        [warning] = captured.err.splitlines()
        assert warning.startswith(f"WARNING: {paths.log_file}:2: ")

    def test_clean_log_exits_0(self, tmp_path: Path, capsys) -> None:
        from boxmunge.commands.log_cmd import run_log
        paths = self._box(tmp_path)
        _write_log_entries(paths.log_file, SAMPLE_ENTRIES)
        assert run_log(paths) == 0
        assert capsys.readouterr().err == ""
