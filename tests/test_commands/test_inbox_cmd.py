"""Tests for boxmunge inbox command."""

import pytest
from pathlib import Path

from boxmunge.commands.inbox_cmd import run_inbox_list, run_inbox_clean
from boxmunge.paths import BoxPaths


def _place_bundle(paths: BoxPaths, project: str = "testapp",
                  timestamp: str = "2026-03-31T091500000000") -> Path:
    """Place a fake bundle file in the inbox."""
    filename = f"{project}-{timestamp}.tar.gz"
    bundle = paths.inbox / filename
    bundle.write_bytes(b"fake tar content")
    return bundle


class TestInboxList:
    def test_empty_inbox(self, paths: BoxPaths,
                         capsys: pytest.CaptureFixture) -> None:
        result = run_inbox_list(paths, project_filter=None)
        assert result == 0
        captured = capsys.readouterr()
        assert "no bundles" in captured.out.lower()

    def test_lists_bundles(self, paths: BoxPaths,
                           capsys: pytest.CaptureFixture) -> None:
        _place_bundle(paths, "testapp", "2026-03-31T091500000000")
        _place_bundle(paths, "testapp", "2026-03-31T102300000000")
        _place_bundle(paths, "other", "2026-03-31T110000000000")
        result = run_inbox_list(paths, project_filter=None)
        assert result == 0
        captured = capsys.readouterr()
        assert "testapp" in captured.out
        assert "other" in captured.out

    def test_filters_by_project(self, paths: BoxPaths,
                                capsys: pytest.CaptureFixture) -> None:
        _place_bundle(paths, "testapp", "2026-03-31T091500000000")
        _place_bundle(paths, "other", "2026-03-31T110000000000")
        result = run_inbox_list(paths, project_filter="testapp")
        assert result == 0
        captured = capsys.readouterr()
        assert "testapp" in captured.out
        assert "other" not in captured.out

    def test_most_recent_first(self, paths: BoxPaths,
                               capsys: pytest.CaptureFixture) -> None:
        _place_bundle(paths, "testapp", "2026-03-31T091500000000")
        _place_bundle(paths, "testapp", "2026-03-31T102300000000")
        result = run_inbox_list(paths, project_filter=None)
        assert result == 0
        captured = capsys.readouterr()
        lines = captured.out.strip().split("\n")
        idx_later = next(i for i, l in enumerate(lines) if "102300" in l)
        idx_earlier = next(i for i, l in enumerate(lines) if "091500" in l)
        assert idx_later < idx_earlier


class TestInboxClean:
    def test_cleans_all_bundles(self, paths: BoxPaths) -> None:
        _place_bundle(paths, "testapp", "2026-03-31T091500000000")
        _place_bundle(paths, "other", "2026-03-31T110000000000")
        result = run_inbox_clean(paths, project_filter=None, yes=True)
        assert result == 0
        remaining = [f for f in paths.inbox.iterdir()
                     if f.is_file() and f.suffix == ".gz"]
        assert len(remaining) == 0

    def test_cleans_only_filtered_project(self, paths: BoxPaths) -> None:
        _place_bundle(paths, "testapp", "2026-03-31T091500000000")
        _place_bundle(paths, "other", "2026-03-31T110000000000")
        result = run_inbox_clean(paths, project_filter="testapp", yes=True)
        assert result == 0
        remaining = [f.name for f in paths.inbox.iterdir()
                     if f.is_file() and f.suffix == ".gz"]
        assert len(remaining) == 1
        assert "other" in remaining[0]

    def test_clean_empty_inbox(self, paths: BoxPaths) -> None:
        result = run_inbox_clean(paths, project_filter=None, yes=True)
        assert result == 0
