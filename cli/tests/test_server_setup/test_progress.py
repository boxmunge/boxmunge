"""Tests for progress marker parsing and rendering."""

import pytest

from boxmunge_cli.server_setup.progress import parse_marker, render_progress_bar


class TestParseMarker:
    def test_valid_marker(self) -> None:
        result = parse_marker("##BOXMUNGE:STEP:3:15:Installing Docker")
        assert result == (3, 15, "Installing Docker")

    def test_non_marker_returns_none(self) -> None:
        assert parse_marker("apt-get install -y docker") is None

    def test_empty_line(self) -> None:
        assert parse_marker("") is None

    def test_partial_marker(self) -> None:
        assert parse_marker("##BOXMUNGE:STEP:3") is None

    def test_first_step(self) -> None:
        result = parse_marker("##BOXMUNGE:STEP:1:15:Updating system packages")
        assert result == (1, 15, "Updating system packages")

    def test_last_step(self) -> None:
        result = parse_marker("##BOXMUNGE:STEP:15:15:OS hardening")
        assert result == (15, 15, "OS hardening")


class TestRenderProgressBar:
    def test_zero_percent(self) -> None:
        bar = render_progress_bar(0, 15, "Starting...", width=20)
        assert "0%" in bar

    def test_fifty_percent(self) -> None:
        bar = render_progress_bar(7, 15, "Halfway", width=20)
        assert "46%" in bar or "47%" in bar

    def test_hundred_percent(self) -> None:
        bar = render_progress_bar(15, 15, "Done!", width=20)
        assert "100%" in bar

    def test_includes_description(self) -> None:
        bar = render_progress_bar(3, 15, "Installing Docker", width=20)
        assert "Installing Docker" in bar
