"""Tests for auto-update version targeting — security patches within major.minor line only."""

import json
import pytest
from unittest.mock import patch, MagicMock

from boxmunge.commands.auto_update_cmd import (
    _version_newer,
    _is_security_release,
    _same_minor_line,
    check_for_security_update,
)


class TestSameMinorLine:
    def test_same_line(self) -> None:
        assert _same_minor_line("0.2.1", "0.2.0") is True

    def test_different_minor(self) -> None:
        assert _same_minor_line("0.3.1", "0.2.0") is False

    def test_different_major(self) -> None:
        assert _same_minor_line("1.2.1", "0.2.0") is False

    def test_same_version(self) -> None:
        assert _same_minor_line("0.2.0", "0.2.0") is True

    def test_handles_two_part_versions(self) -> None:
        assert _same_minor_line("0.2", "0.2.0") is True


class TestVersionTargeting:
    @patch("boxmunge.commands.auto_update_cmd._fetch_releases")
    @patch("boxmunge.commands.auto_update_cmd.read_installed_version")
    def test_ignores_security_release_on_different_minor(self, mock_version, mock_fetch, paths) -> None:
        mock_version.return_value = "0.2.0"
        mock_fetch.return_value = [
            {
                "draft": False, "prerelease": False,
                "tag_name": "v0.3.1",
                "name": "v0.3.1 [security]",
                "body": "security fix",
                "html_url": "https://github.com/boxmunge/boxmunge/releases/v0.3.1",
            }
        ]
        result = check_for_security_update(paths)
        assert result is None

    @patch("boxmunge.commands.auto_update_cmd._fetch_releases")
    @patch("boxmunge.commands.auto_update_cmd.read_installed_version")
    def test_applies_security_release_on_same_minor(self, mock_version, mock_fetch, paths) -> None:
        mock_version.return_value = "0.2.0"
        mock_fetch.return_value = [
            {
                "draft": False, "prerelease": False,
                "tag_name": "v0.2.1",
                "name": "v0.2.1 [security]",
                "body": "security fix",
                "html_url": "https://github.com/boxmunge/boxmunge/releases/v0.2.1",
            }
        ]
        result = check_for_security_update(paths)
        assert result is not None
        assert result["version"] == "0.2.1"

    @patch("boxmunge.commands.auto_update_cmd._fetch_releases")
    @patch("boxmunge.commands.auto_update_cmd.read_installed_version")
    def test_ignores_non_security_release(self, mock_version, mock_fetch, paths) -> None:
        mock_version.return_value = "0.2.0"
        mock_fetch.return_value = [
            {
                "draft": False, "prerelease": False,
                "tag_name": "v0.2.1",
                "name": "v0.2.1 — bug fix",
                "body": "just a fix",
                "html_url": "https://github.com/boxmunge/boxmunge/releases/v0.2.1",
            }
        ]
        result = check_for_security_update(paths)
        assert result is None
