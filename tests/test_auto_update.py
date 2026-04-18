"""Tests for auto-update version targeting — security patches within major.minor line only."""

from unittest.mock import patch

from boxmunge.commands.auto_update_cmd import (
    _version_newer,
    _is_security_release,
    _same_minor_line,
    check_for_security_update,
    UpdateCheckError,
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
    @patch("boxmunge.commands.auto_update_cmd._check_via_endpoint")
    @patch("boxmunge.commands.auto_update_cmd.read_installed_version")
    def test_ignores_security_release_on_different_minor(self, mock_version, mock_endpoint, mock_fetch, paths) -> None:
        mock_version.return_value = "0.2.0"
        mock_endpoint.side_effect = UpdateCheckError("unavailable")
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
    @patch("boxmunge.commands.auto_update_cmd._check_via_endpoint")
    @patch("boxmunge.commands.auto_update_cmd.read_installed_version")
    def test_applies_security_release_on_same_minor(self, mock_version, mock_endpoint, mock_fetch, paths) -> None:
        mock_version.return_value = "0.2.0"
        mock_endpoint.side_effect = UpdateCheckError("unavailable")
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
    @patch("boxmunge.commands.auto_update_cmd._check_via_endpoint")
    @patch("boxmunge.commands.auto_update_cmd.read_installed_version")
    def test_ignores_non_security_release(self, mock_version, mock_endpoint, mock_fetch, paths) -> None:
        mock_version.return_value = "0.2.0"
        mock_endpoint.side_effect = UpdateCheckError("unavailable")
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


class TestVersionCheckEndpoint:
    """Tests for the primary boxmunge.dev check with GitHub fallback."""

    @patch("boxmunge.commands.auto_update_cmd._fetch_releases")
    @patch("boxmunge.commands.auto_update_cmd._check_via_endpoint")
    @patch("boxmunge.commands.auto_update_cmd.read_installed_version")
    def test_uses_endpoint_when_available(self, mock_version, mock_endpoint, mock_github, paths) -> None:
        mock_version.return_value = "0.2.0"
        mock_endpoint.return_value = {
            "status": "security_update_available",
            "security": {"version": "0.2.1", "url": "https://github.com/boxmunge/boxmunge/releases/tag/v0.2.1"},
            "latest": {"version": "0.3.0", "url": "https://github.com/boxmunge/boxmunge/releases/tag/v0.3.0"},
        }
        result = check_for_security_update(paths)
        assert result is not None
        assert result["version"] == "0.2.1"
        mock_github.assert_not_called()

    @patch("boxmunge.commands.auto_update_cmd._fetch_releases")
    @patch("boxmunge.commands.auto_update_cmd._check_via_endpoint")
    @patch("boxmunge.commands.auto_update_cmd.read_installed_version")
    def test_falls_back_to_github_on_endpoint_failure(self, mock_version, mock_endpoint, mock_github, paths) -> None:
        mock_version.return_value = "0.2.0"
        mock_endpoint.side_effect = UpdateCheckError("connection refused")
        mock_github.return_value = [
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

    @patch("boxmunge.commands.auto_update_cmd._check_via_endpoint")
    @patch("boxmunge.commands.auto_update_cmd.read_installed_version")
    def test_endpoint_up_to_date(self, mock_version, mock_endpoint, paths) -> None:
        mock_version.return_value = "0.3.0"
        mock_endpoint.return_value = {
            "status": "up_to_date",
            "security": None,
            "latest": None,
        }
        result = check_for_security_update(paths)
        assert result is None

    @patch("boxmunge.commands.auto_update_cmd._check_via_endpoint")
    @patch("boxmunge.commands.auto_update_cmd.read_installed_version")
    def test_endpoint_update_available_no_security(self, mock_version, mock_endpoint, paths) -> None:
        mock_version.return_value = "0.2.0"
        mock_endpoint.return_value = {
            "status": "update_available",
            "security": None,
            "latest": {"version": "0.3.0", "url": "https://github.com/boxmunge/boxmunge/releases/tag/v0.3.0"},
        }
        result = check_for_security_update(paths)
        assert result is None  # No security update — no action
