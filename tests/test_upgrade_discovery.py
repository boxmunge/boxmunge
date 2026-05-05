"""Tests for upgrade discovery — replaces inline-Python-in-bash logic."""
import json
from unittest.mock import patch, MagicMock
from urllib.error import URLError

import pytest

from boxmunge.paths import BoxPaths
from boxmunge.version import write_installed_version


def _setup(tmp_path):
    paths = BoxPaths(root=tmp_path / "bm")
    for d in ["config", "upgrade-state", "logs"]:
        (paths.root / d).mkdir(parents=True, exist_ok=True)
    paths.config_file.write_text("hostname: t\nadmin_email: a@b\n")
    write_installed_version(paths, "0.3.0", "abc1234")
    paths.blocklist.write_text("{}")
    return paths


def _mock_endpoint(json_response):
    """Build a mock urlopen that returns the given JSON."""
    m = MagicMock()
    m.read.return_value = json.dumps(json_response).encode()
    return m


class TestDiscoverUpdate:
    @patch("urllib.request.urlopen")
    def test_endpoint_says_up_to_date(self, mock_open, tmp_path):
        from boxmunge.upgrade_discovery import discover_update
        mock_open.return_value = _mock_endpoint({
            "latest": None, "security": None, "status": "up_to_date"
        })
        paths = _setup(tmp_path)
        result = discover_update(paths)
        assert result["action"] == "up_to_date"
        assert result["current_version"] == "0.3.0"

    @patch("urllib.request.urlopen")
    def test_endpoint_returns_security_update(self, mock_open, tmp_path):
        from boxmunge.upgrade_discovery import discover_update
        mock_open.return_value = _mock_endpoint({
            "latest": {"version": "0.3.5", "url": "https://example/v0.3.5"},
            "security": {"version": "0.3.5", "url": "https://example/v0.3.5"},
            "status": "security_update_available",
        })
        paths = _setup(tmp_path)
        result = discover_update(paths)
        assert result["action"] == "upgrade"
        assert result["version"] == "0.3.5"
        assert result["is_security"] is True

    @patch("urllib.request.urlopen")
    def test_security_only_skips_non_security(self, mock_open, tmp_path):
        from boxmunge.upgrade_discovery import discover_update
        mock_open.return_value = _mock_endpoint({
            "latest": {"version": "0.3.5", "url": "https://example/v0.3.5"},
            "security": None,
            "status": "update_available",
        })
        paths = _setup(tmp_path)
        result = discover_update(paths, security_only=True)
        assert result["action"] == "up_to_date"

    @patch("urllib.request.urlopen")
    def test_non_security_latest_returned_when_security_only_false(
            self, mock_open, tmp_path):
        from boxmunge.upgrade_discovery import discover_update
        mock_open.return_value = _mock_endpoint({
            "latest": {"version": "0.3.5", "url": "https://example/v0.3.5"},
            "security": None,
            "status": "update_available",
        })
        paths = _setup(tmp_path)
        result = discover_update(paths)
        assert result["action"] == "upgrade"
        assert result["is_security"] is False

    @patch("urllib.request.urlopen")
    def test_blocklisted_version(self, mock_open, tmp_path):
        from boxmunge.upgrade_discovery import discover_update
        mock_open.return_value = _mock_endpoint({
            "latest": {"version": "0.3.5", "url": "https://example/v0.3.5"},
            "security": {"version": "0.3.5", "url": "https://example/v0.3.5"},
            "status": "security_update_available",
        })
        paths = _setup(tmp_path)
        paths.blocklist.write_text(json.dumps({"0.3.5": "preflight_failed"}))
        result = discover_update(paths)
        assert result["action"] == "blocklisted"
        assert result["version"] == "0.3.5"

    @patch("urllib.request.urlopen")
    def test_endpoint_unreachable_falls_back_to_github(
            self, mock_open, tmp_path):
        from boxmunge.upgrade_discovery import discover_update
        # First call (endpoint) fails; second call (GitHub releases) returns data.
        github_response = MagicMock()
        github_response.read.return_value = json.dumps([
            {"tag_name": "v0.3.5", "name": "v0.3.5 [security]",
             "html_url": "https://github.com/boxmunge/boxmunge/releases/tag/v0.3.5",
             "draft": False, "prerelease": False, "body": "[security] fix"}
        ]).encode()
        mock_open.side_effect = [URLError("down"), github_response]
        paths = _setup(tmp_path)
        result = discover_update(paths)
        assert result["action"] == "upgrade"
        assert result["version"] == "0.3.5"

    @patch("urllib.request.urlopen")
    def test_both_unreachable_returns_error(self, mock_open, tmp_path):
        from boxmunge.upgrade_discovery import discover_update
        mock_open.side_effect = URLError("down")
        paths = _setup(tmp_path)
        result = discover_update(paths)
        assert result["action"] == "error"
        assert "message" in result

    @patch("urllib.request.urlopen")
    def test_malformed_json_returns_error(self, mock_open, tmp_path):
        from boxmunge.upgrade_discovery import discover_update
        m = MagicMock()
        m.read.return_value = b"not json"
        mock_open.return_value = m
        paths = _setup(tmp_path)
        result = discover_update(paths)
        # Endpoint malformed → falls back to GitHub. If both fail, error.
        # If we have GitHub mocked separately, structure depends. For this
        # test with single mock, endpoint returns bad JSON → falls back to
        # GitHub (also same bad JSON) → error.
        assert result["action"] == "error"
