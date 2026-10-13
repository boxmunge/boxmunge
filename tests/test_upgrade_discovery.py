"""Tests for upgrade discovery — release-class selection via endpoint and GitHub."""
import json
from unittest.mock import patch, MagicMock
from urllib.error import URLError

import pytest

from boxmunge.paths import BoxPaths
from boxmunge.upgrade_discovery import discover_update
from boxmunge.version import write_installed_version

GH = "https://github.com/boxmunge/boxmunge/releases/tag/"


def _setup(tmp_path, version="0.3.0"):
    paths = BoxPaths(root=tmp_path / "bm")
    for d in ["config", "upgrade-state", "logs"]:
        (paths.root / d).mkdir(parents=True, exist_ok=True)
    paths.config_file.write_text("hostname: t\nadmin_email: a@b\n")
    write_installed_version(paths, version, "abc1234")
    paths.blocklist.write_text("{}")
    return paths


def _response(payload):
    m = MagicMock()
    m.read.return_value = json.dumps(payload).encode()
    return m


def _offer(version, cls):
    return {"version": version, "url": f"{GH}v{version}", "class": cls}


def _endpoint(security=None, breakfix=None, latest=None, status="up_to_date"):
    return _response({"status": status, "security": security,
                      "breakfix": breakfix, "latest": latest})


def _gh_release(version, title="", body="", **extra):
    return {"tag_name": f"v{version}", "name": title or f"v{version}",
            "html_url": f"{GH}v{version}", "draft": False, "prerelease": False,
            "body": body, **extra}


def _github(releases):
    return _response(releases)


# Endpoint offering security 0.3.2, breakfix 0.3.3, latest 0.4.0 to a 0.3.0 box.
FULL = dict(security=_offer("0.3.2", "security"), breakfix=_offer("0.3.3", "breakfix"),
            latest=_offer("0.4.0", "feature"), status="security_update_available")


class TestEndpointSelection:
    @patch("urllib.request.urlopen")
    def test_up_to_date(self, mock_open, tmp_path):
        mock_open.return_value = _endpoint()
        result = discover_update(_setup(tmp_path), mode="latest")
        assert result == {"action": "up_to_date", "current_version": "0.3.0",
                          "source": "endpoint"}

    @pytest.mark.parametrize("mode,version,cls", [
        ("security", "0.3.2", "security"),
        ("breakfix", "0.3.3", "breakfix"),
        ("latest", "0.4.0", "feature"),
    ])
    @patch("urllib.request.urlopen")
    def test_mode_picks_its_field(self, mock_open, tmp_path, mode, version, cls):
        mock_open.return_value = _endpoint(**FULL)
        result = discover_update(_setup(tmp_path), mode=mode)
        assert result == {"action": "upgrade", "version": version,
                          "url": f"{GH}v{version}", "class": cls, "source": "endpoint"}

    @patch("urllib.request.urlopen")
    def test_security_mode_ignores_breakfix(self, mock_open, tmp_path):
        mock_open.return_value = _endpoint(breakfix=_offer("0.3.3", "breakfix"),
                                           status="breakfix_update_available")
        result = discover_update(_setup(tmp_path), mode="security")
        assert result["action"] == "up_to_date"

    @patch("urllib.request.urlopen")
    def test_breakfix_mode_applies_security_class_offer(self, mock_open, tmp_path):
        offer = _offer("0.3.2", "security")
        mock_open.return_value = _endpoint(security=offer, breakfix=offer)
        result = discover_update(_setup(tmp_path), mode="breakfix")
        assert result["version"] == "0.3.2"
        assert result["class"] == "security"

    @patch("urllib.request.urlopen")
    def test_blocklisted_version(self, mock_open, tmp_path):
        mock_open.return_value = _endpoint(**FULL)
        paths = _setup(tmp_path)
        paths.blocklist.write_text(json.dumps({"0.3.3": "preflight_failed"}))
        result = discover_update(paths, mode="breakfix")
        assert result == {"action": "blocklisted", "version": "0.3.3",
                          "class": "breakfix", "source": "endpoint"}

    @patch("urllib.request.urlopen")
    def test_offer_not_newer_than_installed_is_up_to_date(self, mock_open, tmp_path):
        mock_open.return_value = _endpoint(latest=_offer("0.3.0", "feature"))
        assert discover_update(_setup(tmp_path), mode="latest")["action"] == "up_to_date"

    def test_unknown_mode_raises(self, tmp_path):
        with pytest.raises(ValueError, match="mode"):
            discover_update(_setup(tmp_path), mode="everything")


class TestEndpointContract:
    """A response that breaks the contract is not trusted: discovery falls back
    to GitHub and records why, so the caller can log it."""

    @patch("urllib.request.urlopen")
    def test_missing_breakfix_field_falls_back_to_github(self, mock_open, tmp_path):
        stale = _response({"status": "up_to_date", "security": None, "latest": None})
        mock_open.side_effect = [stale, _github([_gh_release("0.3.1", body="[breakfix] fix")])]
        result = discover_update(_setup(tmp_path), mode="breakfix")
        assert result["action"] == "upgrade"
        assert result["version"] == "0.3.1"
        assert result["source"] == "github"
        assert "breakfix" in result["endpoint_error"]

    @patch("urllib.request.urlopen")
    def test_offer_of_wrong_class_is_rejected(self, mock_open, tmp_path):
        bad = _endpoint(breakfix=_offer("0.3.3", "feature"))
        mock_open.side_effect = [bad, _github([])]
        result = discover_update(_setup(tmp_path), mode="breakfix")
        assert result["source"] == "github"
        assert "feature" in result["endpoint_error"]

    @patch("urllib.request.urlopen")
    def test_non_object_response_is_rejected(self, mock_open, tmp_path):
        mock_open.side_effect = [_response([1, 2]), _github([])]
        result = discover_update(_setup(tmp_path), mode="security")
        assert result["action"] == "up_to_date"
        assert result["source"] == "github"


class TestGitHubFallback:
    def _run(self, tmp_path, releases, mode, version="0.3.0"):
        with patch("urllib.request.urlopen") as mock_open:
            mock_open.side_effect = [URLError("down"), _github(releases)]
            return discover_update(_setup(tmp_path, version), mode=mode)

    def test_security_marker(self, tmp_path):
        result = self._run(tmp_path, [_gh_release("0.3.5", title="v0.3.5 [security]")],
                           "security")
        assert result["action"] == "upgrade"
        assert result["class"] == "security"
        assert result["source"] == "github"
        assert "down" in result["endpoint_error"]

    def test_breakfix_marker_in_body(self, tmp_path):
        result = self._run(tmp_path, [_gh_release("0.3.4", body="Fixes X. [breakfix]")],
                           "breakfix")
        assert result["version"] == "0.3.4"
        assert result["class"] == "breakfix"

    def test_breakfix_marker_case_insensitive(self, tmp_path):
        result = self._run(tmp_path, [_gh_release("0.3.4", title="v0.3.4 [BreakFix]")],
                           "breakfix")
        assert result["class"] == "breakfix"

    def test_security_mode_skips_breakfix(self, tmp_path):
        result = self._run(tmp_path, [_gh_release("0.3.4", body="[breakfix]")], "security")
        assert result["action"] == "up_to_date"

    def test_breakfix_mode_accepts_security(self, tmp_path):
        result = self._run(tmp_path, [_gh_release("0.3.4", body="[security]")], "breakfix")
        assert result["class"] == "security"

    def test_breakfix_mode_skips_feature(self, tmp_path):
        result = self._run(tmp_path, [_gh_release("0.3.4", body="new things")], "breakfix")
        assert result["action"] == "up_to_date"

    def test_security_marker_wins_over_breakfix(self, tmp_path):
        result = self._run(tmp_path, [_gh_release("0.3.4", body="[breakfix] [security]")],
                           "breakfix")
        assert result["class"] == "security"

    def test_auto_modes_stay_on_the_minor_line(self, tmp_path):
        result = self._run(tmp_path, [_gh_release("0.4.1", body="[security]")], "breakfix")
        assert result["action"] == "up_to_date"

    def test_latest_mode_crosses_lines_like_the_endpoint(self, tmp_path):
        result = self._run(tmp_path, [_gh_release("0.4.0"), _gh_release("0.3.1")], "latest")
        assert result["version"] == "0.4.0"
        assert result["class"] == "feature"

    def test_picks_newest_version_regardless_of_order(self, tmp_path):
        releases = [_gh_release("0.3.2", body="[breakfix]"),
                    _gh_release("0.3.10", body="[breakfix]"),
                    _gh_release("0.3.3", body="[breakfix]")]
        assert self._run(tmp_path, releases, "breakfix")["version"] == "0.3.10"

    def test_skips_drafts_prereleases_and_client_tags(self, tmp_path):
        releases = [
            _gh_release("0.3.9", body="[breakfix]", draft=True),
            _gh_release("0.3.8", body="[breakfix]", prerelease=True),
            {**_gh_release("0.3.7", body="[breakfix]"), "tag_name": "cli-v0.3.7"},
            _gh_release("0.3.1", body="[breakfix]"),
        ]
        assert self._run(tmp_path, releases, "breakfix")["version"] == "0.3.1"

    def test_rejects_foreign_release_url(self, tmp_path):
        rel = {**_gh_release("0.3.4", body="[security]"),
               "html_url": "https://evil.example/releases/v0.3.4"}
        assert self._run(tmp_path, [rel], "security")["action"] == "up_to_date"


class TestBothSourcesFail:
    @patch("urllib.request.urlopen")
    def test_both_unreachable_returns_error(self, mock_open, tmp_path):
        mock_open.side_effect = URLError("down")
        result = discover_update(_setup(tmp_path), mode="security")
        assert result["action"] == "error"
        assert "down" in result["message"]

    @patch("urllib.request.urlopen")
    def test_malformed_json_from_both_returns_error(self, mock_open, tmp_path):
        m = MagicMock()
        m.read.return_value = b"not json"
        mock_open.return_value = m
        assert discover_update(_setup(tmp_path), mode="latest")["action"] == "error"

    @patch("urllib.request.urlopen")
    def test_read_timeout_is_a_source_failure(self, mock_open, tmp_path):
        mock_open.side_effect = TimeoutError("timed out")
        result = discover_update(_setup(tmp_path), mode="breakfix")
        assert result["action"] == "error"
