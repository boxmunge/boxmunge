"""Tests for upgrade discovery — release-class selection via endpoint and GitHub."""
import http.client
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch, MagicMock
from urllib.error import HTTPError, URLError

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


def _endpoint(security=None, breakfix=None, latest=None, status="up_to_date", blocked=None):
    return _response({"status": status, "security": security,
                      "breakfix": breakfix, "latest": latest, "blocked": blocked})


def _blocked(version="0.4.2", cls="security", reason=None):
    return {**_offer(version, cls), "reason": reason or {"breaking_release": "0.4.0"}}


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
    @patch("urllib.request.OpenerDirector.open")
    def test_up_to_date(self, mock_open, tmp_path):
        mock_open.return_value = _endpoint()
        result = discover_update(_setup(tmp_path), mode="latest")
        assert result == {"action": "up_to_date", "current_version": "0.3.0",
                          "blocked": None, "source": "endpoint"}

    @pytest.mark.parametrize("mode,version,cls", [
        ("security", "0.3.2", "security"),
        ("breakfix", "0.3.3", "breakfix"),
        ("latest", "0.4.0", "feature"),
    ])
    @patch("urllib.request.OpenerDirector.open")
    def test_mode_picks_its_field(self, mock_open, tmp_path, mode, version, cls):
        mock_open.return_value = _endpoint(**FULL)
        result = discover_update(_setup(tmp_path), mode=mode)
        assert result == {"action": "upgrade", "version": version,
                          "url": f"{GH}v{version}", "class": cls, "source": "endpoint",
                          "current_version": "0.3.0", "blocked": None}

    @patch("urllib.request.OpenerDirector.open")
    def test_security_mode_ignores_breakfix(self, mock_open, tmp_path):
        mock_open.return_value = _endpoint(breakfix=_offer("0.3.3", "breakfix"),
                                           status="breakfix_update_available")
        result = discover_update(_setup(tmp_path), mode="security")
        assert result["action"] == "up_to_date"

    @patch("urllib.request.OpenerDirector.open")
    def test_breakfix_mode_applies_security_class_offer(self, mock_open, tmp_path):
        offer = _offer("0.3.2", "security")
        mock_open.return_value = _endpoint(security=offer, breakfix=offer)
        result = discover_update(_setup(tmp_path), mode="breakfix")
        assert result["version"] == "0.3.2"
        assert result["class"] == "security"

    @patch("urllib.request.OpenerDirector.open")
    def test_blocklisted_version(self, mock_open, tmp_path):
        mock_open.return_value = _endpoint(**FULL)
        paths = _setup(tmp_path)
        paths.blocklist.write_text(json.dumps({"0.3.3": "preflight_failed"}))
        result = discover_update(paths, mode="breakfix")
        assert result == {"action": "blocklisted", "version": "0.3.3",
                          "class": "breakfix", "source": "endpoint",
                          "current_version": "0.3.0", "blocked": None}

    @pytest.mark.parametrize("content", ["{not json", "[]"])
    @patch("urllib.request.OpenerDirector.open")
    def test_unreadable_blocklist_is_an_error_naming_the_file(self, mock_open, tmp_path, content):
        mock_open.return_value = _endpoint(**FULL)
        paths = _setup(tmp_path)
        paths.blocklist.write_text(content)
        result = discover_update(paths, mode="breakfix")
        assert result["action"] == "error"
        assert str(paths.blocklist) in result["message"]
        assert "refuses to install" in result["message"]

    @pytest.mark.parametrize("reason", [{"breaking_release": "0.4.0"}, {"major": 1}])
    @patch("urllib.request.OpenerDirector.open")
    def test_blocked_is_passed_through(self, mock_open, tmp_path, reason):
        mock_open.return_value = _endpoint(blocked=_blocked(reason=reason))
        result = discover_update(_setup(tmp_path), mode="breakfix")
        assert result["action"] == "up_to_date"
        assert result["blocked"] == _blocked(reason=reason)
        assert result["source"] == "endpoint"

    @patch("urllib.request.OpenerDirector.open")
    def test_blocked_rides_along_with_an_upgrade(self, mock_open, tmp_path):
        mock_open.return_value = _endpoint(**FULL, blocked=_blocked())
        result = discover_update(_setup(tmp_path), mode="breakfix")
        assert result["action"] == "upgrade"
        assert result["blocked"]["version"] == "0.4.2"

    @patch("urllib.request.OpenerDirector.open")
    def test_offer_not_newer_than_installed_is_up_to_date(self, mock_open, tmp_path):
        mock_open.return_value = _endpoint(latest=_offer("0.3.0", "feature"))
        assert discover_update(_setup(tmp_path), mode="latest")["action"] == "up_to_date"

    def test_unknown_mode_raises(self, tmp_path):
        with pytest.raises(ValueError, match="mode"):
            discover_update(_setup(tmp_path), mode="everything")


class TestEndpointContract:
    """A response that breaks the contract is not trusted, and it is not
    replaced by GitHub's answer either: only the service knows which releases
    its circuit breaker holds. Discovery fails with the reason and the box
    retries on its next check."""

    def _refused(self, mock_open, tmp_path, mode, *needles):
        result = discover_update(_setup(tmp_path), mode=mode)
        assert result["action"] == "error"
        assert mock_open.call_count == 1  # GitHub was never asked
        for needle in needles:
            assert needle in result["message"]
        assert "held" in result["message"]
        return result

    @patch("urllib.request.OpenerDirector.open")
    def test_missing_breakfix_field_is_an_error(self, mock_open, tmp_path):
        stale = _response({"status": "up_to_date", "security": None, "latest": None})
        mock_open.side_effect = [stale, _github([_gh_release("0.3.1", body="[breakfix] fix")])]
        self._refused(mock_open, tmp_path, "breakfix", "breakfix")

    @patch("urllib.request.OpenerDirector.open")
    def test_missing_blocked_field_is_an_error(self, mock_open, tmp_path):
        stale = _response({"status": "up_to_date", "security": None, "breakfix": None,
                           "latest": None})
        mock_open.side_effect = [stale, _github([])]
        self._refused(mock_open, tmp_path, "breakfix", "blocked")

    @pytest.mark.parametrize("blocked", [
        "0.4.2",
        {**_offer("0.4.2", "security")},
        {**_offer("0.4.2", "feature"), "reason": {"major": 1}},
        {**_offer("0.4", "security"), "reason": {"major": 1}},
        {**_offer("0.4.2", "security"), "reason": {}},
        {**_offer("0.4.2", "security"), "reason": {"major": "1"}},
        {**_offer("0.4.2", "security"), "reason": {"major": True}},
        {**_offer("0.4.2", "security"), "reason": {"breaking_release": "x"}},
        {**_offer("0.4.2", "security"), "reason": {"held": "0.4.0"}},
        {**_offer("0.4.2", "security"),
         "reason": {"major": 1, "breaking_release": "0.4.0"}},
    ])
    @patch("urllib.request.OpenerDirector.open")
    def test_malformed_blocked_is_rejected(self, mock_open, tmp_path, blocked):
        mock_open.side_effect = [_endpoint(blocked=blocked), _github([])]
        self._refused(mock_open, tmp_path, "security", "blocked")

    @patch("urllib.request.OpenerDirector.open")
    def test_offer_of_wrong_class_is_rejected(self, mock_open, tmp_path):
        bad = _endpoint(breakfix=_offer("0.3.3", "feature"))
        mock_open.side_effect = [bad, _github([])]
        self._refused(mock_open, tmp_path, "breakfix", "feature")

    @patch("urllib.request.OpenerDirector.open")
    def test_non_object_response_is_rejected(self, mock_open, tmp_path):
        mock_open.side_effect = [_response([1, 2]), _github([])]
        self._refused(mock_open, tmp_path, "security", "JSON object")

    @patch("urllib.request.OpenerDirector.open")
    def test_non_json_answer_is_rejected(self, mock_open, tmp_path):
        page = MagicMock()
        page.read.return_value = b"<html>not json</html>"
        mock_open.side_effect = [page, _github([])]
        self._refused(mock_open, tmp_path, "security", "not JSON")


class TestServiceErrorAnswers:
    """An HTTP error from the service (its own rate limiter, a server error)
    is an answer, not an outage: falling back to GitHub would offer a release
    the circuit breaker holds, because GitHub's [held] markers can lag its holds."""

    @pytest.mark.parametrize("status", [429, 500, 502, 503])
    @patch("urllib.request.OpenerDirector.open")
    def test_http_error_does_not_fall_back_to_github(self, mock_open, tmp_path, status):
        held_on_github = [_gh_release("0.3.2", title="v0.3.2 [security] fix")]
        mock_open.side_effect = [HTTPError("https://x/v1/check", status, "nope", {}, None),
                                 _github(held_on_github)]
        result = discover_update(_setup(tmp_path), mode="security")
        assert result["action"] == "error"
        assert mock_open.call_count == 1
        assert f"HTTP {status}" in result["message"]
        assert "next check" in result["message"]


class TestBrokenAnswers:
    """An answer that breaks mid-way is still an answer: no GitHub fallback."""

    @patch("urllib.request.OpenerDirector.open")
    def test_a_read_that_breaks_off_is_an_error(self, mock_open, tmp_path):
        resp = MagicMock()
        resp.read.side_effect = ConnectionResetError("reset by peer")
        mock_open.side_effect = [resp, _github([])]
        result = discover_update(_setup(tmp_path), mode="security")
        assert result["action"] == "error"
        assert mock_open.call_count == 1
        assert "broke off" in result["message"]
        assert "reset by peer" in result["endpoint_error"]

    @patch("urllib.request.OpenerDirector.open")
    def test_a_malformed_http_response_is_an_error(self, mock_open, tmp_path):
        mock_open.side_effect = [http.client.BadStatusLine("garbage"), _github([])]
        result = discover_update(_setup(tmp_path), mode="security")
        assert result["action"] == "error"
        assert mock_open.call_count == 1
        assert "malformed" in result["message"]

    def test_a_redirect_to_an_unreachable_host_is_an_error(self, tmp_path, monkeypatch):
        class Redirect(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                self.send_response(302)
                self.send_header("Location", "http://127.0.0.1:9/v1/check")
                self.end_headers()

            def log_message(self, *a):
                pass

        server = HTTPServer(("127.0.0.1", 0), Redirect)
        threading.Thread(target=server.handle_request, daemon=True).start()
        monkeypatch.setenv("BOXMUNGE_VERSION_CHECK_URL",
                           f"http://127.0.0.1:{server.server_address[1]}")
        with patch("urllib.request.urlopen") as github:
            result = discover_update(_setup(tmp_path), mode="security")
        server.server_close()
        assert result["action"] == "error"
        assert "redirected to http://127.0.0.1:9/v1/check" in result["message"]
        github.assert_not_called()


class TestHeld:
    """``held`` lists the releases the service's circuit breaker withholds."""

    @patch("urllib.request.OpenerDirector.open")
    def test_held_versions_ride_along(self, mock_open, tmp_path):
        body = {"status": "up_to_date", "security": None, "breakfix": None,
                "latest": _offer("0.3.2", "security"), "blocked": None,
                "held": [{"version": "0.3.2", "reason": "circuit_breaker"}]}
        mock_open.return_value = _response(body)
        result = discover_update(_setup(tmp_path), mode="security")
        assert result["action"] == "up_to_date"
        assert result["held"] == ["0.3.2"]

    @pytest.mark.parametrize("mode", ["security", "breakfix", "latest"])
    @patch("urllib.request.OpenerDirector.open")
    def test_a_held_candidate_is_never_installed(self, mock_open, tmp_path, mode):
        offer = _offer("0.3.2", "security")
        body = {"status": "security_update_available", "security": offer,
                "breakfix": offer, "latest": offer, "blocked": None,
                "held": [{"version": "0.3.2", "reason": "circuit_breaker"}]}
        mock_open.return_value = _response(body)
        result = discover_update(_setup(tmp_path), mode=mode)
        assert result["action"] == "error"
        assert "0.3.2" in result["message"] and "circuit breaker" in result["message"]

    @patch("urllib.request.OpenerDirector.open")
    def test_a_held_refusal_names_the_deliberate_route(self, mock_open, tmp_path):
        offer = _offer("0.3.2", "security")
        mock_open.return_value = _response({
            "status": "security_update_available", "security": offer, "breakfix": offer,
            "latest": offer, "blocked": None,
            "held": [{"version": "0.3.2", "reason": "circuit_breaker"}]})
        message = discover_update(_setup(tmp_path), mode="latest")["message"]
        assert "upgrade --target 0.3.2" in message
        assert "boxmunge-upgrade target 0.3.2" in message

    @patch("urllib.request.OpenerDirector.open")
    def test_latest_skips_a_held_newest_release_for_the_newest_unheld(self, mock_open,
                                                                      tmp_path):
        mock_open.return_value = _response({
            "status": "update_available", "security": _offer("0.3.2", "security"),
            "breakfix": _offer("0.3.3", "breakfix"), "latest": _offer("0.4.0", "feature"),
            "blocked": None, "held": [{"version": "0.4.0", "reason": "circuit_breaker"}]})
        result = discover_update(_setup(tmp_path), mode="latest")
        assert result["action"] == "upgrade"
        assert result["version"] == "0.3.3"
        assert result["held"] == ["0.4.0"]

    @pytest.mark.parametrize("held", [
        "0.3.2", [{"version": "0.3"}], [{"version": "0.3.2"}], ["0.3.2"],
        [{"version": "0.3.2", "reason": 1}],
    ])
    @patch("urllib.request.OpenerDirector.open")
    def test_malformed_held_is_rejected(self, mock_open, tmp_path, held):
        body = {"status": "up_to_date", "security": None, "breakfix": None,
                "latest": None, "blocked": None, "held": held}
        mock_open.side_effect = [_response(body), _github([])]
        result = discover_update(_setup(tmp_path), mode="security")
        assert result["action"] == "error"
        assert mock_open.call_count == 1
        assert "'held'" in result["message"]


class TestGitHubFallback:
    def _run(self, tmp_path, releases, mode, version="0.3.0"):
        with patch("urllib.request.OpenerDirector.open") as mock_open:
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

    def test_auto_modes_cross_minor_lines_when_nothing_breaks(self, tmp_path):
        releases = [_gh_release("0.4.1", body="[security]"), _gh_release("0.4.0")]
        result = self._run(tmp_path, releases, "breakfix")
        assert result["action"] == "upgrade"
        assert result["version"] == "0.4.1"
        assert result["blocked"] is None

    def test_breaking_marker_blocks_crossing(self, tmp_path):
        releases = [_gh_release("0.4.1", body="[security]"),
                    _gh_release("0.4.0", title="v0.4.0 [breaking]")]
        result = self._run(tmp_path, releases, "security")
        assert result["action"] == "up_to_date"
        assert result["blocked"] == {"version": "0.4.1", "url": f"{GH}v0.4.1",
                                     "class": "security",
                                     "reason": {"breaking_release": "0.4.0"}}

    def test_breaking_candidate_itself_is_blocked(self, tmp_path):
        releases = [_gh_release("0.4.0", title="v0.4.0 [breakfix] [Breaking]")]
        result = self._run(tmp_path, releases, "breakfix")
        assert result["action"] == "up_to_date"
        assert result["blocked"]["reason"] == {"breaking_release": "0.4.0"}

    def test_never_crosses_a_major_version(self, tmp_path):
        result = self._run(tmp_path, [_gh_release("1.0.1", body="[security]")], "security")
        assert result["action"] == "up_to_date"
        assert result["blocked"]["reason"] == {"major": 1}

    def test_breaking_draft_does_not_block(self, tmp_path):
        releases = [_gh_release("0.4.1", body="[security]"),
                    _gh_release("0.4.0", title="[breaking]", draft=True)]
        assert self._run(tmp_path, releases, "security")["version"] == "0.4.1"

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
    @patch("urllib.request.OpenerDirector.open")
    def test_both_unreachable_returns_error(self, mock_open, tmp_path):
        mock_open.side_effect = URLError("down")
        result = discover_update(_setup(tmp_path), mode="security")
        assert result["action"] == "error"
        assert "down" in result["message"]

    @patch("urllib.request.OpenerDirector.open")
    def test_malformed_json_from_both_returns_error(self, mock_open, tmp_path):
        m = MagicMock()
        m.read.return_value = b"not json"
        mock_open.return_value = m
        assert discover_update(_setup(tmp_path), mode="latest")["action"] == "error"

    @patch("urllib.request.OpenerDirector.open")
    def test_read_timeout_is_a_source_failure(self, mock_open, tmp_path):
        mock_open.side_effect = TimeoutError("timed out")
        result = discover_update(_setup(tmp_path), mode="breakfix")
        assert result["action"] == "error"
