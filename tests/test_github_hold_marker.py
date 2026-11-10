"""The GitHub twin of a circuit-breaker hold: ``[held]`` in a release title.

A box falls back to the GitHub releases list only when the version-check
service cannot be reached at all; without a twin, a hold would vanish
exactly then (review VC-1). Only the title counts: release notes quote
contributors' PR titles, and only the maintainer edits a title.
"""
from unittest.mock import patch
from urllib.error import URLError

import pytest

from boxmunge.release_selection import github_release_held, parse_github_releases
from boxmunge.upgrade_discovery import discover_update
from tests.test_upgrade_discovery import GH, _gh_release, _github, _setup


def _via_github(tmp_path, releases, mode, version="0.3.0"):
    with patch("urllib.request.OpenerDirector.open") as mock_open:
        mock_open.side_effect = [URLError("down"), _github(releases)]
        return discover_update(_setup(tmp_path, version), mode=mode)


class TestMarker:
    @pytest.mark.parametrize("title, held", [
        ("v0.3.5 [security] [held]", True),
        ("v0.3.5 [security] [HELD]", True),
        ("v0.3.5 [security]", False),
    ])
    def test_read_from_the_title(self, title, held):
        assert github_release_held({"name": title, "body": ""}) is held

    def test_never_from_the_notes(self):
        assert not github_release_held({"name": "v0.3.5 [security]",
                                        "body": "Merged: [held] something"})

    def test_parsed_releases_carry_it(self):
        parsed = parse_github_releases([_gh_release("0.3.5", title="v0.3.5 [security] [held]")])
        assert parsed[0]["held"] is True


class TestFallbackHonoursIt:
    @pytest.mark.parametrize("mode", ["security", "breakfix"])
    def test_auto_update_withholds_a_held_release(self, tmp_path, mode):
        result = _via_github(tmp_path, [_gh_release("0.3.5", title="v0.3.5 [security] [held]")],
                             mode)
        assert result["action"] == "up_to_date"
        assert result["held"] == ["0.3.5"]

    def test_a_manual_upgrade_refuses_a_held_release_naming_the_deliberate_route(
            self, tmp_path):
        result = _via_github(tmp_path, [_gh_release("0.3.5", title="v0.3.5 [security] [held]")],
                             "latest")
        assert result["action"] == "error"
        assert "0.3.5" in result["message"] and "GitHub release title" in result["message"]
        assert "upgrade --target 0.3.5" in result["message"]

    def test_held_in_the_notes_only_is_installed(self, tmp_path):
        result = _via_github(tmp_path, [_gh_release(
            "0.3.5", title="v0.3.5 [security]", body="Reverts #12 ([held] in its title)")],
            "security")
        assert result["action"] == "upgrade" and result["version"] == "0.3.5"

    def test_a_held_breakfix_gives_way_to_the_unheld_security_release(self, tmp_path):
        releases = [_gh_release("0.3.6", title="v0.3.6 [breakfix] [held]"),
                    _gh_release("0.3.5", title="v0.3.5 [security]")]
        result = _via_github(tmp_path, releases, "breakfix")
        assert (result["action"], result["version"]) == ("upgrade", "0.3.5")
        assert result["held"] == ["0.3.6"]
        assert result["source"] == "github"

    def test_a_held_release_is_not_replaced_by_an_older_one(self, tmp_path):
        releases = [_gh_release("0.3.6", title="v0.3.6 [security] [held]"),
                    _gh_release("0.3.5", title="v0.3.5 [security]")]
        result = _via_github(tmp_path, releases, "security")
        assert result["action"] == "up_to_date"
        assert result["held"] == ["0.3.6"]

    def test_latest_skips_a_held_newest_release_for_the_newest_unheld(self, tmp_path):
        releases = [_gh_release("0.3.6", title="v0.3.6 [breakfix] [held]"),
                    _gh_release("0.3.5", title="v0.3.5 [security]")]
        result = _via_github(tmp_path, releases, "latest")
        assert (result["action"], result["version"]) == ("upgrade", "0.3.5")
        assert result["url"] == f"{GH}v0.3.5"
