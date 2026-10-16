# SPDX-License-Identifier: Apache-2.0
"""The version-check service and the box's GitHub fallback must agree.

Both decide which security or break-fix release a box may install, and
which one it is blocked from, but they are separate implementations
(services/version-check/release_catalog.py and
boxmunge.release_selection). One scenario table runs through three paths:

- the service's selection on its own;
- the box's discovery reading the service's /v1/check response;
- the box's discovery falling back to the GitHub releases list, where class
  and breaking come from title markers.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.error import URLError

import pytest

from boxmunge.paths import BoxPaths
from boxmunge.upgrade_discovery import discover_update
from boxmunge.version import write_installed_version

REPO = Path(__file__).resolve().parents[1]
GH = "https://github.com/boxmunge/boxmunge/releases/tag/v"


def _load_catalog():
    path = REPO / "services" / "version-check" / "release_catalog.py"
    spec = importlib.util.spec_from_file_location("parity_release_catalog", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


catalog = _load_catalog()

# (version, class, breaking)
LINES = [
    ("0.10.3", "feature", False),
    ("0.10.4", "security", False),
    ("0.11.0", "feature", False),
    ("0.11.1", "breakfix", False),
    ("0.11.2", "security", False),
    ("0.12.0", "feature", True),
    ("0.12.1", "security", False),
    ("0.12.2", "breakfix", False),
    ("1.0.0", "feature", True),
    ("1.0.1", "security", False),
]
BREAKING_SECURITY = [
    ("0.20.0", "feature", False),
    ("0.21.0", "security", True),
    ("0.21.1", "breakfix", False),
]

# (name, releases, caller, security, breakfix, blocked version, blocked reason)
SCENARIOS = [
    ("same line", LINES, "0.10.3", "0.11.2", "0.11.2", "1.0.1",
     {"major": 1}),
    ("cross line, nothing breaking", LINES, "0.11.0", "0.11.2", "0.11.2", "1.0.1",
     {"major": 1}),
    ("on top of a breaking release", LINES, "0.12.0", "0.12.1", "0.12.2", "1.0.1",
     {"major": 1}),
    ("only a major bump ahead", LINES, "0.12.2", None, None, "1.0.1", {"major": 1}),
    ("newest", LINES, "1.0.1", None, None, None, None),
    ("breaking minor ahead", LINES[:8], "0.11.2", None, None, "0.12.2",
     {"breaking_release": "0.12.0"}),
    ("breaking security release", BREAKING_SECURITY, "0.20.0", None, None, "0.21.1",
     {"breaking_release": "0.21.0"}),
    ("past the breaking security release", BREAKING_SECURITY, "0.21.0", None, "0.21.1",
     None, None),
    ("unknown old caller", LINES, "0.9.0", "0.11.2", "0.11.2", "1.0.1",
     {"major": 1}),
]


def _service_entries(releases):
    return [{"version": v, "class": c, "breaking": b, "url": f"{GH}{v}"}
            for v, c, b in releases]


def _github_entries(releases):
    out = []
    for v, c, b in releases:
        markers = ([f"[{c}]"] if c != "feature" else []) + (["[breaking]"] if b else [])
        out.append({"tag_name": f"v{v}", "name": " ".join([f"v{v}", *markers]),
                    "body": "", "html_url": f"{GH}{v}", "draft": False,
                    "prerelease": False})
    return out


def _response(payload):
    m = MagicMock()
    m.read.return_value = json.dumps(payload).encode()
    return m


def _box(tmp_path, version):
    paths = BoxPaths(root=tmp_path / "bm")
    for d in ["config", "upgrade-state", "logs"]:
        (paths.root / d).mkdir(parents=True, exist_ok=True)
    paths.config_file.write_text("hostname: t\nadmin_email: a@b\n")
    write_installed_version(paths, version, "abc1234")
    paths.blocklist.write_text("{}")
    return paths


def _expected_blocked(releases, version, reason):
    if version is None:
        return None
    cls = next(c for v, c, _ in releases if v == version)
    return {"version": version, "url": f"{GH}{version}", "class": cls, "reason": reason}


def _version(result):
    return result["version"] if result.get("action") == "upgrade" else None


@pytest.mark.parametrize(
    "name,releases,caller,security,breakfix,blocked,reason",
    SCENARIOS, ids=[s[0] for s in SCENARIOS])
class TestParity:
    def test_service(self, name, releases, caller, security, breakfix, blocked, reason):
        entries = _service_entries(releases)
        offers = catalog.select_offers(entries, caller)
        assert (offers["security"] or {}).get("version") == security
        assert (offers["breakfix"] or {}).get("version") == breakfix
        assert catalog.find_blocked(entries, caller) == _expected_blocked(
            releases, blocked, reason)

    @pytest.mark.parametrize("mode", ["security", "breakfix"])
    def test_box_via_endpoint(self, tmp_path, mode, name, releases, caller, security,
                              breakfix, blocked, reason):
        entries = _service_entries(releases)
        offers, held = catalog.apply_holds(catalog.select_offers(entries, caller),
                                           lambda v: False)
        body = catalog.check_response(offers, held, catalog.find_blocked(entries, caller))
        with patch("urllib.request.urlopen", return_value=_response(body)):
            result = discover_update(_box(tmp_path, caller), mode=mode)
        assert result["source"] == "endpoint"
        assert _version(result) == {"security": security, "breakfix": breakfix}[mode]
        assert result["blocked"] == _expected_blocked(releases, blocked, reason)

    @pytest.mark.parametrize("mode", ["security", "breakfix"])
    def test_box_via_github(self, tmp_path, mode, name, releases, caller, security,
                            breakfix, blocked, reason):
        github = _response(_github_entries(releases))
        with patch("urllib.request.urlopen", side_effect=[URLError("down"), github]):
            result = discover_update(_box(tmp_path, caller), mode=mode)
        assert result["source"] == "github"
        assert _version(result) == {"security": security, "breakfix": breakfix}[mode]
        assert result["blocked"] == _expected_blocked(releases, blocked, reason)


def test_shipped_catalog_agrees_for_every_listed_caller():
    """Both implementations, fed the real releases.json, agree for every
    version a box could be running."""
    from boxmunge import release_selection
    entries = catalog.load_releases(REPO / "services" / "version-check" / "releases.json")
    for caller in [r["version"] for r in entries]:
        offers = catalog.select_offers(entries, caller)
        for mode in ("security", "breakfix"):
            box = release_selection.select(entries, caller, mode)
            assert (box or {}).get("version") == (offers[mode] or {}).get("version"), caller
        assert release_selection.find_blocked(entries, caller) == catalog.find_blocked(
            entries, caller), caller
