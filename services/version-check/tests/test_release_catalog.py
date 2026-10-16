"""Tests for the release catalogue: releases.json validation and selection."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from release_catalog import (  # noqa: E402
    ReleaseCatalogError,
    apply_holds,
    check_response,
    find_blocked,
    load_releases,
    select_offers,
    validate_releases,
)

SERVICE_DIR = Path(__file__).parent.parent


def _rel(version: str, cls: str, breaking: bool = False) -> dict:
    return {
        "version": version,
        "class": cls,
        "breaking": breaking,
        "url": f"https://github.com/boxmunge/boxmunge/releases/tag/v{version}",
    }


class TestValidation:
    def test_shipped_releases_json_is_valid(self) -> None:
        releases = load_releases(SERVICE_DIR / "releases.json")
        assert releases, "releases.json must list at least one release"
        assert all(r["class"] in {"feature", "breakfix", "security"} for r in releases)
        assert all(isinstance(r["breaking"], bool) for r in releases)

    def test_accepts_every_class(self) -> None:
        validate_releases({"releases": [
            _rel("0.3.2", "security"), _rel("0.3.1", "breakfix"), _rel("0.3.0", "feature"),
        ]}, source="t")

    def test_rejects_missing_class(self) -> None:
        entry = _rel("0.3.0", "feature")
        del entry["class"]
        with pytest.raises(ReleaseCatalogError, match="class"):
            validate_releases({"releases": [entry]}, source="t")

    def test_rejects_legacy_security_bool(self) -> None:
        entry = _rel("0.3.0", "feature")
        del entry["class"]
        entry["security"] = True
        with pytest.raises(ReleaseCatalogError, match="security"):
            validate_releases({"releases": [entry]}, source="t")

    def test_rejects_missing_breaking(self) -> None:
        entry = _rel("0.3.0", "feature")
        del entry["breaking"]
        with pytest.raises(ReleaseCatalogError, match="breaking"):
            validate_releases({"releases": [entry]}, source="t")

    @pytest.mark.parametrize("value", ["false", 0, 1, None, "yes"])
    def test_rejects_non_boolean_breaking(self, value) -> None:
        entry = _rel("0.3.0", "feature")
        entry["breaking"] = value
        with pytest.raises(ReleaseCatalogError, match="breaking"):
            validate_releases({"releases": [entry]}, source="t")

    def test_rejects_unknown_class(self) -> None:
        with pytest.raises(ReleaseCatalogError, match="hotfix"):
            validate_releases({"releases": [_rel("0.3.0", "hotfix")]}, source="t")

    def test_rejects_non_string_class(self) -> None:
        entry = _rel("0.3.0", "feature")
        entry["class"] = True
        with pytest.raises(ReleaseCatalogError, match="class"):
            validate_releases({"releases": [entry]}, source="t")

    def test_rejects_extra_keys(self) -> None:
        entry = _rel("0.3.0", "feature")
        entry["notes"] = "x"
        with pytest.raises(ReleaseCatalogError, match="notes"):
            validate_releases({"releases": [entry]}, source="t")

    def test_rejects_malformed_version(self) -> None:
        entry = _rel("0.3", "feature")
        with pytest.raises(ReleaseCatalogError, match="version"):
            validate_releases({"releases": [entry]}, source="t")

    def test_rejects_url_not_matching_version(self) -> None:
        entry = _rel("0.3.0", "feature")
        entry["url"] = "https://github.com/boxmunge/boxmunge/releases/tag/v0.3.1"
        with pytest.raises(ReleaseCatalogError, match="url"):
            validate_releases({"releases": [entry]}, source="t")

    def test_rejects_duplicate_version(self) -> None:
        with pytest.raises(ReleaseCatalogError, match="duplicate"):
            validate_releases({"releases": [
                _rel("0.3.0", "feature"), _rel("0.3.0", "security"),
            ]}, source="t")

    def test_rejects_empty_list(self) -> None:
        with pytest.raises(ReleaseCatalogError):
            validate_releases({"releases": []}, source="t")

    def test_rejects_missing_releases_key(self) -> None:
        with pytest.raises(ReleaseCatalogError):
            validate_releases({"versions": []}, source="t")

    def test_load_names_the_file(self, tmp_path) -> None:
        path = tmp_path / "releases.json"
        path.write_text(json.dumps({"releases": [_rel("0.3.0", "nope")]}))
        with pytest.raises(ReleaseCatalogError, match="releases.json"):
            load_releases(path)


CATALOG = [
    _rel("0.4.0", "feature", breaking=True),
    _rel("0.3.4", "feature"),
    _rel("0.3.3", "breakfix"),
    _rel("0.3.2", "security"),
    _rel("0.3.1", "breakfix"),
    _rel("0.3.0", "feature", breaking=True),
]


def _check(caller: str, held: frozenset[str] = frozenset(), catalog=None) -> dict:
    catalog = catalog or CATALOG
    offers = select_offers(catalog, caller)
    offers, held_list = apply_holds(offers, lambda v: v in held)
    return check_response(offers, held_list, find_blocked(catalog, caller))


class TestSelection:
    def test_security_is_newest_reachable_security_release(self) -> None:
        assert _check("0.3.0")["security"]["version"] == "0.3.2"

    def test_security_shape_unchanged_for_deployed_boxes(self) -> None:
        sec = _check("0.3.0")["security"]
        assert sec["version"] == "0.3.2"
        assert sec["url"] == "https://github.com/boxmunge/boxmunge/releases/tag/v0.3.2"

    def test_breakfix_is_newest_reachable_breakfix_or_security(self) -> None:
        data = _check("0.3.0")
        assert data["breakfix"]["version"] == "0.3.3"
        assert data["breakfix"]["class"] == "breakfix"

    def test_breakfix_includes_security_class(self) -> None:
        catalog = [_rel("0.3.2", "security"), _rel("0.3.1", "breakfix"), _rel("0.3.0", "feature")]
        assert _check("0.3.0", catalog=catalog)["breakfix"] == {
            "version": "0.3.2", "class": "security",
            "url": "https://github.com/boxmunge/boxmunge/releases/tag/v0.3.2",
        }

    def test_feature_releases_never_offered_as_breakfix(self) -> None:
        data = _check("0.3.3")
        assert data["breakfix"] is None
        assert data["security"] is None
        assert data["latest"]["version"] == "0.4.0"
        assert data["status"] == "update_available"

    def test_security_status_takes_precedence(self) -> None:
        assert _check("0.3.0")["status"] == "security_update_available"

    def test_breakfix_status_when_no_security(self) -> None:
        data = _check("0.3.2")
        assert data["security"] is None
        assert data["breakfix"]["version"] == "0.3.3"
        assert data["status"] == "breakfix_update_available"

    def test_breaking_release_on_the_path_stops_auto_candidates(self) -> None:
        data = _check("0.2.9")
        assert data["breakfix"] is None
        assert data["security"] is None
        assert data["latest"]["version"] == "0.4.0"

    def test_up_to_date(self) -> None:
        assert _check("0.4.0") == {"status": "up_to_date", "security": None,
                                   "breakfix": None, "latest": None, "blocked": None}

    def test_latest_carries_class(self) -> None:
        assert _check("0.3.0")["latest"]["class"] == "feature"


class TestCrossLine:
    """Security and break-fix candidates cross minor lines when no release in
    (caller, candidate] is breaking, and never cross a major version."""

    def test_security_crosses_minor_lines_when_nothing_breaks(self) -> None:
        catalog = [_rel("0.11.2", "security"), _rel("0.11.0", "feature"),
                   _rel("0.10.3", "feature")]
        data = _check("0.10.3", catalog=catalog)
        assert data["security"]["version"] == "0.11.2"
        assert data["breakfix"]["version"] == "0.11.2"
        assert data["blocked"] is None

    def test_breaking_release_between_blocks_and_is_named(self) -> None:
        catalog = [_rel("0.11.2", "security"), _rel("0.11.0", "feature", breaking=True),
                   _rel("0.10.3", "feature")]
        data = _check("0.10.3", catalog=catalog)
        assert data["security"] is None and data["breakfix"] is None
        assert data["latest"]["version"] == "0.11.2"
        assert data["status"] == "update_available"
        assert data["blocked"] == {
            "version": "0.11.2", "class": "security",
            "url": "https://github.com/boxmunge/boxmunge/releases/tag/v0.11.2",
            "reason": {"breaking_release": "0.11.0"},
        }

    def test_breaking_candidate_itself_is_not_offered(self) -> None:
        catalog = [_rel("0.10.4", "security", breaking=True), _rel("0.10.3", "feature")]
        data = _check("0.10.3", catalog=catalog)
        assert data["security"] is None
        assert data["blocked"]["reason"] == {"breaking_release": "0.10.4"}

    def test_names_the_first_breaking_release_on_the_path(self) -> None:
        catalog = [_rel("0.13.1", "breakfix"), _rel("0.13.0", "feature", breaking=True),
                   _rel("0.12.0", "feature", breaking=True), _rel("0.11.0", "feature")]
        data = _check("0.11.0", catalog=catalog)
        assert data["blocked"]["version"] == "0.13.1"
        assert data["blocked"]["class"] == "breakfix"
        assert data["blocked"]["reason"] == {"breaking_release": "0.12.0"}

    def test_breaking_release_at_or_below_caller_does_not_block(self) -> None:
        catalog = [_rel("0.11.3", "security"), _rel("0.11.0", "feature", breaking=True)]
        data = _check("0.11.0", catalog=catalog)
        assert data["security"]["version"] == "0.11.3"
        assert data["blocked"] is None

    def test_offers_the_newest_reachable_and_blocks_the_rest(self) -> None:
        catalog = [_rel("0.12.1", "security"), _rel("0.12.0", "feature", breaking=True),
                   _rel("0.11.4", "breakfix"), _rel("0.11.1", "security"),
                   _rel("0.11.0", "feature"), _rel("0.10.3", "feature")]
        data = _check("0.10.3", catalog=catalog)
        assert data["security"]["version"] == "0.11.1"
        assert data["breakfix"]["version"] == "0.11.4"
        assert data["blocked"]["version"] == "0.12.1"
        assert data["blocked"]["reason"] == {"breaking_release": "0.12.0"}
        assert data["status"] == "security_update_available"

    def test_never_crosses_a_major_version(self) -> None:
        catalog = [_rel("1.0.1", "security"), _rel("1.0.0", "feature"),
                   _rel("0.11.0", "feature")]
        data = _check("0.11.0", catalog=catalog)
        assert data["security"] is None and data["breakfix"] is None
        assert data["blocked"]["version"] == "1.0.1"
        assert data["blocked"]["reason"] == {"major": 1}

    def test_feature_release_is_never_blocked(self) -> None:
        catalog = [_rel("0.12.0", "feature", breaking=True), _rel("0.11.0", "feature")]
        assert _check("0.11.0", catalog=catalog)["blocked"] is None

    def test_blocked_ignores_circuit_breaker_holds(self) -> None:
        catalog = [_rel("0.11.2", "security"), _rel("0.11.0", "feature", breaking=True),
                   _rel("0.10.3", "feature")]
        data = _check("0.10.3", held=frozenset({"0.11.2"}), catalog=catalog)
        assert data["blocked"]["version"] == "0.11.2"
        assert "held" not in data


class TestHolds:
    def test_held_security_candidate_is_withheld(self) -> None:
        data = _check("0.3.0", held=frozenset({"0.3.2"}))
        assert data["security"] is None
        assert data["breakfix"]["version"] == "0.3.3"
        assert data["status"] == "breakfix_update_available"
        assert data["held"] == [{"version": "0.3.2", "reason": "circuit_breaker"}]

    def test_held_breakfix_candidate_is_withheld(self) -> None:
        data = _check("0.3.2", held=frozenset({"0.3.3"}))
        assert data["breakfix"] is None
        assert data["status"] == "update_available"
        assert data["held"] == [{"version": "0.3.3", "reason": "circuit_breaker"}]

    def test_held_breakfix_falls_back_to_unheld_security(self) -> None:
        """A breakfix-enabled box must never be offered less than a
        security-only box: when the breakfix candidate is held, the security
        candidate (itself a break-fix-class release) stands in."""
        data = _check("0.3.0", held=frozenset({"0.3.3"}))
        assert data["security"]["version"] == "0.3.2"
        assert data["breakfix"]["version"] == "0.3.2"
        assert data["breakfix"]["class"] == "security"
        assert data["held"] == [{"version": "0.3.3", "reason": "circuit_breaker"}]

    def test_same_version_held_once(self) -> None:
        catalog = [_rel("0.3.2", "security"), _rel("0.3.0", "feature")]
        data = _check("0.3.0", held=frozenset({"0.3.2"}), catalog=catalog)
        assert data["security"] is None and data["breakfix"] is None
        assert data["held"] == [{"version": "0.3.2", "reason": "circuit_breaker"}]
        # The circuit breaker withholds auto-apply candidates, not `latest`.
        assert data["status"] == "update_available"

    def test_both_held(self) -> None:
        data = _check("0.3.0", held=frozenset({"0.3.2", "0.3.3"}))
        assert data["security"] is None and data["breakfix"] is None
        assert [h["version"] for h in data["held"]] == ["0.3.2", "0.3.3"]

    def test_held_cross_line_candidate_is_withheld(self) -> None:
        catalog = [_rel("0.11.2", "security"), _rel("0.11.0", "feature"),
                   _rel("0.10.3", "feature")]
        data = _check("0.10.3", held=frozenset({"0.11.2"}), catalog=catalog)
        assert data["security"] is None and data["breakfix"] is None
        assert data["held"] == [{"version": "0.11.2", "reason": "circuit_breaker"}]
        assert data["blocked"] is None

    def test_no_held_key_when_nothing_held(self) -> None:
        assert "held" not in _check("0.3.0")
