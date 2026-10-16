"""Tests for the version-check service."""

import json
import sqlite3
import pytest
from pathlib import Path
from unittest.mock import patch

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture
def releases_data():
    """Multi-version release data for testing."""
    return {
        "releases": [
            {"version": "0.3.0", "class": "feature", "breaking": True,
             "url": "https://github.com/boxmunge/boxmunge/releases/tag/v0.3.0"},
            {"version": "0.2.1", "class": "security", "breaking": False,
             "url": "https://github.com/boxmunge/boxmunge/releases/tag/v0.2.1"},
            {"version": "0.2.0", "class": "feature", "breaking": True,
             "url": "https://github.com/boxmunge/boxmunge/releases/tag/v0.2.0"},
            {"version": "0.1.0", "class": "feature", "breaking": False,
             "url": "https://github.com/boxmunge/boxmunge/releases/tag/v0.1.0"},
        ]
    }


@pytest.fixture
def app(tmp_path, releases_data):
    """Flask test client with test releases and temp SQLite."""
    releases_file = tmp_path / "releases.json"
    releases_file.write_text(json.dumps(releases_data))

    db_path = tmp_path / "checks.db"

    with patch("app.RELEASES_PATH", releases_file), \
         patch("app.DB_PATH", db_path):
        from app import create_app
        application = create_app()
        application.config["TESTING"] = True
        yield application


@pytest.fixture
def client(app):
    return app.test_client()


class TestCheckEndpoint:
    def test_security_update_available(self, client) -> None:
        resp = client.get("/v1/check?v=0.2.0")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "security_update_available"
        assert data["security"]["version"] == "0.2.1"
        assert data["latest"]["version"] == "0.3.0"

    def test_up_to_date(self, client) -> None:
        resp = client.get("/v1/check?v=0.3.0")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "up_to_date"
        assert data["security"] is None
        assert data["latest"] is None

    def test_update_available_no_security(self, client) -> None:
        resp = client.get("/v1/check?v=0.2.1")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "update_available"
        assert data["security"] is None
        assert data["latest"]["version"] == "0.3.0"

    def test_missing_version_param(self, client) -> None:
        resp = client.get("/v1/check")
        assert resp.status_code == 400
        data = resp.get_json()
        assert "error" in data

    def test_empty_version_param(self, client) -> None:
        resp = client.get("/v1/check?v=")
        assert resp.status_code == 400

    def test_unknown_version_returns_latest(self, client) -> None:
        resp = client.get("/v1/check?v=0.0.1")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["security"] is None
        assert data["latest"]["version"] == "0.3.0"

    def test_no_cache_header(self, client) -> None:
        resp = client.get("/v1/check?v=0.2.0")
        assert resp.headers.get("Cache-Control") == "no-cache"

    def test_security_not_offered_across_a_breaking_release(self, client) -> None:
        """v0.1.0 must not be offered v0.2.1: v0.2.0 between them is breaking."""
        resp = client.get("/v1/check?v=0.1.0")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["security"] is None
        assert data["latest"]["version"] == "0.3.0"
        assert data["blocked"] == {
            "version": "0.2.1", "class": "security",
            "url": "https://github.com/boxmunge/boxmunge/releases/tag/v0.2.1",
            "reason": {"breaking_release": "0.2.0"},
        }

    def test_blocked_is_null_when_nothing_is_blocked(self, client) -> None:
        data = client.get("/v1/check?v=0.2.0").get_json()
        assert data["blocked"] is None


def _check_counts(db_path) -> dict:
    db = sqlite3.connect(db_path)
    try:
        return dict(db.execute("SELECT version, count FROM version_checks").fetchall())
    finally:
        db.close()


class TestCounter:
    def test_counts_are_buffered_not_written_per_request(self, app, client, tmp_path) -> None:
        client.get("/v1/check?v=0.2.0")
        client.get("/v1/check?v=0.2.0")
        client.get("/v1/check?v=0.3.0")
        assert _check_counts(tmp_path / "checks.db") == {}
        app.extensions["check_counter"].flush()
        assert _check_counts(tmp_path / "checks.db") == {"0.2.0": 2, "0.3.0": 1}

    def test_unlisted_versions_share_one_bucket(self, app, client, tmp_path) -> None:
        client.get("/v1/check?v=7.7.7")
        client.get("/v1/check?v=8.8.8")
        app.extensions["check_counter"].flush()
        assert _check_counts(tmp_path / "checks.db") == {"unlisted": 2}

    def test_no_counter_on_error(self, app, client, tmp_path) -> None:
        client.get("/v1/check")  # missing param — 400
        client.get("/v1/check?v=not-a-version")  # malformed — 400
        app.extensions["check_counter"].flush()
        assert _check_counts(tmp_path / "checks.db") == {}

    def test_malformed_version_rejected(self, client) -> None:
        resp = client.get("/v1/check?v=1.2.3;drop")
        assert resp.status_code == 400


def _rel(version: str, cls: str) -> dict:
    return {"version": version, "class": cls, "breaking": False,
            "url": f"https://github.com/boxmunge/boxmunge/releases/tag/v{version}"}


def _make_app(tmp_path, releases: list[dict]):
    releases_file = tmp_path / "releases.json"
    releases_file.write_text(json.dumps({"releases": releases}))
    with patch("app.RELEASES_PATH", releases_file), \
         patch("app.DB_PATH", tmp_path / "checks.db"):
        from app import create_app
        application = create_app()
        application.config["TESTING"] = True
        return application


class TestStartupValidation:
    def test_refuses_to_start_on_entry_without_class(self, tmp_path) -> None:
        from release_catalog import ReleaseCatalogError
        bad = {"version": "0.3.0", "security": False,
               "url": "https://github.com/boxmunge/boxmunge/releases/tag/v0.3.0"}
        with pytest.raises(ReleaseCatalogError, match="class"):
            _make_app(tmp_path, [bad])

    def test_refuses_to_start_on_entry_without_breaking(self, tmp_path) -> None:
        from release_catalog import ReleaseCatalogError
        entry = _rel("0.3.0", "feature")
        del entry["breaking"]
        with pytest.raises(ReleaseCatalogError, match="breaking"):
            _make_app(tmp_path, [entry])

    def test_refuses_to_start_on_non_boolean_breaking(self, tmp_path) -> None:
        from release_catalog import ReleaseCatalogError
        entry = {**_rel("0.3.0", "feature"), "breaking": "no"}
        with pytest.raises(ReleaseCatalogError, match="breaking"):
            _make_app(tmp_path, [entry])

    def test_refuses_to_start_on_unknown_class(self, tmp_path) -> None:
        from release_catalog import ReleaseCatalogError
        with pytest.raises(ReleaseCatalogError, match="urgent"):
            _make_app(tmp_path, [_rel("0.3.0", "urgent")])


class TestBreakfixOffer:
    @pytest.fixture
    def bf_client(self, tmp_path):
        with patch("app.DB_PATH", tmp_path / "checks.db"):
            yield _make_app(tmp_path, [
                _rel("0.4.0", "feature"),
                _rel("0.3.2", "breakfix"),
                _rel("0.3.1", "security"),
                _rel("0.3.0", "feature"),
            ]).test_client()

    def test_breakfix_field_and_status(self, bf_client) -> None:
        data = bf_client.get("/v1/check?v=0.3.1").get_json()
        assert data["status"] == "breakfix_update_available"
        assert data["security"] is None
        assert data["breakfix"]["version"] == "0.3.2"
        assert data["breakfix"]["class"] == "breakfix"
        assert data["latest"]["version"] == "0.4.0"

    def test_security_still_reported_alongside_breakfix(self, bf_client) -> None:
        data = bf_client.get("/v1/check?v=0.3.0").get_json()
        assert data["status"] == "security_update_available"
        assert data["security"]["version"] == "0.3.1"
        assert data["breakfix"]["version"] == "0.3.2"
