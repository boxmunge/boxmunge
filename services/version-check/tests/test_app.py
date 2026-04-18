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
            {"version": "0.3.0", "security": False,
             "url": "https://github.com/boxmunge/boxmunge/releases/tag/v0.3.0"},
            {"version": "0.2.1", "security": True,
             "url": "https://github.com/boxmunge/boxmunge/releases/tag/v0.2.1"},
            {"version": "0.2.0", "security": False,
             "url": "https://github.com/boxmunge/boxmunge/releases/tag/v0.2.0"},
            {"version": "0.1.0", "security": False,
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

    def test_security_only_same_minor_line(self, client) -> None:
        """v0.1.0 should NOT see v0.2.1 as a security update."""
        resp = client.get("/v1/check?v=0.1.0")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["security"] is None
        assert data["latest"]["version"] == "0.3.0"


class TestCounter:
    def test_increments_counter(self, client, tmp_path) -> None:
        with patch("app.DB_PATH", tmp_path / "checks.db"):
            client.get("/v1/check?v=0.2.0")
            client.get("/v1/check?v=0.2.0")
            client.get("/v1/check?v=0.3.0")

            db = sqlite3.connect(tmp_path / "checks.db")
            rows = db.execute(
                "SELECT version, count FROM version_checks ORDER BY version"
            ).fetchall()
            db.close()

        counts = {row[0]: row[1] for row in rows}
        assert counts.get("0.2.0", 0) >= 2
        assert counts.get("0.3.0", 0) >= 1

    def test_no_counter_on_error(self, client, tmp_path) -> None:
        with patch("app.DB_PATH", tmp_path / "checks.db"):
            client.get("/v1/check")  # missing param — 400
            db = sqlite3.connect(tmp_path / "checks.db")
            rows = db.execute("SELECT count(*) FROM version_checks").fetchone()
            db.close()
        assert rows[0] == 0
