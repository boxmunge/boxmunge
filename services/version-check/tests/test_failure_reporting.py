# services/version-check/tests/test_failure_reporting.py
import json
import sqlite3
import os
import pytest
from pathlib import Path
from unittest.mock import patch

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture
def app(tmp_path):
    releases_file = tmp_path / "releases.json"
    releases_file.write_text(json.dumps({
        "releases": [
            {"version": "0.2.1", "security": True,
             "url": "https://github.com/boxmunge/boxmunge/releases/tag/v0.2.1"},
            {"version": "0.2.0", "security": False,
             "url": "https://github.com/boxmunge/boxmunge/releases/tag/v0.2.0"},
        ]
    }))
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


class TestReportFailure:
    def test_accepts_valid_report(self, client):
        resp = client.post("/v1/report-failure", json={
            "version": "0.2.1", "installed_from": "0.2.0",
            "stage": "preflight", "timestamp": "2024-01-15T14:30:00Z"})
        assert resp.status_code == 204

    def test_rejects_missing_version(self, client):
        resp = client.post("/v1/report-failure", json={
            "installed_from": "0.2.0", "stage": "preflight", "timestamp": "2024-01-15T14:30:00Z"})
        assert resp.status_code == 400

    def test_rejects_invalid_stage(self, client):
        resp = client.post("/v1/report-failure", json={
            "version": "0.2.1", "installed_from": "0.2.0",
            "stage": "invalid_stage", "timestamp": "2024-01-15T14:30:00Z"})
        assert resp.status_code == 400

    def test_stores_failure_in_db(self, client, tmp_path):
        with patch("app.DB_PATH", tmp_path / "checks.db"):
            client.post("/v1/report-failure", json={
                "version": "0.2.1", "installed_from": "0.2.0",
                "stage": "apply", "timestamp": "2024-01-15T14:30:00Z"})
            db = sqlite3.connect(tmp_path / "checks.db")
            row = db.execute("SELECT version, stage FROM failures").fetchone()
            db.close()
        assert row == ("0.2.1", "apply")


class TestFailureQuery:
    def test_returns_failure_summary(self, client, tmp_path):
        with patch("app.DB_PATH", tmp_path / "checks.db"):
            for stage in ["preflight", "apply", "apply"]:
                client.post("/v1/report-failure", json={
                    "version": "0.2.1", "installed_from": "0.2.0",
                    "stage": stage, "timestamp": "2024-01-15T14:30:00Z"})
            resp = client.get("/v1/failures?version=0.2.1")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["version"] == "0.2.1"
        assert data["total"] == 3
        assert data["by_stage"]["apply"] == 2
        assert data["by_stage"]["preflight"] == 1

    def test_returns_empty_for_unknown_version(self, client):
        resp = client.get("/v1/failures?version=9.9.9")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["total"] == 0

    def test_requires_version_param(self, client):
        resp = client.get("/v1/failures")
        assert resp.status_code == 400


class TestCircuitBreaker:
    def test_trip_requires_auth(self, client):
        resp = client.post("/v1/circuit-breaker/trip?version=0.2.1")
        assert resp.status_code == 401

    def test_trip_with_valid_auth(self, client, app):
        app.config["CB_SECRET"] = "test-secret"
        resp = client.post("/v1/circuit-breaker/trip?version=0.2.1",
            headers={"Authorization": "Bearer test-secret"})
        assert resp.status_code == 200

    def test_tripped_version_excluded_from_check(self, client, app):
        app.config["CB_SECRET"] = "test-secret"
        client.post("/v1/circuit-breaker/trip?version=0.2.1",
            headers={"Authorization": "Bearer test-secret"})
        resp = client.get("/v1/check?v=0.2.0")
        data = resp.get_json()
        assert data["security"] is None
        assert data.get("held") is not None
        assert data["held"]["version"] == "0.2.1"

    def test_reset_re_enables_version(self, client, app):
        app.config["CB_SECRET"] = "test-secret"
        client.post("/v1/circuit-breaker/trip?version=0.2.1",
            headers={"Authorization": "Bearer test-secret"})
        client.post("/v1/circuit-breaker/reset?version=0.2.1",
            headers={"Authorization": "Bearer test-secret"})
        resp = client.get("/v1/check?v=0.2.0")
        data = resp.get_json()
        assert data["security"]["version"] == "0.2.1"
        assert data.get("held") is None

    def test_reset_requires_auth(self, client):
        resp = client.post("/v1/circuit-breaker/reset?version=0.2.1")
        assert resp.status_code == 401
