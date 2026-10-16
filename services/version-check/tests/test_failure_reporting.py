# services/version-check/tests/test_failure_reporting.py
import json
import sqlite3
import os
import sys
import pytest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture
def app(tmp_path, migrated_db):
    releases_file = tmp_path / "releases.json"
    releases_file.write_text(json.dumps({
        "releases": [
            {"version": "0.2.1", "class": "security", "breaking": False,
             "url": "https://github.com/boxmunge/boxmunge/releases/tag/v0.2.1"},
            {"version": "0.2.0", "class": "feature", "breaking": False,
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

    def test_rate_limits_per_ip(self, client, tmp_path):
        with patch("app.DB_PATH", tmp_path / "checks.db"):
            # First report should be stored
            client.post("/v1/report-failure", json={
                "version": "0.2.1", "installed_from": "0.2.0",
                "stage": "apply", "timestamp": "2024-01-15T14:30:00Z"})
            # Second report from same IP within 1 hour should be silently accepted
            client.post("/v1/report-failure", json={
                "version": "0.2.1", "installed_from": "0.2.0",
                "stage": "apply", "timestamp": "2024-01-15T14:35:00Z"})

            db = sqlite3.connect(tmp_path / "checks.db")
            count = db.execute("SELECT COUNT(*) FROM failures WHERE version = '0.2.1'").fetchone()[0]
            db.close()
        assert count == 1  # Only one stored despite two reports


class TestFailureQuery:
    def test_returns_failure_summary(self, client, tmp_path):
        with patch("app.DB_PATH", tmp_path / "checks.db"):
            for i, stage in enumerate(["preflight", "apply", "apply"]):
                client.post("/v1/report-failure", json={
                    "version": "0.2.1", "installed_from": "0.2.0",
                    "stage": stage, "timestamp": "2024-01-15T14:30:00Z"},
                    environ_base={"REMOTE_ADDR": f"10.0.0.{i + 1}"})
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
        assert data["breakfix"] is None
        assert data["held"] == [{"version": "0.2.1", "reason": "circuit_breaker"}]

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


class TestAutoTrip:
    def test_auto_trip_disabled_by_default(self, client, app, tmp_path):
        with patch("app.DB_PATH", tmp_path / "checks.db"):
            for i in range(5):
                client.post("/v1/report-failure", json={
                    "version": "0.2.1", "installed_from": "0.2.0",
                    "stage": "apply", "timestamp": "2024-01-15T14:30:00Z"},
                    environ_base={"REMOTE_ADDR": f"10.0.0.{i + 1}"})
            # Should not be tripped (auto-trip disabled)
            resp = client.get("/v1/check?v=0.2.0")
            data = resp.get_json()
        assert data["security"]["version"] == "0.2.1"
        assert data.get("held") is None

    def test_auto_trip_when_threshold_reached(self, tmp_path, migrated_db):
        releases_file = tmp_path / "threshold-releases.json"
        releases_file.write_text(json.dumps({"releases": [
            {"version": "0.2.1", "class": "security", "breaking": False,
             "url": "https://github.com/boxmunge/boxmunge/releases/tag/v0.2.1"},
        ]}))
        with patch("app.RELEASES_PATH", releases_file), \
             patch("app.DB_PATH", tmp_path / "checks.db"), \
             patch.dict(os.environ, {"CIRCUIT_BREAKER_AUTO_THRESHOLD": "3"}):
            from app import create_app
            client = create_app().test_client()
            for i in range(3):
                client.post("/v1/report-failure", json={
                    "version": "0.2.1", "installed_from": "0.2.0",
                    "stage": "apply", "timestamp": "2024-01-15T14:30:00Z"},
                    environ_base={"REMOTE_ADDR": f"10.0.0.{i + 1}"})
            resp = client.get("/v1/check?v=0.2.0")
            data = resp.get_json()
        assert data["security"] is None
        assert data["held"] == [{"version": "0.2.1", "reason": "circuit_breaker"}]

    @pytest.mark.parametrize("value", ["three", "-1", "2.5"])
    def test_invalid_threshold_stops_startup(self, tmp_path, migrated_db, value):
        releases_file = tmp_path / "threshold-releases.json"
        releases_file.write_text(json.dumps({"releases": [
            {"version": "0.2.1", "class": "security", "breaking": False,
             "url": "https://github.com/boxmunge/boxmunge/releases/tag/v0.2.1"},
        ]}))
        with patch("app.RELEASES_PATH", releases_file), \
             patch("app.DB_PATH", tmp_path / "checks.db"), \
             patch.dict(os.environ, {"CIRCUIT_BREAKER_AUTO_THRESHOLD": value}):
            from app import create_app
            with pytest.raises(ValueError, match="CIRCUIT_BREAKER_AUTO_THRESHOLD"):
                create_app()


class TestShimStages:
    def test_accepts_every_stage_the_upgrade_shim_reports(self, client):
        """scripts/boxmunge-upgrade reports these stages; a report the
        service rejects is silently lost on the box."""
        import re
        shim = Path(__file__).resolve().parents[3] / "scripts" / "boxmunge-upgrade"
        text = shim.read_text()
        # Literal stages passed straight to report_failure.
        stages = set(re.findall(r'report_failure "\$\w+" "\$\w+" "(\w+)"', text))
        # Defaults written as "${N:-stage}" inside helper functions.
        stages |= set(re.findall(r'report_failure [^\n]*"\$\{\d:-(\w+)\}"', text))
        # preflight_fail <v> <from> <reason> <message> [stage]: the optional
        # trailing bare word after the quoted message, possibly on a
        # continuation line.
        stages |= set(re.findall(
            r'preflight_fail "[^"]*" "[^"]*" "[^"]*" \\?\s*"[^"]*" (\w+)\s*$', text, re.M))
        stages |= {"apply", "health_immediate", "health_probation"}  # passed via $stage
        assert {"system_upgrade", "preflight"} <= stages, stages
        from app import VALID_STAGES
        assert stages <= VALID_STAGES, stages - VALID_STAGES
        for i, stage in enumerate(sorted(stages)):
            resp = client.post("/v1/report-failure", json={
                "version": "0.2.1", "installed_from": "0.2.0", "stage": stage},
                environ_base={"REMOTE_ADDR": f"10.1.0.{i + 1}"})
            assert resp.status_code == 204, stage


class TestCircuitBreakerBreakfix:
    @pytest.fixture
    def bf_app(self, tmp_path, migrated_db):
        releases_file = tmp_path / "releases.json"
        releases_file.write_text(json.dumps({"releases": [
            {"version": v, "class": c, "breaking": False,
             "url": f"https://github.com/boxmunge/boxmunge/releases/tag/v{v}"}
            for v, c in [("0.2.2", "breakfix"), ("0.2.1", "security"), ("0.2.0", "feature")]
        ]}))
        with patch("app.RELEASES_PATH", releases_file), \
             patch("app.DB_PATH", tmp_path / "checks.db"):
            from app import create_app
            application = create_app()
            application.config["TESTING"] = True
            application.config["CB_SECRET"] = "s"
            yield application

    def test_tripped_breakfix_is_held(self, bf_app):
        client = bf_app.test_client()
        client.post("/v1/circuit-breaker/trip?version=0.2.2",
                    headers={"Authorization": "Bearer s"})
        data = client.get("/v1/check?v=0.2.1").get_json()
        assert data["breakfix"] is None
        assert data["held"] == [{"version": "0.2.2", "reason": "circuit_breaker"}]
        assert data["status"] == "update_available"

    def test_tripped_breakfix_falls_back_to_security(self, bf_app):
        client = bf_app.test_client()
        client.post("/v1/circuit-breaker/trip?version=0.2.2",
                    headers={"Authorization": "Bearer s"})
        data = client.get("/v1/check?v=0.2.0").get_json()
        assert data["security"]["version"] == "0.2.1"
        assert data["breakfix"]["version"] == "0.2.1"
        assert data["status"] == "security_update_available"
