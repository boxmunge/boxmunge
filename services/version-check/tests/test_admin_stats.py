"""Tests for the admin stats endpoint (GET /v1/admin/version-checks).

The endpoint exposes the version_checks table aggregated by date so a
weekly bot can answer "is anyone using boxmunge?" Auth is required —
the data is intentionally NOT public.
"""

import json
import sqlite3
import sys
from datetime import date, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture
def app(tmp_path):
    releases_file = tmp_path / "releases.json"
    releases_file.write_text(json.dumps({
        "releases": [
            {"version": "0.4.2", "security": False,
             "url": "https://github.com/boxmunge/boxmunge/releases/tag/v0.4.2"},
            {"version": "0.4.1", "security": True,
             "url": "https://github.com/boxmunge/boxmunge/releases/tag/v0.4.1"},
        ]
    }))
    db_path = tmp_path / "checks.db"
    with patch("app.RELEASES_PATH", releases_file), \
         patch("app.DB_PATH", db_path):
        from app import create_app
        application = create_app()
        application.config["TESTING"] = True
        application.config["DB_PATH"] = db_path  # tests reach in directly
        yield application


@pytest.fixture
def client(app):
    return app.test_client()


def _seed_checks(db_path: Path, rows: list[tuple[str, str, int]]) -> None:
    """Seed the version_checks table directly. rows = [(date, version, count), ...]"""
    conn = sqlite3.connect(db_path)
    try:
        for d, v, c in rows:
            conn.execute(
                "INSERT INTO version_checks (date, version, count) VALUES (?, ?, ?)",
                (d, v, c),
            )
        conn.commit()
    finally:
        conn.close()


def _today() -> str:
    return date.today().isoformat()


def _days_ago(n: int) -> str:
    return (date.today() - timedelta(days=n)).isoformat()


class TestStatsEndpointAuth:
    def test_no_auth_returns_401(self, client):
        resp = client.get("/v1/admin/version-checks")
        assert resp.status_code == 401

    def test_bearer_token_accepted(self, client, app):
        app.config["STATS_SECRET"] = "test-stats-secret"
        resp = client.get(
            "/v1/admin/version-checks",
            headers={"Authorization": "Bearer test-stats-secret"},
        )
        assert resp.status_code == 200

    def test_url_token_accepted(self, client, app):
        """User asked for url-or-bearer support; URL token is the convenience path
        for simple weekly bots."""
        app.config["STATS_SECRET"] = "test-stats-secret"
        resp = client.get(
            "/v1/admin/version-checks?token=test-stats-secret",
        )
        assert resp.status_code == 200

    def test_wrong_bearer_returns_401(self, client, app):
        app.config["STATS_SECRET"] = "test-stats-secret"
        resp = client.get(
            "/v1/admin/version-checks",
            headers={"Authorization": "Bearer wrong"},
        )
        assert resp.status_code == 401

    def test_wrong_url_token_returns_401(self, client, app):
        app.config["STATS_SECRET"] = "test-stats-secret"
        resp = client.get("/v1/admin/version-checks?token=wrong")
        assert resp.status_code == 401

    def test_uses_separate_secret_from_circuit_breaker(self, client, app):
        """Stats and circuit-breaker have different blast radius; secrets MUST
        be independent so a stats-token leak doesn't enable releaseside-suppression."""
        app.config["CB_SECRET"] = "cb-secret"
        # No STATS_SECRET set; CB_SECRET should NOT grant stats access
        resp = client.get(
            "/v1/admin/version-checks",
            headers={"Authorization": "Bearer cb-secret"},
        )
        assert resp.status_code == 401

    def test_no_stats_secret_configured_returns_401(self, client):
        """If the operator hasn't set STATS_SECRET at all, the endpoint
        is effectively disabled — fail closed."""
        resp = client.get(
            "/v1/admin/version-checks",
            headers={"Authorization": "Bearer anything"},
        )
        assert resp.status_code == 401


class TestStatsEndpointShape:
    def test_returns_empty_when_no_data(self, client, app):
        app.config["STATS_SECRET"] = "s"
        resp = client.get("/v1/admin/version-checks?token=s")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["totals"] == []
        assert data["by_date"] == []
        assert "since" in data
        assert "until" in data
        assert data["days"] == 7  # default

    def test_default_window_is_7_days(self, client, app):
        app.config["STATS_SECRET"] = "s"
        db_path = app.config["DB_PATH"]
        _seed_checks(db_path, [
            (_today(), "0.4.2", 5),
            (_days_ago(3), "0.4.1", 12),
            (_days_ago(10), "0.3.0", 99),  # outside default window
        ])
        resp = client.get("/v1/admin/version-checks?token=s")
        assert resp.status_code == 200
        data = resp.get_json()
        # 0.3.0 (10d ago) excluded; 0.4.2 + 0.4.1 included
        versions = {row["version"] for row in data["totals"]}
        assert "0.3.0" not in versions
        assert "0.4.2" in versions
        assert "0.4.1" in versions

    def test_custom_window_via_last_param(self, client, app):
        app.config["STATS_SECRET"] = "s"
        db_path = app.config["DB_PATH"]
        _seed_checks(db_path, [
            (_days_ago(5), "0.4.1", 10),
            (_days_ago(20), "0.3.0", 5),
        ])
        # last=30 should pull in the older entry
        resp = client.get("/v1/admin/version-checks?token=s&last=30")
        data = resp.get_json()
        versions = {row["version"] for row in data["totals"]}
        assert "0.3.0" in versions
        assert data["days"] == 30

    def test_last_param_capped_at_90_days(self, client, app):
        """Cap prevents pathological queries against an unbounded table."""
        app.config["STATS_SECRET"] = "s"
        resp = client.get("/v1/admin/version-checks?token=s&last=9999")
        data = resp.get_json()
        assert data["days"] == 90

    def test_invalid_last_param_falls_back_to_default(self, client, app):
        app.config["STATS_SECRET"] = "s"
        resp = client.get("/v1/admin/version-checks?token=s&last=banana")
        data = resp.get_json()
        assert data["days"] == 7

    def test_totals_aggregate_across_dates(self, client, app):
        app.config["STATS_SECRET"] = "s"
        db_path = app.config["DB_PATH"]
        _seed_checks(db_path, [
            (_today(), "0.4.1", 10),
            (_days_ago(1), "0.4.1", 12),
            (_days_ago(2), "0.4.1", 8),
            (_today(), "0.4.2", 3),
        ])
        resp = client.get("/v1/admin/version-checks?token=s")
        data = resp.get_json()
        totals = {row["version"]: row["count"] for row in data["totals"]}
        assert totals["0.4.1"] == 30
        assert totals["0.4.2"] == 3

    def test_totals_sorted_by_count_desc(self, client, app):
        """Most-active versions first — that's what a weekly report wants on top."""
        app.config["STATS_SECRET"] = "s"
        db_path = app.config["DB_PATH"]
        _seed_checks(db_path, [
            (_today(), "0.4.1", 5),
            (_today(), "0.4.2", 50),
            (_today(), "0.3.0", 1),
        ])
        resp = client.get("/v1/admin/version-checks?token=s")
        data = resp.get_json()
        counts = [row["count"] for row in data["totals"]]
        assert counts == sorted(counts, reverse=True)

    def test_by_date_includes_raw_rows(self, client, app):
        app.config["STATS_SECRET"] = "s"
        db_path = app.config["DB_PATH"]
        _seed_checks(db_path, [
            (_today(), "0.4.2", 3),
            (_today(), "0.4.1", 12),
        ])
        resp = client.get("/v1/admin/version-checks?token=s")
        data = resp.get_json()
        # Each row has date, version, count
        for row in data["by_date"]:
            assert {"date", "version", "count"} <= row.keys()
        rows = [(r["date"], r["version"], r["count"]) for r in data["by_date"]]
        assert (_today(), "0.4.2", 3) in rows
        assert (_today(), "0.4.1", 12) in rows
