"""Abuse-limit behaviour of the version-check service (audit F-12)."""

import json
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

PROXY = {"REMOTE_ADDR": "172.18.0.2"}  # Caddy's address on the project network


def _report(version="0.2.1", stage="apply"):
    return {"version": version, "installed_from": "0.2.0", "stage": stage,
            "timestamp": "2026-10-13T00:00:00Z"}


@pytest.fixture
def make_app(tmp_path):
    releases_file = tmp_path / "releases.json"
    releases_file.write_text(json.dumps({"releases": [
        {"version": "0.2.1", "class": "security", "breaking": False,
         "url": "https://github.com/boxmunge/boxmunge/releases/tag/v0.2.1"},
    ]}))
    patches = [patch("app.RELEASES_PATH", releases_file),
               patch("app.DB_PATH", tmp_path / "checks.db")]

    def build(**overrides):
        for name, value in overrides.items():
            patches.append(patch(f"app.{name}", value))
        for p in patches:
            p.start()
        from app import create_app
        application = create_app()
        application.config["TESTING"] = True
        return application

    yield build
    for p in patches:
        p.stop()


def _failure_addrs(db_path):
    conn = sqlite3.connect(db_path)
    try:
        return [r[0] for r in conn.execute("SELECT remote_addr FROM failures ORDER BY id")]
    finally:
        conn.close()


class TestForwardedClientAddress:
    def test_failure_report_records_forwarded_client(self, make_app, tmp_path):
        client = make_app().test_client()
        client.post("/v1/report-failure", json=_report(), environ_base=PROXY,
                    headers={"X-Forwarded-For": "198.51.100.9"})
        assert _failure_addrs(tmp_path / "checks.db") == ["198.51.100.9"]

    def test_dedupe_is_per_client_not_per_proxy(self, make_app, tmp_path):
        """Behind the proxy every request used to share one address, so one
        report per version per hour was accepted fleet-wide."""
        client = make_app().test_client()
        for addr in ("198.51.100.1", "198.51.100.2", "198.51.100.2"):
            client.post("/v1/report-failure", json=_report(), environ_base=PROXY,
                        headers={"X-Forwarded-For": addr})
        assert _failure_addrs(tmp_path / "checks.db") == ["198.51.100.1", "198.51.100.2"]

    def test_only_the_proxy_hop_is_trusted(self, make_app, tmp_path):
        """A client-supplied X-Forwarded-For prefix is ignored: only the
        entry appended by the trusted proxy counts."""
        client = make_app().test_client()
        client.post("/v1/report-failure", json=_report(), environ_base=PROXY,
                    headers={"X-Forwarded-For": "10.9.9.9, 198.51.100.9"})
        assert _failure_addrs(tmp_path / "checks.db") == ["198.51.100.9"]


class TestRateLimit:
    def test_per_client_limit(self, make_app):
        client = make_app(RATE_LIMIT_REQUESTS=3).test_client()
        codes = [client.get("/v1/check?v=0.2.0", environ_base=PROXY,
                            headers={"X-Forwarded-For": "198.51.100.1"}).status_code
                 for _ in range(4)]
        assert codes == [200, 200, 200, 429]
        other = client.get("/v1/check?v=0.2.0", environ_base=PROXY,
                           headers={"X-Forwarded-For": "198.51.100.2"})
        assert other.status_code == 200

    def test_limited_response_is_explicit(self, make_app):
        client = make_app(RATE_LIMIT_REQUESTS=1).test_client()
        client.get("/v1/check?v=0.2.0")
        resp = client.get("/v1/check?v=0.2.0")
        assert resp.status_code == 429
        assert resp.get_json() == {"error": "rate limited"}
        assert resp.headers["Retry-After"] == "60"

    def test_limit_covers_failure_reports(self, make_app, tmp_path):
        client = make_app(RATE_LIMIT_REQUESTS=1).test_client()
        client.post("/v1/report-failure", json=_report("0.2.1"))
        resp = client.post("/v1/report-failure", json=_report("0.2.2"))
        assert resp.status_code == 429
        assert len(_failure_addrs(tmp_path / "checks.db")) == 1


class TestBodyLimits:
    def test_oversized_body_rejected(self, make_app, tmp_path):
        client = make_app().test_client()
        body = _report()
        body["installed_from"] = "x" * 10_000
        resp = client.post("/v1/report-failure", json=body)
        assert resp.status_code == 413
        assert _failure_addrs(tmp_path / "checks.db") == []

    def test_non_object_body_rejected(self, make_app):
        client = make_app().test_client()
        assert client.post("/v1/report-failure", json=["x"]).status_code == 400

    @pytest.mark.parametrize("field,value", [
        ("version", "0.2.1; drop"), ("version", 5), ("installed_from", "y" * 65),
        ("installed_from", 3),
    ])
    def test_malformed_fields_rejected(self, make_app, tmp_path, field, value):
        client = make_app().test_client()
        body = _report()
        body[field] = value
        assert client.post("/v1/report-failure", json=body).status_code == 400
        assert _failure_addrs(tmp_path / "checks.db") == []


class TestAddressRetention:
    def test_addresses_older_than_dedupe_window_are_forgotten(self, make_app, tmp_path):
        client = make_app().test_client()
        db_path = tmp_path / "checks.db"
        old = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        conn = sqlite3.connect(db_path)
        conn.execute("INSERT INTO failures (version, installed_from, stage, reported_at, "
                     "remote_addr) VALUES ('0.2.1', '0.2.0', 'apply', ?, '198.51.100.7')", (old,))
        conn.commit()
        conn.close()
        client.post("/v1/report-failure", json=_report(), environ_base=PROXY,
                    headers={"X-Forwarded-For": "198.51.100.8"})
        assert _failure_addrs(db_path) == [None, "198.51.100.8"]


class TestStatsSeeBufferedCounts:
    def test_admin_stats_flush_pending_counts(self, make_app):
        app = make_app()
        app.config["STATS_SECRET"] = "s"
        client = app.test_client()
        client.get("/v1/check?v=0.2.1")
        data = client.get("/v1/admin/version-checks?token=s").get_json()
        assert data["totals"] == [{"version": "0.2.1", "count": 1}]
