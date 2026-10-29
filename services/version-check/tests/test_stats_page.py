"""The /v1/admin/stats page, and failure reports carrying a reason."""

import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

SECRET = "page-secret"
BEARER = {"Authorization": f"Bearer {SECRET}"}


@pytest.fixture
def db_path(tmp_path, migrated_db):
    return tmp_path / "checks.db"


@pytest.fixture
def app(tmp_path, db_path):
    releases_file = tmp_path / "releases.json"
    releases_file.write_text(json.dumps({"releases": [
        {"version": "0.4.2", "class": "feature", "breaking": False,
         "url": "https://github.com/boxmunge/boxmunge/releases/tag/v0.4.2"},
    ]}))
    with patch("app.RELEASES_PATH", releases_file), patch("app.DB_PATH", db_path):
        from app import create_app
        application = create_app()
        application.config["TESTING"] = True
        application.config["STATS_SECRET"] = SECRET
        yield application


@pytest.fixture
def client(app):
    return app.test_client()


def _report(client, **overrides):
    body = {"version": "0.4.2", "installed_from": "0.4.1", "stage": "system_upgrade"}
    body.update(overrides)
    return client.post("/v1/report-failure", json=body)


def _rows(db_path):
    conn = sqlite3.connect(db_path)
    try:
        return conn.execute("SELECT installed_from, stage, detail FROM failures").fetchall()
    finally:
        conn.close()


class TestFailureDetail:
    def test_detail_is_stored(self, client, db_path):
        resp = _report(client, detail="system_upgrade_failed: install_sh_exit_100")
        assert resp.status_code == 204
        assert _rows(db_path) == [("0.4.1", "system_upgrade",
                                   "system_upgrade_failed: install_sh_exit_100")]

    def test_detail_is_optional(self, client, db_path):
        assert _report(client).status_code == 204
        assert _rows(db_path) == [("0.4.1", "system_upgrade", None)]

    @pytest.mark.parametrize("detail", ["x" * 201, "café", "tab\there", "a\nb", 5, ["a"]])
    def test_bad_detail_is_rejected(self, client, db_path, detail):
        assert _report(client, detail=detail).status_code == 400
        assert _rows(db_path) == []

    def test_detail_at_the_cap_is_accepted(self, client, db_path):
        assert _report(client, detail="x" * 200).status_code == 204

    @pytest.mark.parametrize("sent", ["boxmunge 0.10.1", "boxmunge  0.10.1", "0.10.1"])
    def test_legacy_from_version_is_normalised(self, client, db_path, sent):
        assert _report(client, installed_from=sent).status_code == 204
        assert _rows(db_path)[0][0] == "0.10.1"


class TestStatsPageAuth:
    def test_no_credentials_is_401(self, client):
        assert client.get("/v1/admin/stats").status_code == 401

    def test_unconfigured_secret_is_401_for_everyone(self, app, client):
        app.config["STATS_SECRET"] = ""
        assert client.get("/v1/admin/stats", headers=BEARER).status_code == 401
        assert client.get("/v1/admin/stats?token=").status_code == 401

    def test_bearer_works_and_returns_html(self, client):
        resp = client.get("/v1/admin/stats", headers=BEARER)
        assert resp.status_code == 200
        assert resp.content_type.startswith("text/html")
        assert resp.headers["Cache-Control"] == "no-store"
        assert "script-src" not in resp.headers["Content-Security-Policy"]

    def test_wrong_bearer_is_401(self, client):
        assert client.get("/v1/admin/stats",
                          headers={"Authorization": "Bearer nope"}).status_code == 401

    def test_token_in_query_never_authorizes_the_page(self, client):
        # ?token= only trades the secret for a cookie and redirects; no page body.
        resp = client.get("/v1/admin/stats?token=" + SECRET)
        assert resp.status_code == 303
        assert resp.headers["Location"] == "/v1/admin/stats?last=7"
        assert SECRET not in resp.headers["Location"]
        assert b"<table" not in resp.data

    def test_wrong_token_is_401_and_sets_no_cookie(self, client):
        resp = client.get("/v1/admin/stats?token=nope")
        assert resp.status_code == 401 and "Set-Cookie" not in resp.headers

    def test_cookie_from_token_login_authorizes_the_page(self, client):
        resp = client.get("/v1/admin/stats?token=" + SECRET)
        cookie = resp.headers["Set-Cookie"]
        assert "HttpOnly" in cookie and "Secure" in cookie and "SameSite=Strict" in cookie
        assert "Path=/v1/admin" in cookie
        assert SECRET not in cookie  # derived value, never the secret itself
        value = cookie.split(";")[0]
        page = client.get("/v1/admin/stats", headers={"Cookie": value})
        assert page.status_code == 200

    def test_forged_cookie_is_401(self, client):
        assert client.get("/v1/admin/stats",
                          headers={"Cookie": "bm_stats=" + SECRET}).status_code == 401

    def test_cookie_does_not_open_the_json_endpoint(self, client):
        value = client.get("/v1/admin/stats?token=" + SECRET).headers["Set-Cookie"].split(";")[0]
        assert client.get("/v1/admin/version-checks",
                          headers={"Cookie": value}).status_code == 401


class TestStatsPageContent:
    def test_shows_daily_checks_per_version_including_unlisted_ones(self, client):
        for v in ("0.4.2", "0.4.2", "9.9.9-not", "0.0.9", "0.0.9", "0.0.9"):
            client.get("/v1/check", query_string={"v": v})
        html = client.get("/v1/admin/stats", headers=BEARER).get_data(as_text=True)
        today = datetime.now(timezone.utc).date().isoformat()
        assert today in html
        assert "<th>0.4.2</th>" in html
        assert "<th>0.0.9 (unlisted)</th>" in html
        assert "9.9.9-not" not in html
        assert "not unique boxes" in html

    def test_lists_failure_reports_with_their_reason(self, client):
        _report(client, installed_from="boxmunge 0.10.1",
                detail="system_upgrade_failed: install_sh_exit_100")
        html = client.get("/v1/admin/stats", headers=BEARER).get_data(as_text=True)
        assert "system_upgrade_failed: install_sh_exit_100" in html
        assert "<td class=\"l\">0.10.1</td>" in html
        assert "boxmunge 0.10.1" not in html

    def test_stored_text_is_escaped(self, client, db_path):
        conn = sqlite3.connect(db_path)
        conn.execute("INSERT INTO failures (version, installed_from, stage, detail, reported_at)"
                     " VALUES ('0.4.2', '<script>x</script>', 's', '<b>d</b>', '2026-01-01')")
        conn.commit()
        conn.close()
        html = client.get("/v1/admin/stats", headers=BEARER).get_data(as_text=True)
        assert "<script>" not in html and "<b>d</b>" not in html
        assert "&lt;script&gt;" in html

    def test_empty_state_and_last_parameter(self, client):
        html = client.get("/v1/admin/stats?last=3", headers=BEARER).get_data(as_text=True)
        assert "No checks recorded" in html and "No failure reports" in html

    def test_json_endpoint_marks_unlisted_versions(self, client):
        client.get("/v1/check?v=0.0.9")
        client.get("/v1/check?v=0.4.2")
        totals = client.get("/v1/admin/version-checks", headers=BEARER).get_json()["totals"]
        assert {t["version"]: t["listed"] for t in totals} == {"0.0.9": False, "0.4.2": True}


class TestMigration:
    def test_detail_column_exists_after_migrating_an_old_database(self, tmp_path):
        import db_schema
        path = tmp_path / "old.db"
        db_schema.migrate(path)
        conn = sqlite3.connect(path)
        conn.execute("ALTER TABLE failures DROP COLUMN detail")
        conn.execute("PRAGMA user_version = 2")
        conn.commit()
        conn.close()
        db_schema.migrate(path)
        conn = sqlite3.connect(path)
        assert "detail" in [r[1] for r in conn.execute("PRAGMA table_info(failures)")]
        conn.close()
