"""Who reaches the admin pages and endpoints: passkey sessions, Bearer, and neither."""

import os
import re
import sqlite3
from unittest.mock import patch

import pytest

import admin_auth
import webauthn_store
from conftest import ADMIN_RP_ID, ADMIN_SECRET
from softauthn import SoftAuthenticator, login, register, session_header

BEARER = {"Authorization": f"Bearer {ADMIN_SECRET}"}
LOGIN_REDIRECT = "/v1/admin/login?next=/v1/admin/stats"


@pytest.fixture
def signed_in(admin_client, authenticator) -> dict[str, str]:
    """The Cookie header of a browser that registered the passkey and signed in."""
    assert register(admin_client, authenticator, ADMIN_SECRET).status_code == 201
    return session_header(login(admin_client, authenticator))


def _cookie(value: str) -> dict[str, str]:
    return {"Cookie": f"{admin_auth.SESSION_COOKIE}={value}"}


class TestStatsPageNeedsASession:
    def test_an_unauthenticated_request_is_sent_to_sign_in(self, admin_client):
        response = admin_client.get("/v1/admin/stats?last=30")
        assert response.status_code == 303
        assert response.headers["Location"] == LOGIN_REDIRECT

    def test_bearer_does_not_open_the_page(self, admin_client):
        response = admin_client.get("/v1/admin/stats", headers=BEARER)
        assert response.status_code == 303 and b"<table" not in response.data

    def test_a_token_in_the_url_grants_nothing(self, admin_client):
        response = admin_client.get(f"/v1/admin/stats?token={ADMIN_SECRET}")
        assert response.status_code == 303
        assert response.headers["Location"] == LOGIN_REDIRECT
        assert "Set-Cookie" not in response.headers

    def test_a_token_in_the_url_is_ignored_with_a_session(self, admin_client, signed_in):
        response = admin_client.get("/v1/admin/stats?token=nope", headers=signed_in)
        assert response.status_code == 200 and "Set-Cookie" not in response.headers

    def test_the_session_opens_the_page(self, admin_client, signed_in):
        response = admin_client.get("/v1/admin/stats", headers=signed_in)
        assert response.status_code == 200
        assert response.content_type.startswith("text/html")
        assert response.headers["Cache-Control"] == "no-store"

    @pytest.mark.parametrize("value", [ADMIN_SECRET, "1.é", "", "x.y", "9999999999."])
    def test_a_forged_cookie_is_sent_to_sign_in(self, admin_client, value):
        assert admin_client.get("/v1/admin/stats", headers=_cookie(value)).status_code == 303

    def test_the_session_expires_after_eight_hours(self, admin_client, migrated_db):
        issued = 1_800_000_000
        with patch.object(admin_auth, "now_unix", return_value=issued):
            value = admin_auth.session_cookie_value(ADMIN_SECRET,
                                                    webauthn_store.session_key(migrated_db))
        assert value.startswith(f"{issued + 8 * 3600}.")
        for now, status in ((issued + 8 * 3600 - 1, 200), (issued + 8 * 3600, 303)):
            with patch.object(admin_auth, "now_unix", return_value=now):
                assert admin_client.get("/v1/admin/stats",
                                        headers=_cookie(value)).status_code == status

    def test_the_signature_covers_the_expiry(self, admin_client, migrated_db):
        expires, _, mac = admin_auth.session_cookie_value(
            ADMIN_SECRET, webauthn_store.session_key(migrated_db)).partition(".")
        extended = f"{int(expires) + 3600}.{mac}"
        assert admin_client.get("/v1/admin/stats", headers=_cookie(extended)).status_code == 303

    def test_a_cookie_forged_with_stats_secret_alone_is_refused(self, admin_client, migrated_db):
        genuine = admin_auth.session_cookie_value(ADMIN_SECRET,
                                                  webauthn_store.session_key(migrated_db))
        assert admin_client.get("/v1/admin/stats", headers=_cookie(genuine)).status_code == 200
        for guessed_key in (b"", bytes(32), os.urandom(32)):
            forged = admin_auth.session_cookie_value(ADMIN_SECRET, guessed_key)
            assert admin_client.get("/v1/admin/stats", headers=_cookie(forged)).status_code == 303

    def test_each_database_has_its_own_random_session_key(self, tmp_path, migrated_db):
        import db_schema
        other = tmp_path / "other.db"
        db_schema.migrate(other)
        assert webauthn_store.session_key(other) != webauthn_store.session_key(migrated_db)


class TestTheTwoMethodsStaySeparate:
    def test_the_session_does_not_open_the_json_endpoint(self, admin_client, signed_in):
        response = admin_client.get("/v1/admin/version-checks", headers=signed_in)
        assert response.status_code == 401

    def test_bearer_opens_the_json_endpoint(self, admin_client):
        assert admin_client.get("/v1/admin/version-checks", headers=BEARER).status_code == 200


class TestSecretGuessing:
    def test_wrong_bearer_secrets_are_limited_per_client(self, admin_client):
        guesser = {"X-Forwarded-For": "203.0.113.9"}
        for _ in range(admin_auth.GUESS_FAILURES):
            response = admin_client.get("/v1/admin/version-checks",
                                        headers={**guesser, "Authorization": "Bearer guess"})
            assert response.status_code == 401
        blocked = admin_client.get("/v1/admin/version-checks", headers={**guesser, **BEARER})
        assert blocked.status_code == 429
        other = admin_client.get("/v1/admin/version-checks",
                                 headers={"X-Forwarded-For": "198.51.100.3", **BEARER})
        assert other.status_code == 200

    def test_correct_bearer_requests_do_not_use_up_the_limit(self, admin_client):
        for _ in range(admin_auth.GUESS_FAILURES + 2):
            assert admin_client.get("/v1/admin/version-checks",
                                    headers=BEARER).status_code == 200

    def test_bearer_and_registration_code_guesses_share_one_budget(self, admin_client):
        for _ in range(admin_auth.GUESS_FAILURES):
            admin_client.get("/v1/admin/version-checks", headers={"Authorization": "Bearer x"})
        response = admin_client.post("/v1/admin/register/options", json={"code": ADMIN_SECRET})
        assert response.status_code == 429


class TestRotatingTheSecret:
    def test_rotation_reopens_registration_and_ends_sessions(
            self, admin_app, admin_client, authenticator, signed_in, migrated_db):
        assert admin_client.get("/v1/admin/register").status_code == 403
        admin_app.config["STATS_SECRET"] = "rotated-registration-code-0123456789abcdef"

        assert admin_client.get("/v1/admin/stats", headers=signed_in).status_code == 303
        assert admin_client.post("/v1/admin/login/options", json={}).status_code == 409
        assert admin_client.get("/v1/admin/register").status_code == 200
        old_code = admin_client.post("/v1/admin/register/options", json={"code": ADMIN_SECRET})
        assert old_code.status_code == 401

        replacement = SoftAuthenticator(ADMIN_RP_ID, f"https://{ADMIN_RP_ID}")
        assert register(admin_client, replacement,
                        "rotated-registration-code-0123456789abcdef").status_code == 201
        assert login(admin_client, authenticator).status_code == 401
        new_session = session_header(login(admin_client, replacement))
        assert admin_client.get("/v1/admin/stats", headers=new_session).status_code == 200
        conn = sqlite3.connect(migrated_db)
        try:
            (stored,) = conn.execute("SELECT code_mac FROM admin_credential").fetchone()
        finally:
            conn.close()
        assert "rotated-registration-code-0123456789abcdef" not in stored
        assert stored == admin_auth.code_mac("rotated-registration-code-0123456789abcdef")


class TestUnconfigured:
    @pytest.mark.parametrize("method,path", [
        ("get", "/v1/admin/stats"), ("get", "/v1/admin/register"), ("get", "/v1/admin/login"),
        ("post", "/v1/admin/register/options"), ("post", "/v1/admin/login/options"),
        ("get", "/v1/admin/version-checks"),
    ])
    def test_every_admin_route_refuses_without_stats_secret(
            self, admin_app, admin_client, method, path):
        admin_app.config["STATS_SECRET"] = ""
        response = getattr(admin_client, method)(path, json={"code": ""}, headers=BEARER)
        assert response.status_code == 503
        assert "STATS_SECRET is unset" in response.get_json()["error"]

    @pytest.mark.parametrize("method,path", [
        ("get", "/v1/admin/stats"), ("get", "/v1/admin/register"),
        ("post", "/v1/admin/register/options"), ("post", "/v1/admin/login/options"),
        ("get", "/v1/admin/version-checks"),
    ])
    def test_a_short_stats_secret_is_refused_like_a_missing_one(
            self, admin_app, admin_client, method, path):
        short = "x" * 31
        admin_app.config["STATS_SECRET"] = short
        response = getattr(admin_client, method)(path, json={"code": short},
                                                 headers={"Authorization": f"Bearer {short}"})
        assert response.status_code == 503
        error = response.get_json()["error"]
        assert "STATS_SECRET is shorter than 32 characters" in error
        assert "openssl rand -hex 32" in error

    def test_a_32_character_secret_is_enough(self, admin_app, admin_client):
        admin_app.config["STATS_SECRET"] = "x" * 32
        response = admin_client.get("/v1/admin/version-checks",
                                    headers={"Authorization": "Bearer " + "x" * 32})
        assert response.status_code == 200

    def test_an_invalid_rp_id_stops_the_service(self, tmp_path, migrated_db, monkeypatch):
        monkeypatch.setenv("ADMIN_RP_ID", "https://example.com/")
        with patch("app.DB_PATH", migrated_db):
            from app import create_app
            with pytest.raises(ValueError, match="ADMIN_RP_ID"):
                create_app()


class TestPages:
    @pytest.mark.parametrize("path", ["/v1/admin/register", "/v1/admin/login",
                                      "/v1/admin/stats"])
    def test_pages_allow_only_same_origin_script_and_style(self, admin_client, signed_in, path):
        # signed_in has registered, so /register shows its closed page.
        response = admin_client.get(path, headers=signed_in)
        csp = response.headers["Content-Security-Policy"]
        assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
        assert "script-src 'self'" in csp and "style-src 'self'" in csp
        assert "frame-ancestors 'none'" in csp and "base-uri 'none'" in csp
        html = response.get_data(as_text=True)
        assert "<style" not in html and " style=" not in html
        assert re.findall(r"<script(?![^>]*\bsrc=)", html) == []

    def test_open_registration_page_has_a_form_field_and_the_script(self, admin_client):
        html = admin_client.get("/v1/admin/register").get_data(as_text=True)
        assert 'type="password" name="code"' in html and 'method="post"' in html
        assert '<script src="/static/admin-passkey.js" defer></script>' in html
        assert "unsafe-inline" not in admin_client.get(
            "/v1/admin/register").headers["Content-Security-Policy"]

    def test_the_script_and_stylesheet_are_served_from_this_origin(self, admin_client):
        script = admin_client.get("/static/admin-passkey.js")
        assert script.status_code == 200 and "javascript" in script.content_type
        assert b"navigator.credentials" in script.data
        assert admin_client.get("/static/admin.css").status_code == 200

    def test_sign_in_page_before_registration_points_to_register(self, admin_client):
        html = admin_client.get("/v1/admin/login").get_data(as_text=True)
        assert "/v1/admin/register" in html and 'id="signin"' not in html

    def test_sign_in_page_carries_the_requested_admin_page(self, admin_client, signed_in):
        html = admin_client.get("/v1/admin/login?next=/v1/admin/stats").get_data(as_text=True)
        assert 'data-next="/v1/admin/stats"' in html and 'id="signin"' in html

    @pytest.mark.parametrize("target", ["https://example.net/", "//example.net/v1/admin/x",
                                        "/v1/admin/../x", "/v1/adminx", "javascript:x",
                                        "/v1/admin/stats?token=x"])
    def test_sign_in_refuses_a_next_outside_the_admin_pages(self, admin_client, target):
        response = admin_client.get("/v1/admin/login", query_string={"next": target})
        assert response.status_code == 400


class TestMigration:
    def test_admin_tables_are_added_to_an_existing_database(self, tmp_path):
        import db_schema
        path = tmp_path / "old.db"
        db_schema.migrate(path)
        conn = sqlite3.connect(path)
        conn.execute("DROP TABLE admin_credential")
        conn.execute("DROP TABLE admin_challenges")
        conn.execute("DROP TABLE admin_session_key")
        conn.execute("PRAGMA user_version = 3")
        conn.commit()
        conn.close()
        db_schema.migrate(path)
        conn = sqlite3.connect(path)
        try:
            tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
            assert {"admin_credential", "admin_challenges", "admin_session_key"} <= tables
            assert conn.execute("PRAGMA user_version").fetchone()[0] == db_schema.SCHEMA_VERSION
        finally:
            conn.close()
