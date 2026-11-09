"""Passkey registration and sign-in for the admin pages, against a software authenticator."""

import sqlite3
from unittest.mock import patch

import pytest

import admin_auth
import webauthn_store
from conftest import ADMIN_RP_ID, ADMIN_SECRET
from softauthn import SoftAuthenticator, b64url, login, register, session_header

ORIGIN = f"https://{ADMIN_RP_ID}"


def _challenges(db_path) -> list[tuple[str]]:
    conn = sqlite3.connect(db_path)
    try:
        return conn.execute("SELECT purpose FROM admin_challenges").fetchall()
    finally:
        conn.close()


def _sign_count(db_path) -> int:
    conn = sqlite3.connect(db_path)
    try:
        return conn.execute("SELECT sign_count FROM admin_credential").fetchone()[0]
    finally:
        conn.close()


def _credential_rows(db_path) -> int:
    conn = sqlite3.connect(db_path)
    try:
        return conn.execute("SELECT COUNT(*) FROM admin_credential").fetchone()[0]
    finally:
        conn.close()


class TestRegisterThenLogin:
    def test_register_then_login_opens_the_stats_page(self, admin_client, authenticator):
        assert register(admin_client, authenticator, ADMIN_SECRET).status_code == 201
        signed_in = login(admin_client, authenticator)
        assert signed_in.status_code == 200
        cookie = signed_in.headers["Set-Cookie"]
        for attribute in ("HttpOnly", "Secure", "SameSite=Strict", "Path=/v1/admin",
                          "Max-Age=28800"):
            assert attribute in cookie
        assert ADMIN_SECRET not in cookie
        page = admin_client.get("/v1/admin/stats", headers=session_header(signed_in))
        assert page.status_code == 200 and b"Checks per version" in page.data

    def test_registration_options_ask_for_es256_or_eddsa_with_user_verification(
            self, admin_client, migrated_db):
        options = admin_client.post("/v1/admin/register/options",
                                    json={"code": ADMIN_SECRET}).get_json()
        assert [p["alg"] for p in options["pubKeyCredParams"]] == [-7, -8]
        assert options["authenticatorSelection"]["userVerification"] == "required"
        assert options["attestation"] == "none"
        assert options["rp"]["id"] == ADMIN_RP_ID
        assert _challenges(migrated_db) == [("register",)]

    def test_login_options_name_the_one_credential_and_require_verification(
            self, admin_client, authenticator):
        register(admin_client, authenticator, ADMIN_SECRET)
        options = admin_client.post("/v1/admin/login/options", json={}).get_json()
        assert options["userVerification"] == "required"
        assert [c["id"] for c in options["allowCredentials"]] == [
            b64url(authenticator.credential_id)]

    def test_a_key_type_other_than_es256_or_eddsa_is_refused(self, admin_client, migrated_db):
        p384 = SoftAuthenticator(ADMIN_RP_ID, ORIGIN, alg=-35)
        response = register(admin_client, p384, ADMIN_SECRET)
        assert response.status_code == 400
        assert "Unsupported credential public key alg" in response.get_json()["error"]
        assert _credential_rows(migrated_db) == 0

    def test_registration_without_user_verification_is_refused(
            self, admin_client, authenticator, migrated_db):
        response = register(admin_client, authenticator, ADMIN_SECRET, uv=False)
        assert response.status_code == 400
        assert "User verification is required" in response.get_json()["error"]
        assert _credential_rows(migrated_db) == 0


class TestRegistrationIsGuarded:
    def test_registration_is_closed_after_the_first_passkey(self, admin_client, authenticator, migrated_db):
        assert register(admin_client, authenticator, ADMIN_SECRET).status_code == 201
        page = admin_client.get("/v1/admin/register")
        assert page.status_code == 403 and b"already registered" in page.data
        refused = admin_client.post("/v1/admin/register/options", json={"code": ADMIN_SECRET})
        assert refused.status_code == 403
        assert "registration is closed" in refused.get_json()["error"]
        assert _challenges(migrated_db) == []

    def test_a_second_completion_is_refused_even_with_a_challenge_issued_while_open(
            self, admin_client, authenticator, migrated_db):
        early = admin_client.post("/v1/admin/register/options",
                                  json={"code": ADMIN_SECRET}).get_json()
        assert register(admin_client, authenticator, ADMIN_SECRET).status_code == 201
        other = SoftAuthenticator(ADMIN_RP_ID, ORIGIN)
        late = admin_client.post("/v1/admin/register/verify", json={
            "code": ADMIN_SECRET, "credential": other.create(early)})
        assert late.status_code == 403
        assert _credential_rows(migrated_db) == 1

    @pytest.mark.parametrize("body", [{"code": "wrong"}, {"code": ""}, {}, {"code": 5},
                                      {"code": "é"}])
    def test_a_wrong_code_is_refused_and_issues_no_challenge(self, admin_client, body, migrated_db):
        response = admin_client.post("/v1/admin/register/options", json=body)
        assert response.status_code == 401
        assert response.get_json()["error"] == "wrong registration code"
        assert _challenges(migrated_db) == []

    def test_the_code_is_checked_again_when_registration_completes(
            self, admin_client, authenticator, migrated_db):
        options = admin_client.post("/v1/admin/register/options",
                                    json={"code": ADMIN_SECRET}).get_json()
        response = admin_client.post("/v1/admin/register/verify", json={
            "code": "wrong", "credential": authenticator.create(options)})
        assert response.status_code == 401
        assert _credential_rows(migrated_db) == 0

    def test_the_code_is_never_read_from_the_url(self, admin_client):
        response = admin_client.post(f"/v1/admin/register/options?code={ADMIN_SECRET}",
                                     json={})
        assert response.status_code == 401

    def test_code_guesses_are_rate_limited(self, admin_client, migrated_db):
        for _ in range(admin_auth.GUESS_FAILURES):
            assert admin_client.post("/v1/admin/register/options",
                                     json={"code": "guess"}).status_code == 401
        response = admin_client.post("/v1/admin/register/options", json={"code": ADMIN_SECRET})
        assert response.status_code == 429
        assert _challenges(migrated_db) == []


class TestChallenges:
    def test_an_expired_challenge_is_refused(self, admin_client, authenticator, migrated_db):
        issued = 1_800_000_000
        with patch.object(admin_auth, "now_unix", return_value=issued):
            options = admin_client.post("/v1/admin/register/options",
                                        json={"code": ADMIN_SECRET}).get_json()
        with patch.object(admin_auth, "now_unix", return_value=issued + 5 * 60):
            response = admin_client.post("/v1/admin/register/verify", json={
                "code": ADMIN_SECRET, "credential": authenticator.create(options)})
        assert response.status_code == 400
        assert "expired or already used" in response.get_json()["error"]
        assert _credential_rows(migrated_db) == 0

    def test_a_challenge_just_inside_five_minutes_is_accepted(self, admin_client, authenticator):
        issued = 1_800_000_000
        with patch.object(admin_auth, "now_unix", return_value=issued):
            options = admin_client.post("/v1/admin/register/options",
                                        json={"code": ADMIN_SECRET}).get_json()
        with patch.object(admin_auth, "now_unix", return_value=issued + 5 * 60 - 1):
            response = admin_client.post("/v1/admin/register/verify", json={
                "code": ADMIN_SECRET, "credential": authenticator.create(options)})
        assert response.status_code == 201

    def test_a_reused_challenge_is_refused(self, admin_client, authenticator):
        register(admin_client, authenticator, ADMIN_SECRET)
        options = admin_client.post("/v1/admin/login/options", json={}).get_json()
        first = admin_client.post("/v1/admin/login/verify",
                                  json={"credential": authenticator.get(options)})
        assert first.status_code == 200
        replay = admin_client.post("/v1/admin/login/verify",
                                   json={"credential": authenticator.get(options)})
        assert replay.status_code == 400
        assert "expired or already used" in replay.get_json()["error"]
        assert "Set-Cookie" not in replay.headers

    def test_a_login_challenge_cannot_complete_a_registration(self, admin_client, authenticator):
        register(admin_client, authenticator, ADMIN_SECRET)
        options = admin_client.post("/v1/admin/login/options", json={}).get_json()
        admin_client.application.config["STATS_SECRET"] = "rotated-registration-code-0123456789abcdef"
        response = admin_client.post("/v1/admin/register/verify", json={
            "code": "rotated-registration-code-0123456789abcdef",
            "credential": SoftAuthenticator(ADMIN_RP_ID, ORIGIN).create(options)})
        assert response.status_code == 400
        assert "expired or already used" in response.get_json()["error"]

    def test_one_client_flooding_sign_in_cannot_block_another(
            self, admin_client, authenticator):
        register(admin_client, authenticator, ADMIN_SECRET)
        flooder = {"X-Forwarded-For": "203.0.113.7"}
        for _ in range(webauthn_store.MAX_PENDING_PER_CLIENT):
            assert admin_client.post("/v1/admin/login/options",
                                     headers=flooder).status_code == 200
        refused = admin_client.post("/v1/admin/login/options", headers=flooder)
        assert refused.status_code == 429 and "this client" in refused.get_json()["error"]
        admin = {"X-Forwarded-For": "198.51.100.20"}
        assert login_from(admin_client, authenticator, admin).status_code == 200

    def test_registration_challenges_count_towards_the_client_cap(self, admin_client):
        for _ in range(webauthn_store.MAX_PENDING_PER_CLIENT):
            assert admin_client.post("/v1/admin/register/options",
                                     json={"code": ADMIN_SECRET}).status_code == 200
        assert admin_client.post("/v1/admin/register/options",
                                 json={"code": ADMIN_SECRET}).status_code == 429

    def test_a_global_backstop_bounds_the_table(self, admin_client, authenticator):
        register(admin_client, authenticator, ADMIN_SECRET)
        with patch("webauthn_store.MAX_PENDING_CHALLENGES", 2):
            for n, status in ((1, 200), (2, 200), (3, 429)):
                response = admin_client.post("/v1/admin/login/options",
                                             headers={"X-Forwarded-For": f"192.0.2.{n}"})
                assert response.status_code == status


def login_from(client, authenticator, headers):
    options = client.post("/v1/admin/login/options", json={}, headers=headers)
    assert options.status_code == 200, options.get_json()
    return client.post("/v1/admin/login/verify", headers=headers,
                       json={"credential": authenticator.get(options.get_json())})


class TestAssertionChecks:
    @pytest.mark.parametrize("ceremony", ["register", "login"])
    def test_a_wrong_origin_is_refused(self, admin_client, authenticator, ceremony, migrated_db):
        evil = {"origin": "https://admin.example.net"}
        if ceremony == "register":
            response = register(admin_client, authenticator, ADMIN_SECRET, **evil)
            assert response.status_code == 400
            assert _credential_rows(migrated_db) == 0
        else:
            register(admin_client, authenticator, ADMIN_SECRET)
            response = login(admin_client, authenticator, **evil)
            assert response.status_code == 401 and "Set-Cookie" not in response.headers
        assert "Unexpected client data origin" in response.get_json()["error"]

    @pytest.mark.parametrize("ceremony", ["register", "login"])
    def test_a_wrong_rp_id_hash_is_refused(self, admin_client, authenticator, ceremony, migrated_db):
        evil = {"rp_id": "example.net"}
        if ceremony == "register":
            response = register(admin_client, authenticator, ADMIN_SECRET, **evil)
            assert response.status_code == 400
            assert _credential_rows(migrated_db) == 0
        else:
            register(admin_client, authenticator, ADMIN_SECRET)
            response = login(admin_client, authenticator, **evil)
            assert response.status_code == 401 and "Set-Cookie" not in response.headers
        assert "Unexpected RP ID hash" in response.get_json()["error"]

    def test_a_sign_count_rollback_is_refused(self, admin_client, authenticator, migrated_db):
        register(admin_client, authenticator, ADMIN_SECRET)
        assert login(admin_client, authenticator, sign_count=5).status_code == 200
        assert _sign_count(migrated_db) == 5
        for stale in (5, 3):
            response = login(admin_client, authenticator, sign_count=stale)
            assert response.status_code == 401 and "sign count" in response.get_json()["error"]
        assert login(admin_client, authenticator, sign_count=6).status_code == 200
        assert _sign_count(migrated_db) == 6

    def test_an_authenticator_without_a_counter_keeps_signing_in(
            self, admin_client, authenticator):
        register(admin_client, authenticator, ADMIN_SECRET)
        assert login(admin_client, authenticator, sign_count=0).status_code == 200
        assert login(admin_client, authenticator, sign_count=0).status_code == 200

    def test_another_key_cannot_sign_in(self, admin_client, authenticator):
        register(admin_client, authenticator, ADMIN_SECRET)
        stranger = SoftAuthenticator(ADMIN_RP_ID, ORIGIN)
        assert login(admin_client, stranger).status_code == 401
        impostor = SoftAuthenticator(ADMIN_RP_ID, ORIGIN)
        impostor.credential_id = authenticator.credential_id
        assert login(admin_client, impostor).status_code == 401

    @pytest.mark.parametrize("credential", [None, "x", {}, {"id": "a", "rawId": "a"}])
    def test_a_malformed_credential_is_400(self, admin_client, authenticator, credential):
        register(admin_client, authenticator, ADMIN_SECRET)
        admin_client.post("/v1/admin/login/options", json={})
        response = admin_client.post("/v1/admin/login/verify", json={"credential": credential})
        assert response.status_code == 400

    def test_login_before_any_registration_is_refused(self, admin_client):
        response = admin_client.post("/v1/admin/login/options", json={})
        assert response.status_code == 409
        assert "/v1/admin/register" in response.get_json()["error"]
