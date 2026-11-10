"""Passkey (WebAuthn) registration and sign-in for the admin HTML pages.

Registration is open only while no credential registered under the current
STATS_SECRET exists, and needs that secret as the registration code (in a
JSON body, never a URL): checked when the challenge is issued and again
when the passkey is stored. A sign-in sets the admin session cookie
(admin_auth). Challenges are single-use, purpose-bound and short-lived
(webauthn_store). Only ES256 and EdDSA keys, user verification required,
no attestation.
"""

import re
from pathlib import Path

from flask import Blueprint, Response, current_app, jsonify, request
from webauthn import (
    generate_authentication_options, generate_registration_options, options_to_json,
    verify_authentication_response, verify_registration_response,
)
from webauthn.helpers import (
    parse_authentication_credential_json, parse_client_data_json,
    parse_registration_credential_json,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import (
    AttestationConveyancePreference, AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor, ResidentKeyRequirement, UserVerificationRequirement,
)

import admin_auth
import admin_pages
import webauthn_store
from prefix_store import network_prefix
from request_limits import RateLimiter, client_key

ALGORITHMS = [COSEAlgorithmIdentifier.ECDSA_SHA_256, COSEAlgorithmIdentifier.EDDSA]
RP_NAME = "boxmunge version-check"
# Fixed, so registering again on the same authenticator replaces its old
# passkey for this site instead of adding a second one.
USER_ID = b"boxmunge-version-check-admin"
# Passkey ceremonies one client (IPv4 address or IPv6 /64) may start per
# challenge lifetime, per worker; and one network (IPv4 /24 or IPv6 /48), so
# the many /64s of one /48 cannot fill the global cap in webauthn_store.
CHALLENGES_PER_CLIENT = 5
CHALLENGES_PER_NETWORK = 20
CHALLENGE_LIMITER_CLIENTS = 10_000
USER_NAME = "admin"
DEFAULT_NEXT = "/v1/admin/stats"
NEXT_RE = re.compile(r"/v1/admin/[a-z0-9][a-z0-9_-]*(?:/[a-z0-9][a-z0-9_-]*)*\Z")
RP_ID_RE = re.compile(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\Z")
CLOSED = ("registration is closed: a passkey is already registered; to replace it, set a "
          "new STATS_SECRET through the deploy shell and redeploy")


class Refusal(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


def relying_party(rp_id: str) -> dict[str, str]:
    """App config for ADMIN_RP_ID; the origin is https://<rp_id> (tests override ADMIN_ORIGIN)."""
    if not RP_ID_RE.match(rp_id):
        raise ValueError(f"ADMIN_RP_ID must be a lower-case host name, got {rp_id!r}")
    return {"ADMIN_RP_ID": rp_id, "ADMIN_ORIGIN": f"https://{rp_id}"}


def _json_body() -> dict:
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise Refusal(400, "body must be a JSON object")
    return body


def _parse_credential(raw: object, parse) -> tuple[object, bytes]:
    """The credential from a JSON body, and the challenge its clientDataJSON answers."""
    if not isinstance(raw, dict):
        raise Refusal(400, "credential must be a JSON object")
    try:
        credential = parse(raw)
        challenge = parse_client_data_json(credential.response.client_data_json).challenge
    except (WebAuthnException, ValueError, TypeError) as exc:
        raise Refusal(400, f"malformed credential: {exc}") from exc
    return credential, challenge


def _options(options) -> Response:
    response = Response(options_to_json(options), mimetype="application/json")
    response.headers["Cache-Control"] = "no-store"
    return response


def create_blueprint(db_path: Path) -> Blueprint:
    bp = Blueprint("passkey", __name__)
    # Per client and per network, per worker, in memory: one client can hold
    # up only its own ceremonies, one network only its own, and no address is
    # stored.
    started = RateLimiter(CHALLENGES_PER_CLIENT, webauthn_store.CHALLENGE_TTL_SECONDS,
                          CHALLENGE_LIMITER_CLIENTS)
    started_on_network = RateLimiter(CHALLENGES_PER_NETWORK, webauthn_store.CHALLENGE_TTL_SECONDS,
                                     CHALLENGE_LIMITER_CLIENTS)

    @bp.errorhandler(Refusal)
    def refused(exc: Refusal):
        return jsonify({"error": str(exc)}), exc.status

    @bp.errorhandler(webauthn_store.TooManyChallenges)
    def too_many(exc: webauthn_store.TooManyChallenges):
        return jsonify({"error": str(exc)}), 429

    def issue(challenge: bytes, purpose: str) -> None:
        client, network = client_key(request.remote_addr), network_prefix(request.remote_addr)
        minutes = webauthn_store.CHALLENGE_TTL_SECONDS // 60
        if started.exhausted(client):
            raise webauthn_store.TooManyChallenges(
                f"this client started {CHALLENGES_PER_CLIENT} passkey ceremonies in the last "
                f"{minutes} minutes; try again later")
        if started_on_network.exhausted(network):
            raise webauthn_store.TooManyChallenges(
                f"this network started {CHALLENGES_PER_NETWORK} passkey ceremonies in the last "
                f"{minutes} minutes; try again later")
        if not (started.allow(client) and started_on_network.allow(network)):
            raise webauthn_store.TooManyChallenges(
                f"too many clients are starting passkey ceremonies; try again in {minutes} "
                f"minutes")
        webauthn_store.issue_challenge(db_path, challenge, purpose, admin_auth.now_unix())

    def registered(secret: str) -> webauthn_store.Credential | None:
        return webauthn_store.active_credential(db_path, admin_auth.code_mac(secret))

    def check_registration_code(secret: str, body: dict) -> None:
        """Registration is open and the body carries the code (admin_auth bounds guessing)."""
        if registered(secret) is not None:
            raise Refusal(403, CLOSED)
        code = body.get("code")
        if not admin_auth.check_secret(code if isinstance(code, str) else "", secret):
            raise Refusal(401, "wrong registration code")

    def redeem(challenge: bytes, purpose: str) -> None:
        if not webauthn_store.redeem_challenge(db_path, challenge, purpose,
                                               admin_auth.now_unix()):
            raise Refusal(400, "challenge expired or already used; start again")

    @bp.get("/v1/admin/register")
    def register_page():
        if registered(admin_auth.stats_secret()) is not None:
            return admin_auth.html_response(admin_pages.registration_closed(), 403)
        return admin_auth.html_response(admin_pages.register())

    @bp.post("/v1/admin/register/options")
    def register_options():
        secret = admin_auth.stats_secret()
        check_registration_code(secret, _json_body())
        options = generate_registration_options(
            rp_id=current_app.config["ADMIN_RP_ID"], rp_name=RP_NAME,
            user_id=USER_ID, user_name=USER_NAME,
            attestation=AttestationConveyancePreference.NONE,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.REQUIRED),
            supported_pub_key_algs=ALGORITHMS)
        issue(options.challenge, "register")
        return _options(options)

    @bp.post("/v1/admin/register/verify")
    def register_verify():
        secret = admin_auth.stats_secret()
        body = _json_body()
        check_registration_code(secret, body)
        credential, challenge = _parse_credential(body.get("credential"),
                                                  parse_registration_credential_json)
        redeem(challenge, "register")
        try:
            verified = verify_registration_response(
                credential=credential, expected_challenge=challenge,
                expected_rp_id=current_app.config["ADMIN_RP_ID"],
                expected_origin=current_app.config["ADMIN_ORIGIN"],
                require_user_verification=True, supported_pub_key_algs=ALGORITHMS)
        except WebAuthnException as exc:
            raise Refusal(400, f"passkey registration failed: {exc}") from exc
        stored = webauthn_store.store_credential(db_path, webauthn_store.Credential(
            verified.credential_id, verified.credential_public_key, verified.sign_count),
            admin_auth.code_mac(secret))
        if not stored:
            raise Refusal(403, CLOSED)
        return jsonify({"status": "registered"}), 201

    @bp.get("/v1/admin/login")
    def login_page():
        secret = admin_auth.stats_secret()
        next_path = request.args.get("next", DEFAULT_NEXT)
        if not NEXT_RE.match(next_path):
            raise Refusal(400, f"next must be an admin page path such as {DEFAULT_NEXT}")
        if registered(secret) is None:
            return admin_auth.html_response(admin_pages.no_passkey())
        return admin_auth.html_response(admin_pages.login(next_path))

    def require_registered() -> tuple[str, webauthn_store.Credential]:
        secret = admin_auth.stats_secret()
        stored = registered(secret)
        if stored is None:
            raise Refusal(409, "no passkey is registered; register one at /v1/admin/register")
        return secret, stored

    @bp.post("/v1/admin/login/options")
    def login_options():
        _, stored = require_registered()
        options = generate_authentication_options(
            rp_id=current_app.config["ADMIN_RP_ID"],
            allow_credentials=[PublicKeyCredentialDescriptor(id=stored.credential_id)],
            user_verification=UserVerificationRequirement.REQUIRED)
        issue(options.challenge, "login")
        return _options(options)

    @bp.post("/v1/admin/login/verify")
    def login_verify():
        secret, stored = require_registered()
        credential, challenge = _parse_credential(_json_body().get("credential"),
                                                  parse_authentication_credential_json)
        redeem(challenge, "login")
        if credential.raw_id != stored.credential_id:
            raise Refusal(401, "passkey sign-in failed: not the registered passkey")
        try:
            # Also refuses a sign count that did not increase (unless both are 0:
            # authenticators that keep no counter always send 0).
            verified = verify_authentication_response(
                credential=credential, expected_challenge=challenge,
                expected_rp_id=current_app.config["ADMIN_RP_ID"],
                expected_origin=current_app.config["ADMIN_ORIGIN"],
                credential_public_key=stored.public_key,
                credential_current_sign_count=stored.sign_count,
                require_user_verification=True)
        except WebAuthnException as exc:
            raise Refusal(401, f"passkey sign-in failed: {exc}") from exc
        if not webauthn_store.advance_sign_count(db_path, stored, verified.new_sign_count):
            raise Refusal(401, "passkey sign-in failed: the passkey was used concurrently; "
                               "sign in again")
        response = jsonify({"status": "signed in"})
        admin_auth.set_session_cookie(response, secret)
        return response

    return bp
