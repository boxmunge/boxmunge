"""Who may use the admin endpoints, and the keys derived from STATS_SECRET.

Three separate methods, never interchangeable:
- the JSON stats endpoint (scripts) takes `Authorization: Bearer <STATS_SECRET>`;
- the circuit breaker's trip and reset take `Authorization: Bearer <CB_SECRET>`,
  a separate secret because a hold reaches every box;
- the HTML pages (browsers) take the session cookie a passkey sign-in sets.

STATS_SECRET is also the passkey registration code. The code fingerprint
stored with the credential is an HMAC of it under a fixed label. The
session-signing key needs both STATS_SECRET and a random key that never
leaves the database, so a leaked Bearer secret cannot forge a session, and
rotating STATS_SECRET still ends every session and reopens registration.
With no STATS_SECRET, or one too short to resist guessing, every admin
route refuses (AdminNotConfigured); likewise the circuit breaker without a
CB_SECRET, and a CB_SECRET too short stops the service from starting.
Wrong guesses of either secret, by Bearer or as the registration code,
share one per-client limit.
"""

import hashlib
import hmac
import os
import time
from functools import wraps
from typing import Callable
from urllib.parse import quote

from flask import current_app, make_response, redirect, request

from prefix_store import network_prefix
from request_limits import FULL, LIMITED, NETWORK_LIMITED, RequestLimiter

SESSION_COOKIE = "bm_admin"
SESSION_SECONDS = 8 * 3600
SESSION_PATH = "/v1/admin"
LOGIN_PATH = "/v1/admin/login"
MIN_SECRET_LENGTH = 32
# Wrong STATS_SECRET guesses per client (IPv4 address or IPv6 /64) per
# worker, before that client is refused outright for the rest of the window.
# Per worker: gunicorn runs several (Dockerfile), and each counts on its own,
# so a client gets GUESS_FAILURES per worker. Past GUESS_LIMITER_CLIENTS
# tracked clients, a new client is limited by its network (IPv4 /24, IPv6
# /48) instead, GUESS_FAILURES_PER_NETWORK per window, so one network's
# flood locks out only that network; past GUESS_LIMITER_CLIENTS networks
# too, every new client is refused until the window frees room.
GUESS_FAILURES = 10
GUESS_FAILURES_PER_NETWORK = 20
GUESS_WINDOW_SECONDS = 15 * 60
GUESS_LIMITER_CLIENTS = 10_000
SESSION_KEY = "admin_session_key"   # app.extensions: the database's random key
GUESSES = "admin_secret_guesses"    # app.extensions: the shared RequestLimiter

_SESSION_KEY_LABEL = b"boxmunge version-check: admin session signing key v1"
_CODE_MAC_LABEL = b"boxmunge version-check: passkey registration code v1"

# Admin HTML pages load their script and stylesheet from this origin only;
# nothing inline, nothing from a CDN.
ADMIN_CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
             "form-action 'none'; frame-ancestors 'none'; base-uri 'none'")


class AdminNotConfigured(RuntimeError):
    """A secret is unset or too short, so the method it guards cannot be checked."""


_GUESS_REFUSALS = {
    LIMITED: "too many wrong secrets from this client",
    NETWORK_LIMITED: "too many wrong secrets from this network",
    FULL: "too many clients are guessing the admin secret",
}


class TooManyGuesses(RuntimeError):
    """This client may not try STATS_SECRET now. `reason` is the guess
    limiter's refusal: this client (LIMITED) or its network
    (NETWORK_LIMITED) used its guesses, or both tables are full (FULL) and
    its guesses could not be counted."""

    def __init__(self, reason: str = LIMITED) -> None:
        super().__init__(f"{_GUESS_REFUSALS[reason]}; try again in "
                         f"{GUESS_WINDOW_SECONDS // 60} minutes")


def guess_limiter(max_clients: int = GUESS_LIMITER_CLIENTS,
                  per_network: int = GUESS_FAILURES_PER_NETWORK) -> RequestLimiter:
    return RequestLimiter(GUESS_FAILURES, per_network, GUESS_WINDOW_SECONDS, max_clients,
                          network_prefix)


def now_unix() -> int:
    return int(time.time())


def eq(a: str, b: str) -> bool:
    """Constant-time equality; bytes, because compare_digest raises on non-ASCII str."""
    return hmac.compare_digest(a.encode(), b.encode())


def _too_short(name: str, what: str) -> AdminNotConfigured:
    return AdminNotConfigured(
        f"{what} is not configured: {name} is shorter than {MIN_SECRET_LENGTH} characters; "
        "set a new one (e.g. `openssl rand -hex 32`) through the deploy shell and redeploy")


def _secret(name: str, what: str) -> str:
    secret = current_app.config.get(name) or os.environ.get(name, "")
    if not secret:
        raise AdminNotConfigured(f"{what} is not configured: {name} is unset; "
                                 "set it through the deploy shell and redeploy")
    if len(secret) < MIN_SECRET_LENGTH:
        raise _too_short(name, what)
    return secret


def stats_secret() -> str:
    return _secret("STATS_SECRET", "admin access")


def cb_secret() -> str:
    return _secret("CB_SECRET", "the circuit breaker")


def refuse_short_cb_secret() -> None:
    """At startup: a CB_SECRET that is set but guessable stops the service.

    It is the only way to hold a release from every box, so a deploy must
    not run with one an attacker could guess. Unset only refuses the
    circuit-breaker endpoints, as an unset STATS_SECRET refuses admin access.
    """
    secret = os.environ.get("CB_SECRET", "")
    if secret and len(secret) < MIN_SECRET_LENGTH:
        raise _too_short("CB_SECRET", "the circuit breaker")


def check_secret(candidate: str, secret: str) -> bool:
    """Compare a guess with `secret` in constant time, within the client's guess limit.

    A client past the limit is refused before the comparison, so even the
    right secret does not get through until the window rolls over. A client
    the full client table cannot track is counted by its network instead;
    one neither table has room for is refused (fail closed): a guess that
    could not be counted would be a free one.
    """
    limiter = current_app.extensions[GUESSES]
    refused = limiter.refusal(request.remote_addr)
    if refused is not None:
        raise TooManyGuesses(refused)
    if eq(candidate, secret):
        return True
    refused = limiter.admit(request.remote_addr)  # records the failure
    if refused is not None:  # another request used the last guess or slot meanwhile
        raise TooManyGuesses(refused)
    return False


def code_mac(secret: str) -> str:
    """The fingerprint of the registration code stored with the credential."""
    return hmac.new(secret.encode(), _CODE_MAC_LABEL, hashlib.sha256).hexdigest()


def _session_mac(secret: str, db_key: bytes, expires: str) -> str:
    secret_part = hmac.new(secret.encode(), _SESSION_KEY_LABEL, hashlib.sha256).digest()
    key = hmac.new(db_key, b"session" + secret_part, hashlib.sha256).digest()
    return hmac.new(key, f"session|{expires}".encode(), hashlib.sha256).hexdigest()


def session_cookie_value(secret: str, db_key: bytes) -> str:
    """"<expires_unix>.<mac>": the signature covers the expiry, so it cannot be extended."""
    expires = str(now_unix() + SESSION_SECONDS)
    return f"{expires}.{_session_mac(secret, db_key, expires)}"


def session_valid(secret: str, db_key: bytes, value: str) -> bool:
    expires, _, mac = value.partition(".")
    if not expires.isascii() or not expires.isdigit():
        return False
    if not eq(mac, _session_mac(secret, db_key, expires)):
        return False
    return now_unix() < int(expires)


def set_session_cookie(response, secret: str) -> None:
    value = session_cookie_value(secret, current_app.extensions[SESSION_KEY])
    response.set_cookie(SESSION_COOKIE, value, max_age=SESSION_SECONDS,
                        path=SESSION_PATH, secure=True, httponly=True, samesite="Strict")


def bearer_authorized(secret: str) -> bool:
    """The JSON endpoints' check against `secret` (stats_secret() or cb_secret(),
    evaluated first, so an unconfigured one refuses loudly): the Bearer header
    only, never the session cookie. A request without one is not a guess."""
    scheme, _, candidate = request.headers.get("Authorization", "").partition(" ")
    if scheme != "Bearer":
        return False
    return check_secret(candidate, secret)


def require_session(view: Callable) -> Callable:
    """An admin HTML page: a browser without a valid session is sent to sign in.

    The Bearer header is not accepted here, and the query string is neither
    read nor carried to the sign-in page.
    """
    @wraps(view)
    def guarded(*args, **kwargs):
        if not session_valid(stats_secret(), current_app.extensions[SESSION_KEY],
                             request.cookies.get(SESSION_COOKIE, "")):
            return redirect(f"{LOGIN_PATH}?next={quote(request.path, safe='/')}", code=303)
        return view(*args, **kwargs)
    return guarded


def html_response(page: str, status: int = 200):
    response = make_response(page, status)
    response.headers["Content-Type"] = "text/html; charset=utf-8"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = ADMIN_CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response
