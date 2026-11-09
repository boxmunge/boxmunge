"""Who may use the admin endpoints, and the keys derived from STATS_SECRET.

Two separate methods, never interchangeable:
- the JSON endpoints (scripts) take `Authorization: Bearer <STATS_SECRET>`;
- the HTML pages (browsers) take the session cookie a passkey sign-in sets.

STATS_SECRET is also the passkey registration code. The session-signing key
and the code fingerprint stored with the credential are HMACs of it under
fixed labels, so rotating it both ends every session and reopens
registration. With no STATS_SECRET every admin route refuses (AdminNotConfigured).
"""

import hashlib
import hmac
import os
import time
from functools import wraps
from typing import Callable
from urllib.parse import quote

from flask import current_app, make_response, redirect, request

SESSION_COOKIE = "bm_admin"
SESSION_SECONDS = 8 * 3600
SESSION_PATH = "/v1/admin"
LOGIN_PATH = "/v1/admin/login"

_SESSION_KEY_LABEL = b"boxmunge version-check: admin session signing key v1"
_CODE_MAC_LABEL = b"boxmunge version-check: passkey registration code v1"

# Admin HTML pages load their script and stylesheet from this origin only;
# nothing inline, nothing from a CDN.
ADMIN_CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
             "form-action 'none'; frame-ancestors 'none'; base-uri 'none'")


class AdminNotConfigured(RuntimeError):
    """STATS_SECRET is unset, so no admin method can be checked."""

    def __init__(self) -> None:
        super().__init__("admin access is not configured: STATS_SECRET is unset; set it "
                         "through the deploy shell and redeploy")


def now_unix() -> int:
    return int(time.time())


def eq(a: str, b: str) -> bool:
    """Constant-time equality; bytes, because compare_digest raises on non-ASCII str."""
    return hmac.compare_digest(a.encode(), b.encode())


def stats_secret() -> str:
    secret = current_app.config.get("STATS_SECRET") or os.environ.get("STATS_SECRET", "")
    if not secret:
        raise AdminNotConfigured()
    return secret


def code_mac(secret: str) -> str:
    """The fingerprint of the registration code stored with the credential."""
    return hmac.new(secret.encode(), _CODE_MAC_LABEL, hashlib.sha256).hexdigest()


def _session_mac(secret: str, expires: str) -> str:
    key = hmac.new(secret.encode(), _SESSION_KEY_LABEL, hashlib.sha256).digest()
    return hmac.new(key, f"session|{expires}".encode(), hashlib.sha256).hexdigest()


def session_cookie_value(secret: str) -> str:
    """"<expires_unix>.<mac>": the signature covers the expiry, so it cannot be extended."""
    expires = str(now_unix() + SESSION_SECONDS)
    return f"{expires}.{_session_mac(secret, expires)}"


def session_valid(secret: str, value: str) -> bool:
    expires, _, mac = value.partition(".")
    if not expires.isascii() or not expires.isdigit():
        return False
    if not eq(mac, _session_mac(secret, expires)):
        return False
    return now_unix() < int(expires)


def set_session_cookie(response, secret: str) -> None:
    response.set_cookie(SESSION_COOKIE, session_cookie_value(secret), max_age=SESSION_SECONDS,
                        path=SESSION_PATH, secure=True, httponly=True, samesite="Strict")


def bearer_authorized() -> bool:
    """The JSON endpoints' check: the Bearer header only, never the session cookie."""
    return eq(request.headers.get("Authorization", ""), f"Bearer {stats_secret()}")


def require_session(view: Callable) -> Callable:
    """An admin HTML page: a browser without a valid session is sent to sign in.

    The Bearer header is not accepted here, and the query string is neither
    read nor carried to the sign-in page.
    """
    @wraps(view)
    def guarded(*args, **kwargs):
        if not session_valid(stats_secret(), request.cookies.get(SESSION_COOKIE, "")):
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
