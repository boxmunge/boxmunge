"""boxmunge version-check service.

Serves:
1. GET  /v1/check?v=X                    — security/breakfix/update offers (and any blocked
                                            auto-update) for the given version
2. POST /v1/report-failure               — record an upgrade failure
3. GET  /v1/failures?version=X           — query failure summary for a version
4. POST /v1/circuit-breaker/trip?version=X   — suppress a broken release (auth required)
5. POST /v1/circuit-breaker/reset?version=X  — re-enable a release (auth required)
6. GET  /v1/admin/version-checks?last=N  — daily check counts by version (auth required)
7. GET  /v1/admin/stats?last=N           — the same as an HTML page, plus recent failure
                                            reports (auth required)
8. GET  /healthz                         — liveness; counts nothing (smoke and health checks)
9. GET  /                                — static landing page

Abuse limits (F-12): the client address is taken from the X-Forwarded-For
header set by the boxmunge Caddy proxy (one trusted hop), every request is
rate-limited per client, request bodies are capped, and check counts are
buffered in memory and flushed periodically rather than written per request.
Failure reports are accepted only for listed releases and count once per
reporter (IPv4 address or IPv6 /64) per version per six hours; see
failure_store. The database schema changes only through db_schema migrations,
run once before gunicorn starts.

Source: https://github.com/boxmunge/boxmunge/tree/main/services/version-check
"""

import hashlib
import hmac
import os
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import Flask, make_response, redirect, request, jsonify
from werkzeug.middleware.proxy_fix import ProxyFix

import failure_store
from db_schema import require_current
from release_catalog import (
    VERSION_RE, apply_holds, check_response, find_blocked, load_releases, select_offers,
)
import stats_page
from request_limits import CheckCounter, RateLimiter, client_key, utc_today

SERVICE_DIR = Path(__file__).parent
RELEASES_PATH = SERVICE_DIR / "releases.json"
DB_PATH = Path("/data/checks.db")

VALID_STAGES = {
    "preflight",
    "apply",
    "apply_partial_rollback",
    "health_immediate",
    "health_probation",
    "system_upgrade",
}

# Stats endpoint window cap. Stops a runaway query against an unbounded
# version_checks table; 90 days is plenty for a "is anyone using this?"
# weekly summary.
STATS_MAX_DAYS = 90
STATS_DEFAULT_DAYS = 7

# The service runs behind exactly one proxy we control (boxmunge's Caddy),
# which overwrites X-Forwarded-For with the address it saw.
TRUSTED_PROXY_HOPS = 1
# Per-client request limit across all endpoints. A box checks every 6 hours;
# this leaves ample room for many boxes behind one NAT.
RATE_LIMIT_REQUESTS = 60
RATE_LIMIT_WINDOW_SECONDS = 60
# Bounded limiter memory; beyond this many clients in one window, new
# clients are refused until the window rolls over.
RATE_LIMIT_MAX_CLIENTS = 100_000
# Failure reports are ~200 bytes; nothing here needs a large body.
MAX_REQUEST_BYTES = 4096
CHECK_FLUSH_SECONDS = 60
CHECK_MAX_PENDING = 1000
# Failure-report free text. Boxes send e.g. "system_upgrade_failed: install_sh_exit_100".
DETAIL_MAX = 200
PRINTABLE_ASCII = re.compile(r"[ -~]*\Z")
# The 0.10.x shim sends `boxmunge-server --version` output as installed_from.
LEGACY_FROM_PREFIX = re.compile(r"^boxmunge\s+")
STATS_COOKIE = "bm_stats"
STATS_COOKIE_MAX_AGE = 8 * 3600
STATS_FAILURES_SHOWN = 100


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def _is_circuit_broken(db_path, version):
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            "SELECT tripped FROM circuit_breaker WHERE version = ? AND tripped = 1",
            (version,)).fetchone()
    finally:
        conn.close()
    return row is not None


def _trip_circuit_breaker(db_path, version, tripped_by):
    now = datetime.now(timezone.utc).isoformat()
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """INSERT INTO circuit_breaker (version, tripped, tripped_by, tripped_at)
               VALUES (?, 1, ?, ?)
               ON CONFLICT (version) DO UPDATE SET tripped = 1, tripped_by = ?, tripped_at = ?""",
            (version, tripped_by, now, tripped_by, now))
        conn.commit()
    finally:
        conn.close()


def _reset_circuit_breaker(db_path, version):
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("UPDATE circuit_breaker SET tripped = 0 WHERE version = ?", (version,))
        conn.commit()
    finally:
        conn.close()


def _auto_trip_threshold() -> int:
    """CIRCUIT_BREAKER_AUTO_THRESHOLD: distinct reporters in 6 hours that trip a version.

    0 (the default) disables auto-trip. Anything that is not a non-negative
    integer stops the service from starting, rather than silently leaving
    auto-trip off.
    """
    raw = os.environ.get("CIRCUIT_BREAKER_AUTO_THRESHOLD", "0")
    try:
        threshold = int(raw)
    except ValueError:
        threshold = -1
    if threshold < 0:
        raise ValueError(
            f"CIRCUIT_BREAKER_AUTO_THRESHOLD must be a non-negative integer, got {raw!r}")
    return threshold


def _maybe_auto_trip(db_path: Path, version: str, threshold: int, now: datetime) -> None:
    """Auto-trip circuit breaker if failure threshold is exceeded."""
    if threshold == 0:
        return
    if failure_store.count_recent(db_path, version, now) >= threshold:
        _trip_circuit_breaker(db_path, version, "auto")


def _check_cb_auth(app_config):
    secret = app_config.get("CB_SECRET") or os.environ.get("CB_SECRET", "")
    if not secret:
        return False
    auth = request.headers.get("Authorization", "")
    return _eq(auth, f"Bearer {secret}")


def _eq(a: str, b: str) -> bool:
    """Constant-time equality; bytes, because compare_digest raises on non-ASCII str."""
    return hmac.compare_digest(a.encode(), b.encode())


def _check_stats_auth(app_config):
    """Authorize the admin/version-checks endpoint: `Authorization: Bearer <secret>`.

    Uses STATS_SECRET, NOT CB_SECRET — different blast radius. A leaked
    stats token is read-only over check counts; a leaked CB token can
    suppress security releases fleetwide.
    """
    secret = _stats_secret(app_config)
    if not secret:
        return False
    return _eq(request.headers.get("Authorization", ""), f"Bearer {secret}")


def _stats_secret(app_config) -> str:
    return app_config.get("STATS_SECRET") or os.environ.get("STATS_SECRET", "")


def _now_unix() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def _stats_cookie_mac(secret: str, issued: str) -> str:
    return hmac.new(secret.encode(), f"stats-cookie|{issued}".encode(), hashlib.sha256).hexdigest()


def _stats_cookie_value(secret: str) -> str:
    """"<issued_unix>.<mac>": derived from the secret, never the secret itself,
    and checked against its issue time so a stolen cookie dies after STATS_COOKIE_MAX_AGE."""
    issued = str(_now_unix())
    return f"{issued}.{_stats_cookie_mac(secret, issued)}"


def _stats_cookie_valid(secret: str, value: str) -> bool:
    issued, _, mac = value.partition(".")
    if not issued.isascii() or not issued.isdigit() or not _eq(mac, _stats_cookie_mac(secret, issued)):
        return False
    return 0 <= _now_unix() - int(issued) <= STATS_COOKIE_MAX_AGE


def _check_stats_page_auth(app_config) -> bool:
    """Authorize the stats page: Bearer header, or the cookie set by ?token=."""
    secret = _stats_secret(app_config)
    if not secret:
        return False
    if _eq(request.headers.get("Authorization", ""), f"Bearer {secret}"):
        return True
    return _stats_cookie_valid(secret, request.cookies.get(STATS_COOKIE, ""))


def _query_version_checks(db_path: Path, days: int, listed: set[str]) -> dict:
    """Aggregate the version_checks table for the last `days` days.

    Returns:
      {
        "since": "YYYY-MM-DD",   # earliest day in window (inclusive)
        "until": "YYYY-MM-DD",   # latest day in window (today, inclusive)
        "days": N,
        "totals":  [ {"version": "X", "count": N, "listed": bool}, ... ],   # count desc
        "by_date": [ {"date": "...", "version": "X", "count": N}, ... ]
      }
    """
    until = utc_today()
    since = until - timedelta(days=days - 1)  # inclusive of today
    since_iso = since.isoformat()
    until_iso = until.isoformat()

    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(
            "SELECT date, version, count FROM version_checks "
            "WHERE date >= ? AND date <= ? "
            "ORDER BY date DESC, count DESC",
            (since_iso, until_iso),
        ).fetchall()
        totals_rows = conn.execute(
            "SELECT version, SUM(count) AS total FROM version_checks "
            "WHERE date >= ? AND date <= ? "
            "GROUP BY version ORDER BY total DESC",
            (since_iso, until_iso),
        ).fetchall()
    finally:
        conn.close()

    return {
        "since": since_iso,
        "until": until_iso,
        "days": days,
        "totals": [{"version": v, "count": c, "listed": v in listed} for v, c in totals_rows],
        "by_date": [{"date": d, "version": v, "count": c} for d, v, c in rows],
    }


def _parse_last_param(raw: str | None) -> int:
    """Coerce ?last=N to a sane integer in [1, STATS_MAX_DAYS].

    Default applied for missing or unparseable values. Cap applied for
    excessive values. Negative or zero falls back to default.
    """
    if not raw:
        return STATS_DEFAULT_DAYS
    try:
        n = int(raw)
    except ValueError:
        return STATS_DEFAULT_DAYS
    if n <= 0:
        return STATS_DEFAULT_DAYS
    return min(n, STATS_MAX_DAYS)


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def _version_arg(name: str) -> str | None:
    """The X.Y.Z version in query parameter `name`, or None if absent/malformed."""
    value = request.args.get(name, "").strip()
    return value if VERSION_RE.match(value) else None


def create_app() -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__, static_folder="static")
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=TRUSTED_PROXY_HOPS)
    app.config["MAX_CONTENT_LENGTH"] = MAX_REQUEST_BYTES

    # The pre-start step (db_schema.py, run by the image's CMD) migrates.
    require_current(DB_PATH)
    # Raises ReleaseCatalogError on any invalid entry: a service that
    # cannot classify releases must not answer fleet update checks.
    releases = load_releases(RELEASES_PATH)
    listed_versions = {r["version"] for r in releases}
    auto_trip_threshold = _auto_trip_threshold()
    limiter = RateLimiter(RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW_SECONDS,
                          RATE_LIMIT_MAX_CLIENTS)
    counter = CheckCounter(DB_PATH, CHECK_FLUSH_SECONDS, CHECK_MAX_PENDING,
                           always_count=frozenset(listed_versions))
    app.extensions["check_counter"] = counter
    sweeper = failure_store.Sweeper(DB_PATH, failure_store.SWEEP_INTERVAL)
    sweeper.start()
    app.extensions["failure_sweeper"] = sweeper

    @app.before_request
    def rate_limit():
        if not limiter.allow(client_key(request.remote_addr)):
            response = jsonify({"error": "rate limited"})
            response.status_code = 429
            response.headers["Retry-After"] = str(RATE_LIMIT_WINDOW_SECONDS)
            return response
        return None

    @app.route("/healthz")
    def healthz():
        """Liveness for the smoke script and platform health check; counts nothing."""
        response = jsonify({"status": "ok"})
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.route("/v1/check")
    def check():
        version = _version_arg("v")
        if version is None:
            return jsonify({"error": "missing or malformed version parameter (want X.Y.Z)"}), 400

        offers, held = apply_holds(
            select_offers(releases, version),
            lambda v: _is_circuit_broken(DB_PATH, v),
        )
        result = check_response(offers, held, find_blocked(releases, version))
        # The real version, listed or not (a dev build, a dropped release): it is
        # valid X.Y.Z, and the counter caps distinct versions per day.
        counter.record(version)

        response = jsonify(result)
        response.headers["Cache-Control"] = "no-cache"
        return response

    @app.route("/v1/report-failure", methods=["POST"])
    def report_failure():
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify({"error": "body must be a JSON object"}), 400
        version = body.get("version")
        stage = body.get("stage")
        if not version:
            return jsonify({"error": "missing required field: version"}), 400
        if not isinstance(version, str) or not VERSION_RE.match(version):
            return jsonify({"error": "version must be X.Y.Z"}), 400
        if version not in listed_versions:
            # Only published releases can be held, so reports for anything
            # else would only grow the table.
            return jsonify({"error": f"version {version} is not a release listed in "
                                     "releases.json; report failures of published "
                                     "releases only"}), 400
        if not isinstance(stage, str) or stage not in VALID_STAGES:
            return jsonify({"error": f"invalid stage; must be one of {sorted(VALID_STAGES)}"}), 400
        installed_from = body.get("installed_from", "")
        if not isinstance(installed_from, str) or len(installed_from) > 64:
            return jsonify({"error": "installed_from must be a string of at most 64 characters"}), 400
        detail = body.get("detail")
        if detail is not None and (not isinstance(detail, str) or len(detail) > DETAIL_MAX
                                   or not PRINTABLE_ASCII.match(detail)):
            return jsonify({"error": f"detail must be printable ASCII of at most "
                                     f"{DETAIL_MAX} characters"}), 400
        installed_from = LEGACY_FROM_PREFIX.sub("", installed_from)
        if installed_from != "unknown" and not VERSION_RE.match(installed_from):
            return jsonify({"error": "installed_from must be X.Y.Z or \"unknown\" "
                                     "(optionally prefixed \"boxmunge \")"}), 400
        now = datetime.now(timezone.utc)
        # A repeat from the same reporter is accepted but not stored: the
        # box needs no different answer, and storing it would let one host
        # count several times towards the auto-trip threshold.
        if failure_store.record_failure(DB_PATH, version, installed_from, stage,
                                        client_key(request.remote_addr), now, detail or None):
            _maybe_auto_trip(DB_PATH, version, auto_trip_threshold, now)
        return "", 204

    @app.route("/v1/failures")
    def failures():
        version = _version_arg("version")
        if version is None:
            return jsonify({"error": "missing or malformed version parameter (want X.Y.Z)"}), 400
        return jsonify(failure_store.query_failures(DB_PATH, version))

    @app.route("/v1/circuit-breaker/trip", methods=["POST"])
    def cb_trip():
        if not _check_cb_auth(app.config):
            return jsonify({"error": "unauthorized"}), 401
        version = _version_arg("version")
        if version is None:
            return jsonify({"error": "missing or malformed version parameter (want X.Y.Z)"}), 400
        _trip_circuit_breaker(DB_PATH, version, tripped_by="api")
        return jsonify({"status": "tripped", "version": version})

    @app.route("/v1/circuit-breaker/reset", methods=["POST"])
    def cb_reset():
        if not _check_cb_auth(app.config):
            return jsonify({"error": "unauthorized"}), 401
        version = _version_arg("version")
        if version is None:
            return jsonify({"error": "missing or malformed version parameter (want X.Y.Z)"}), 400
        _reset_circuit_breaker(DB_PATH, version)
        return jsonify({"status": "reset", "version": version})

    @app.route("/v1/admin/version-checks")
    def admin_version_checks():
        """Daily check counts by version, last N days. Auth required.

        Counts are /v1/check hits, NOT unique boxes — a single box checks
        ~4x/day per its auto-update timer, plus manual upgrades. Versions
        not in releases.json are counted under their own version (marked
        listed: false); the "unlisted" row only collects the overflow beyond the
        per-day cap on distinct versions. Use this as a "is
        anyone running boxmunge?" signal, not for precise install counts.
        Counts buffered in other gunicorn workers appear after their next
        flush (at most CHECK_FLUSH_SECONDS later).
        """
        if not _check_stats_auth(app.config):
            return jsonify({"error": "unauthorized"}), 401
        counter.flush()
        days = _parse_last_param(request.args.get("last"))
        return jsonify(_query_version_checks(DB_PATH, days, listed_versions))

    @app.route("/v1/admin/stats")
    def admin_stats():
        """HTML: daily checks per version and recent failure reports. Auth required.

        Browsers cannot send a Bearer header, so `?token=<secret>` once sets a
        short-lived HttpOnly cookie and redirects to the page without the token
        in the URL. The page itself accepts only the header or that cookie.
        """
        token = request.args.get("token")
        if token is not None:
            secret = _stats_secret(app.config)
            if not secret or not _eq(token, secret):
                return jsonify({"error": "unauthorized"}), 401
            response = redirect(f"/v1/admin/stats?last={_parse_last_param(request.args.get('last'))}",
                                code=303)
            response.set_cookie(STATS_COOKIE, _stats_cookie_value(secret),
                                max_age=STATS_COOKIE_MAX_AGE, path="/v1/admin",
                                secure=True, httponly=True, samesite="Strict")
            return response
        if not _check_stats_page_auth(app.config):
            return jsonify({"error": "unauthorized"}), 401
        counter.flush()
        stats = _query_version_checks(DB_PATH, _parse_last_param(request.args.get("last")),
                                      listed_versions)
        page = stats_page.render(stats, failure_store.recent_failures(
            DB_PATH, STATS_FAILURES_SHOWN))
        response = make_response(page)
        response.headers["Content-Type"] = "text/html; charset=utf-8"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'")
        return response

    @app.route("/")
    def index():
        return app.send_static_file("index.html")

    return app
