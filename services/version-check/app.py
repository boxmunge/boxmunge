"""boxmunge version-check service.

Serves:
1. GET  /v1/check?v=X                    — security/breakfix/update offers (and any blocked
                                            auto-update) for the given version
2. POST /v1/report-failure               — record an upgrade failure
3. GET  /v1/failures?version=X           — query failure summary for a version
4. POST /v1/circuit-breaker/trip?version=X   — hold a release (Bearer CB_SECRET)
5. POST /v1/circuit-breaker/reset?version=X  — release a hold (Bearer CB_SECRET)
6. GET  /v1/admin/version-checks?last=N  — daily check counts by version (Bearer
                                            STATS_SECRET)
7. GET  /v1/admin/stats?last=N           — the same as an HTML page, plus the network
                                            prefixes that checked and recent failure
                                            reports (passkey session)
8. /v1/admin/register, /v1/admin/login   — passkey registration and sign-in (passkey_routes)
9. GET  /healthz                         — liveness; counts nothing (smoke and health checks)
10. GET /                                — static landing page

Abuse limits (F-12): the client address is taken from the X-Forwarded-For
header set by the boxmunge Caddy proxy (one trusted hop), every request is
rate-limited per client (per network once the client table is full; see
request_limits.RequestLimiter), request bodies are capped, and check counts
are buffered in memory and flushed periodically rather than written per
request. Every limit is per gunicorn worker. Failure reports are accepted
only for listed releases and repeats are not stored (failure_store). They
never hold a release: they are unauthenticated, so they only alert the
maintainer, counting each reporter (IPv4 /24 or IPv6 /48) once per version
per six hours (failure_alert); only the maintainer trips the breaker. The
database schema changes only through db_schema migrations, run once before
gunicorn starts.

Privacy: the database holds a client's network prefix (prefix_store), never
its address. The address is held in memory for rate limiting and written
to the request logs (gunicorn's access log here, Caddy's in front).
Stored rows expire on a schedule (retention).

Source: https://github.com/boxmunge/boxmunge/tree/main/services/version-check
"""

import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import Flask, request, jsonify
from werkzeug.middleware.proxy_fix import ProxyFix

import admin_auth
import circuit_breaker
import db
import failure_alert
import failure_store
import passkey_routes
import prefix_store
import retention
from db_schema import require_current
from release_catalog import (
    VERSION_RE, apply_holds, check_response, find_blocked, load_releases, select_offers,
)
import stats_page
import webauthn_store
from request_limits import CheckCounter, RequestLimiter, utc_today

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
# Bounded limiter memory. Beyond this many clients in one window, a new
# client is limited by its network (IPv4 /24, IPv6 /48) instead, with this
# allowance per network; beyond this many networks too, it is refused until
# the window rolls over (request_limits.RequestLimiter).
RATE_LIMIT_MAX_CLIENTS = 100_000
RATE_LIMIT_NETWORK_REQUESTS = 600
# Failure reports are ~200 bytes; nothing here needs a large body.
MAX_REQUEST_BYTES = 4096
CHECK_FLUSH_SECONDS = 60
CHECK_MAX_PENDING = 1000
# Failure-report free text. Boxes send e.g. "system_upgrade_failed: install_sh_exit_100".
DETAIL_MAX = 200
PRINTABLE_ASCII = re.compile(r"[ -~]*\Z")
# The 0.10.x shim sends `boxmunge-server --version` output as installed_from.
LEGACY_FROM_PREFIX = re.compile(r"^boxmunge\s+")
STATS_FAILURES_SHOWN = 100
PREFIXES_SHOWN = 500


REMOVED_AUTO_TRIP_KEY = "CIRCUIT_BREAKER_AUTO_THRESHOLD"


def _warn_removed_auto_trip() -> None:
    """Say so at every start if a deploy still sets the removed auto-trip key.

    It used to let failure reports from N networks hold a release fleet-wide.
    Reports are unauthenticated, so now they only alert (failure_alert), and
    the setting does nothing. The service starts, but says so plainly.
    """
    if REMOVED_AUTO_TRIP_KEY not in os.environ:
        return
    print(f"WARNING: {REMOVED_AUTO_TRIP_KEY} is set, but it was removed in 0.11.6 and "
          "does nothing: failure reports never hold a release. When reports for a "
          f"release come from {failure_alert.ALERT_NETWORKS} networks, the box's health "
          "check alerts and the maintainer holds the release by hand "
          f"(docs/DEVELOPMENT.md, \"Holding a broken release\"). Remove {REMOVED_AUTO_TRIP_KEY} "
          "from the service's environment.", file=sys.stderr)


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

    conn = db.connect(db_path)
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
    app.config.update(passkey_routes.relying_party(os.environ.get("ADMIN_RP_ID", "boxmunge.dev")))

    # The pre-start step (db_schema.py, run by the image's CMD) migrates.
    require_current(DB_PATH)
    # Raises ReleaseCatalogError on any invalid entry: a service that
    # cannot classify releases must not answer fleet update checks.
    releases = load_releases(RELEASES_PATH)
    listed_versions = {r["version"] for r in releases}
    _warn_removed_auto_trip()
    admin_auth.refuse_short_cb_secret()
    limiter = RequestLimiter(RATE_LIMIT_REQUESTS, RATE_LIMIT_NETWORK_REQUESTS,
                             RATE_LIMIT_WINDOW_SECONDS, RATE_LIMIT_MAX_CLIENTS,
                             prefix_store.network_prefix)
    counter = CheckCounter(DB_PATH, CHECK_FLUSH_SECONDS, CHECK_MAX_PENDING,
                           always_count=frozenset(listed_versions))
    app.extensions["check_counter"] = counter
    prefixes = prefix_store.PrefixLog(DB_PATH, CHECK_FLUSH_SECONDS, CHECK_MAX_PENDING,
                                      frozenset(listed_versions))
    app.extensions["prefix_log"] = prefixes
    sweeper = retention.Sweeper(DB_PATH, retention.SWEEP_INTERVAL,
                                flushes=(counter.flush, prefixes.flush))
    sweeper.start()
    app.extensions["retention_sweeper"] = sweeper

    app.extensions[admin_auth.SESSION_KEY] = webauthn_store.session_key(DB_PATH)
    app.extensions[admin_auth.GUESSES] = admin_auth.guess_limiter()
    app.register_blueprint(passkey_routes.create_blueprint(DB_PATH))

    @app.errorhandler(admin_auth.AdminNotConfigured)
    def admin_not_configured(exc):
        return jsonify({"error": str(exc)}), 503

    @app.errorhandler(admin_auth.TooManyGuesses)
    def too_many_guesses(exc):
        return jsonify({"error": str(exc)}), 429

    @app.before_request
    def rate_limit():
        if not limiter.allow(request.remote_addr):
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
        prefix = prefix_store.network_prefix(request.remote_addr)

        # One query per check, whatever the number of candidates.
        tripped = circuit_breaker.tripped_versions(DB_PATH)
        offers, held = apply_holds(select_offers(releases, version), tripped.__contains__)
        result = check_response(offers, held, find_blocked(releases, version))
        # The real version, listed or not (a dev build, a dropped release): it is
        # valid X.Y.Z, and the counter caps distinct versions per day.
        counter.record(version)
        prefixes.record(prefix, version)

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
        # A repeat of a report the same network already sent is accepted but
        # not stored: the box needs no different answer. Reports never hold a
        # release; the smoke script's failure_alert check alerts the maintainer.
        failure_store.record_failure(DB_PATH, version, installed_from, stage,
                                     prefix_store.network_prefix(request.remote_addr), now,
                                     detail or None)
        return "", 204

    @app.route("/v1/failures")
    def failures():
        version = _version_arg("version")
        if version is None:
            return jsonify({"error": "missing or malformed version parameter (want X.Y.Z)"}), 400
        return jsonify(failure_store.query_failures(DB_PATH, version))

    @app.route("/v1/circuit-breaker/trip", methods=["POST"])
    def cb_trip():
        if not admin_auth.bearer_authorized(admin_auth.cb_secret()):
            return jsonify({"error": "unauthorized"}), 401
        version = _version_arg("version")
        if version is None:
            return jsonify({"error": "missing or malformed version parameter (want X.Y.Z)"}), 400
        circuit_breaker.trip(DB_PATH, version, tripped_by="api")
        return jsonify({"status": "tripped", "version": version})

    @app.route("/v1/circuit-breaker/reset", methods=["POST"])
    def cb_reset():
        if not admin_auth.bearer_authorized(admin_auth.cb_secret()):
            return jsonify({"error": "unauthorized"}), 401
        version = _version_arg("version")
        if version is None:
            return jsonify({"error": "missing or malformed version parameter (want X.Y.Z)"}), 400
        circuit_breaker.reset(DB_PATH, version)
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
        # Bearer STATS_SECRET only: the passkey session cookie does not open
        # this. A leaked STATS_SECRET is read-only over check counts; CB_SECRET
        # (which can suppress releases fleetwide) is separate.
        if not admin_auth.bearer_authorized(admin_auth.stats_secret()):
            return jsonify({"error": "unauthorized"}), 401
        counter.flush()
        days = _parse_last_param(request.args.get("last"))
        return jsonify(_query_version_checks(DB_PATH, days, listed_versions))

    @app.route("/v1/admin/stats")
    @admin_auth.require_session
    def admin_stats():
        """HTML for a signed-in browser: daily checks per version, the network
        prefixes that checked, and recent failure reports."""
        counter.flush()
        prefixes.flush()
        stats = _query_version_checks(DB_PATH, _parse_last_param(request.args.get("last")),
                                      listed_versions)
        return admin_auth.html_response(stats_page.render(
            stats, prefix_store.by_prefix(DB_PATH, PREFIXES_SHOWN),
            failure_store.recent_failures(DB_PATH, STATS_FAILURES_SHOWN)))

    @app.route("/")
    def index():
        return app.send_static_file("index.html")

    return app
