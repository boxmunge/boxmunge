"""boxmunge version-check service.

Serves:
1. GET  /v1/check?v=X                    — security/update status for the given version
2. POST /v1/report-failure               — record an upgrade failure
3. GET  /v1/failures?version=X           — query failure summary for a version
4. POST /v1/circuit-breaker/trip?version=X   — suppress a broken release (auth required)
5. POST /v1/circuit-breaker/reset?version=X  — re-enable a release (auth required)
6. GET  /                                — static landing page

Source: https://github.com/boxmunge/boxmunge/tree/main/services/version-check
"""

import json
import os
import sqlite3
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from flask import Flask, request, jsonify

SERVICE_DIR = Path(__file__).parent
RELEASES_PATH = SERVICE_DIR / "releases.json"
DB_PATH = Path("/data/checks.db")

VALID_STAGES = {"preflight", "apply", "health_immediate", "health_probation"}


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def _init_db(db_path: Path) -> None:
    """Create all tables if they don't exist."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS version_checks (
                date    TEXT NOT NULL,
                version TEXT NOT NULL,
                count   INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (date, version)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS failures (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                version       TEXT NOT NULL,
                installed_from TEXT NOT NULL,
                stage         TEXT NOT NULL,
                reported_at   TEXT NOT NULL,
                remote_addr   TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS circuit_breaker (
                version    TEXT PRIMARY KEY,
                tripped    INTEGER NOT NULL DEFAULT 1,
                tripped_by TEXT,
                tripped_at TEXT NOT NULL
            )
        """)
        conn.commit()
    finally:
        conn.close()


def _record_check(db_path: Path, version: str) -> None:
    """Increment the daily counter for this version."""
    today = date.today().isoformat()
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """INSERT INTO version_checks (date, version, count)
               VALUES (?, ?, 1)
               ON CONFLICT (date, version) DO UPDATE SET count = count + 1""",
            (today, version),
        )
        conn.commit()
    finally:
        conn.close()


def _record_failure(db_path, version, installed_from, stage, reported_at, remote_addr):
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "INSERT INTO failures (version, installed_from, stage, reported_at, remote_addr) VALUES (?, ?, ?, ?, ?)",
            (version, installed_from, stage, reported_at, remote_addr))
        conn.commit()
    finally:
        conn.close()


def _query_failures(db_path, version):
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(
            "SELECT stage, COUNT(*) FROM failures WHERE version = ? GROUP BY stage",
            (version,)).fetchall()
        time_range = conn.execute(
            "SELECT MIN(reported_at), MAX(reported_at) FROM failures WHERE version = ?",
            (version,)).fetchone()
    finally:
        conn.close()
    by_stage = {row[0]: row[1] for row in rows}
    total = sum(by_stage.values())
    return {
        "version": version,
        "total": total,
        "by_stage": by_stage,
        "first_seen": time_range[0] if total > 0 else None,
        "last_seen": time_range[1] if total > 0 else None,
    }


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


def _maybe_auto_trip(db_path: Path, version: str) -> None:
    """Auto-trip circuit breaker if failure threshold is exceeded."""
    threshold_str = os.environ.get("CIRCUIT_BREAKER_AUTO_THRESHOLD", "0")
    try:
        threshold = int(threshold_str)
    except ValueError:
        return
    if threshold <= 0:
        return

    six_hours_ago = (datetime.now(timezone.utc) - timedelta(hours=6)).isoformat()
    conn = sqlite3.connect(db_path)
    try:
        count = conn.execute(
            "SELECT COUNT(*) FROM failures WHERE version = ? AND reported_at > ?",
            (version, six_hours_ago),
        ).fetchone()[0]
    finally:
        conn.close()

    if count >= threshold:
        _trip_circuit_breaker(db_path, version, "auto")


def _check_cb_auth(app_config):
    secret = app_config.get("CB_SECRET") or os.environ.get("CB_SECRET", "")
    if not secret:
        return False
    auth = request.headers.get("Authorization", "")
    return auth == f"Bearer {secret}"


# ---------------------------------------------------------------------------
# Version logic
# ---------------------------------------------------------------------------

def _parse_version(v: str) -> tuple[int, ...] | None:
    """Parse semver string to tuple. Returns None if unparseable."""
    parts = v.split(".")
    try:
        return tuple(int(x) for x in parts)
    except ValueError:
        return None


def _same_minor_line(a: str, b: str) -> bool:
    """Check if two versions share the same major.minor."""
    pa = _parse_version(a)
    pb = _parse_version(b)
    if pa is None or pb is None or len(pa) < 2 or len(pb) < 2:
        return False
    return pa[0] == pb[0] and pa[1] == pb[1]


def _version_gt(a: str, b: str) -> bool:
    """Return True if version a > version b."""
    pa = _parse_version(a)
    pb = _parse_version(b)
    if pa is None or pb is None:
        return False
    max_len = max(len(pa), len(pb))
    pa = pa + (0,) * (max_len - len(pa))
    pb = pb + (0,) * (max_len - len(pb))
    return pa > pb


def _load_releases(path: Path) -> list[dict]:
    """Load and return the releases list from JSON."""
    with open(path) as f:
        return json.load(f)["releases"]


def _check_version(releases: list[dict], caller_version: str) -> dict:
    """Compute the check response for a given caller version."""
    latest = None
    for r in releases:
        if latest is None or _version_gt(r["version"], latest["version"]):
            latest = r

    security = None
    for r in releases:
        if not r.get("security"):
            continue
        if not _same_minor_line(r["version"], caller_version):
            continue
        if not _version_gt(r["version"], caller_version):
            continue
        if security is None or _version_gt(r["version"], security["version"]):
            security = r

    security_resp = None
    if security:
        security_resp = {"version": security["version"], "url": security["url"]}

    latest_resp = None
    if latest and _version_gt(latest["version"], caller_version):
        latest_resp = {"version": latest["version"], "url": latest["url"]}

    if security_resp:
        status = "security_update_available"
    elif latest_resp:
        status = "update_available"
    else:
        status = "up_to_date"

    return {"status": status, "security": security_resp, "latest": latest_resp}


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app() -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__, static_folder="static")

    _init_db(DB_PATH)
    releases = _load_releases(RELEASES_PATH)

    @app.route("/v1/check")
    def check():
        version = request.args.get("v", "").strip()
        if not version:
            return jsonify({"error": "missing version parameter"}), 400

        result = _check_version(releases, version)
        _record_check(DB_PATH, version)

        held = None
        if result.get("security"):
            sec_version = result["security"]["version"]
            if _is_circuit_broken(DB_PATH, sec_version):
                held = {"version": sec_version, "reason": "circuit_breaker"}
                result["security"] = None
                if result.get("latest"):
                    result["status"] = "update_available"
                else:
                    result["status"] = "up_to_date"
        if held:
            result["held"] = held

        response = jsonify(result)
        response.headers["Cache-Control"] = "no-cache"
        return response

    @app.route("/v1/report-failure", methods=["POST"])
    def report_failure():
        body = request.get_json(silent=True) or {}
        version = body.get("version")
        stage = body.get("stage")
        if not version:
            return jsonify({"error": "missing required field: version"}), 400
        if stage not in VALID_STAGES:
            return jsonify({"error": f"invalid stage; must be one of {sorted(VALID_STAGES)}"}), 400
        installed_from = body.get("installed_from", "")
        timestamp = datetime.now(timezone.utc).isoformat()

        # Check rate limit: max 1 report per version per IP per hour
        one_hour_ago = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        conn = sqlite3.connect(DB_PATH)
        try:
            existing = conn.execute(
                "SELECT COUNT(*) FROM failures WHERE version = ? AND remote_addr = ? AND reported_at > ?",
                (version, request.remote_addr, one_hour_ago),
            ).fetchone()
        finally:
            conn.close()

        if existing and existing[0] > 0:
            return "", 204  # Silently accept but don't store (rate limited)

        _record_failure(DB_PATH, version, installed_from, stage, timestamp,
                        request.remote_addr)
        _maybe_auto_trip(DB_PATH, version)
        return "", 204

    @app.route("/v1/failures")
    def failures():
        version = request.args.get("version", "").strip()
        if not version:
            return jsonify({"error": "missing version parameter"}), 400
        return jsonify(_query_failures(DB_PATH, version))

    @app.route("/v1/circuit-breaker/trip", methods=["POST"])
    def cb_trip():
        if not _check_cb_auth(app.config):
            return jsonify({"error": "unauthorized"}), 401
        version = request.args.get("version", "").strip()
        if not version:
            return jsonify({"error": "missing version parameter"}), 400
        _trip_circuit_breaker(DB_PATH, version, tripped_by="api")
        return jsonify({"status": "tripped", "version": version})

    @app.route("/v1/circuit-breaker/reset", methods=["POST"])
    def cb_reset():
        if not _check_cb_auth(app.config):
            return jsonify({"error": "unauthorized"}), 401
        version = request.args.get("version", "").strip()
        if not version:
            return jsonify({"error": "missing version parameter"}), 400
        _reset_circuit_breaker(DB_PATH, version)
        return jsonify({"status": "reset", "version": version})

    @app.route("/")
    def index():
        return app.send_static_file("index.html")

    return app
