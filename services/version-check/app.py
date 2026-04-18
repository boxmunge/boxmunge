"""boxmunge version-check service.

Serves two things:
1. GET /v1/check?v=X — returns security/update status for the given version
2. GET / — static landing page

Source: https://github.com/boxmunge/boxmunge/tree/main/services/version-check
"""

import json
import sqlite3
from datetime import date
from pathlib import Path

from flask import Flask, request, jsonify

SERVICE_DIR = Path(__file__).parent
RELEASES_PATH = SERVICE_DIR / "releases.json"
DB_PATH = Path("/data/checks.db")


def _init_db(db_path: Path) -> None:
    """Create the counter table if it doesn't exist."""
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
    # Find latest overall release
    latest = None
    for r in releases:
        if latest is None or _version_gt(r["version"], latest["version"]):
            latest = r

    # Find latest security release on caller's minor line
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

    # Build response
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

        response = jsonify(result)
        response.headers["Cache-Control"] = "no-cache"
        return response

    @app.route("/")
    def index():
        return app.send_static_file("index.html")

    return app
