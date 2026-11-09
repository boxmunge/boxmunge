"""Shared fixtures for the version-check service tests."""

import os
import sys
import time
from datetime import date, datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import db_schema  # noqa: E402


@pytest.fixture
def migrated_db(tmp_path):
    """The database an app under test uses, as the image's pre-start step leaves it.

    Workers never migrate (create_app only checks the version), so each test
    starts from the state `python db_schema.py <db>` produces before gunicorn.
    """
    db_path = tmp_path / "checks.db"
    db_schema.migrate(db_path)
    return db_path


@pytest.fixture
def local_date_not_utc():
    """A local zone 12 hours off UTC, on whichever side makes the local
    calendar date differ from the UTC one right now; restored afterwards."""
    saved = os.environ.get("TZ")
    ahead = datetime.now(timezone.utc).hour >= 12
    os.environ["TZ"] = "XST-12" if ahead else "XST+12"
    time.tzset()
    assert date.today() != datetime.now(timezone.utc).date()
    try:
        yield
    finally:
        if saved is None:
            del os.environ["TZ"]
        else:
            os.environ["TZ"] = saved
        time.tzset()


ADMIN_SECRET = "registration-code-for-tests-0123456789"
ADMIN_RP_ID = "admin.example.com"


@pytest.fixture
def admin_app(tmp_path, migrated_db, monkeypatch):
    """The service with STATS_SECRET set and the relying party at ADMIN_RP_ID."""
    import json
    from unittest.mock import patch

    releases_file = tmp_path / "releases.json"
    releases_file.write_text(json.dumps({"releases": [
        {"version": "0.4.2", "class": "feature", "breaking": False,
         "url": "https://github.com/boxmunge/boxmunge/releases/tag/v0.4.2"},
    ]}))
    monkeypatch.setenv("ADMIN_RP_ID", ADMIN_RP_ID)
    with patch("app.RELEASES_PATH", releases_file), patch("app.DB_PATH", migrated_db):
        from app import create_app
        application = create_app()
        application.config["TESTING"] = True
        application.config["STATS_SECRET"] = ADMIN_SECRET
        yield application


@pytest.fixture
def admin_client(admin_app):
    # Cookies are passed by hand, so each test shows exactly what a browser sends.
    return admin_app.test_client(use_cookies=False)


@pytest.fixture
def authenticator():
    from softauthn import SoftAuthenticator
    return SoftAuthenticator(ADMIN_RP_ID, f"https://{ADMIN_RP_ID}")
