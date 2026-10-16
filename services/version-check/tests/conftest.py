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
