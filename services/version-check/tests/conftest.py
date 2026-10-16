"""Shared fixtures for the version-check service tests."""

import sys
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
