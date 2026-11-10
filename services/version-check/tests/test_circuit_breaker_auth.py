"""CB_SECRET guards the only way to hold a release, so it resists guessing.

Failure reports never hold a release (failure_alert); the maintainer's
Bearer CB_SECRET on /v1/circuit-breaker/trip and /reset does. Like
STATS_SECRET, it must be long enough not to be guessed, and wrong guesses
share admin_auth's per-client limit.
"""

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import admin_auth  # noqa: E402

CB_SECRET = "circuit-breaker-secret-0123456789abcdef"
TRIP = "/v1/circuit-breaker/trip?version=0.2.1"
RESET = "/v1/circuit-breaker/reset?version=0.2.1"


@pytest.fixture
def make_app(tmp_path, migrated_db, monkeypatch):
    releases_file = tmp_path / "releases.json"
    releases_file.write_text(json.dumps({"releases": [
        {"version": "0.2.1", "class": "security", "breaking": False,
         "url": "https://github.com/boxmunge/boxmunge/releases/tag/v0.2.1"},
    ]}))
    monkeypatch.delenv("CB_SECRET", raising=False)
    monkeypatch.delenv("STATS_SECRET", raising=False)

    def build(**env):
        for name, value in env.items():
            monkeypatch.setenv(name, value)
        with patch("app.RELEASES_PATH", releases_file), patch("app.DB_PATH", migrated_db):
            from app import create_app
            return create_app()

    with patch("app.DB_PATH", migrated_db):
        yield build


def _bearer(secret):
    return {"Authorization": f"Bearer {secret}"}


class TestConfiguration:
    def test_a_short_secret_stops_the_service_from_starting(self, make_app):
        with pytest.raises(admin_auth.AdminNotConfigured) as refused:
            make_app(CB_SECRET="x")
        message = str(refused.value)
        assert "CB_SECRET" in message
        assert f"shorter than {admin_auth.MIN_SECRET_LENGTH}" in message
        assert "openssl rand -hex 32" in message

    def test_a_long_secret_starts(self, make_app):
        client = make_app(CB_SECRET=CB_SECRET).test_client()
        assert client.post(TRIP, headers=_bearer(CB_SECRET)).status_code == 200

    @pytest.mark.parametrize("path", [TRIP, RESET])
    def test_unset_secret_refuses_naming_the_fix(self, make_app, path):
        response = make_app().test_client().post(path, headers=_bearer("anything"))
        assert response.status_code == 503
        assert "CB_SECRET is unset" in response.get_json()["error"]


class TestGuessing:
    @pytest.mark.parametrize("path", [TRIP, RESET])
    def test_wrong_guesses_are_limited(self, make_app, path):
        client = make_app(CB_SECRET=CB_SECRET).test_client()
        for _ in range(admin_auth.GUESS_FAILURES):
            assert client.post(path, headers=_bearer("wrong")).status_code == 401
        # Past the limit even the right secret waits for the window.
        assert client.post(path, headers=_bearer(CB_SECRET)).status_code == 429

    def test_no_header_is_not_a_guess(self, make_app):
        client = make_app(CB_SECRET=CB_SECRET).test_client()
        for _ in range(admin_auth.GUESS_FAILURES + 1):
            assert client.post(TRIP).status_code == 401
        assert client.post(TRIP, headers=_bearer(CB_SECRET)).status_code == 200

    def test_stats_secret_does_not_open_the_breaker(self, make_app):
        stats = "stats-secret-0123456789abcdef0123456789"
        client = make_app(CB_SECRET=CB_SECRET, STATS_SECRET=stats).test_client()
        assert client.post(TRIP, headers=_bearer(stats)).status_code == 401
