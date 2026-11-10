"""Failure reports alert the maintainer; they never hold a release.

Reports are unauthenticated, so anyone with addresses in a few networks can
send them. Letting them trip the circuit breaker would let anyone withhold a
security release from every box. Instead, once reports for a release come
from failure_alert.ALERT_NETWORKS distinct networks in the report window,
the smoke script makes the box's health check warn (and so alert, once per
message), naming exactly how the maintainer holds the release by hand.
"""

import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import circuit_breaker  # noqa: E402
import failure_alert  # noqa: E402
import failure_store  # noqa: E402

SERVICE_DIR = Path(__file__).parent.parent
PROXY = {"REMOTE_ADDR": "172.18.0.2"}
OLD_KEY = "CIRCUIT_BREAKER_AUTO_THRESHOLD"


@pytest.fixture
def make_client(tmp_path, migrated_db, monkeypatch):
    releases_file = tmp_path / "releases.json"
    releases_file.write_text(json.dumps({"releases": [
        {"version": "0.2.1", "class": "security", "breaking": False,
         "url": "https://github.com/boxmunge/boxmunge/releases/tag/v0.2.1"},
        {"version": "0.2.0", "class": "feature", "breaking": False,
         "url": "https://github.com/boxmunge/boxmunge/releases/tag/v0.2.0"},
    ]}))
    monkeypatch.delenv(OLD_KEY, raising=False)

    def build():
        with patch("app.RELEASES_PATH", releases_file), patch("app.DB_PATH", migrated_db):
            from app import create_app
            return create_app().test_client()

    with patch("app.DB_PATH", migrated_db):
        yield build


def _report(client, addr, version="0.2.1"):
    body = {"version": version, "installed_from": "0.2.0", "stage": "apply"}
    resp = client.post("/v1/report-failure", json=body, environ_base=PROXY,
                       headers={"X-Forwarded-For": addr})
    assert resp.status_code == 204


def _store(db_path, version, reporter, age=timedelta(0)):
    failure_store.record_failure(db_path, version, "0.2.0", "apply", reporter,
                                 datetime.now(timezone.utc) - age)


def _networks(n):
    return [f"198.51.{i}.0/24" for i in range(n)]


class TestReportsNeverHold:
    def test_reports_from_many_networks_leave_the_release_offered(self, make_client):
        client = make_client()
        for n in range(failure_alert.ALERT_NETWORKS + 5):
            _report(client, f"198.51.{n}.1")
        answer = client.get("/v1/check?v=0.2.0").get_json()
        assert answer.get("held") is None
        assert answer["security"]["version"] == "0.2.1"

    def test_the_old_auto_trip_key_no_longer_holds(self, make_client, monkeypatch):
        monkeypatch.setenv(OLD_KEY, "1")
        client = make_client()
        _report(client, "198.51.100.1")
        assert client.get("/v1/check?v=0.2.0").get_json().get("held") is None


class TestOldKeyAtStartup:
    @pytest.mark.parametrize("value", ["0", "3", "garbage"])
    def test_service_starts_and_says_the_key_was_removed(self, make_client, monkeypatch,
                                                          capsys, value):
        monkeypatch.setenv(OLD_KEY, value)
        make_client()
        err = capsys.readouterr().err
        assert f"{OLD_KEY} is set, but it was removed" in err
        assert "never hold a release" in err
        assert f"Remove {OLD_KEY}" in err

    def test_unset_key_says_nothing(self, make_client, capsys):
        make_client()
        assert OLD_KEY not in capsys.readouterr().err


class TestCrossing:
    def test_below_the_threshold_nothing_alerts(self, migrated_db):
        for net in _networks(failure_alert.ALERT_NETWORKS - 1):
            _store(migrated_db, "0.2.1", net)
        assert failure_alert.crossing(migrated_db, datetime.now(timezone.utc)) == []

    def test_distinct_networks_at_the_threshold_alert(self, migrated_db):
        for net in _networks(failure_alert.ALERT_NETWORKS):
            _store(migrated_db, "0.2.1", net)
        assert failure_alert.crossing(migrated_db, datetime.now(timezone.utc)) == ["0.2.1"]

    def test_one_network_counts_once(self, migrated_db):
        for n in range(failure_alert.ALERT_NETWORKS + 2):
            failure_store.record_failure(migrated_db, "0.2.1", "0.2.0", "apply",
                                         "198.51.100.0/24", datetime.now(timezone.utc),
                                         f"reason {n}")
        assert failure_alert.crossing(migrated_db, datetime.now(timezone.utc)) == []

    def test_reports_outside_the_window_do_not_count(self, migrated_db):
        old = failure_store.REPORT_WINDOW + timedelta(minutes=1)
        for net in _networks(failure_alert.ALERT_NETWORKS):
            _store(migrated_db, "0.2.1", net, age=old)
        assert failure_alert.crossing(migrated_db, datetime.now(timezone.utc)) == []

    def test_a_held_release_no_longer_alerts(self, migrated_db):
        """Tripping the breaker is the maintainer's answer; the alert clears."""
        for net in _networks(failure_alert.ALERT_NETWORKS):
            _store(migrated_db, "0.2.1", net)
        circuit_breaker.trip(migrated_db, "0.2.1", "api")
        assert failure_alert.crossing(migrated_db, datetime.now(timezone.utc)) == []

    def test_a_reset_release_alerts_again(self, migrated_db):
        for net in _networks(failure_alert.ALERT_NETWORKS):
            _store(migrated_db, "0.2.1", net)
        circuit_breaker.trip(migrated_db, "0.2.1", "api")
        circuit_breaker.reset(migrated_db, "0.2.1")
        assert failure_alert.crossing(migrated_db, datetime.now(timezone.utc)) == ["0.2.1"]

    def test_versions_are_listed_oldest_first(self, migrated_db):
        for version in ("0.10.0", "0.9.1"):
            for net in _networks(failure_alert.ALERT_NETWORKS):
                _store(migrated_db, version, net)
        assert failure_alert.crossing(
            migrated_db, datetime.now(timezone.utc)) == ["0.9.1", "0.10.0"]


class TestMessage:
    def test_names_exactly_how_to_hold_the_release(self):
        text = failure_alert.message(["0.2.1"])
        assert "\n" not in text
        assert f"0.2.1: {failure_alert.hold_steps('0.2.1')}" in text
        assert "not held" in text

    def test_names_every_crossing_release(self):
        text = failure_alert.message(["0.2.0", "0.2.1"])
        assert "version=0.2.0" in text and "version=0.2.1" in text

    def test_more_reports_do_not_change_the_message(self, migrated_db):
        """The box alerts once per distinct message: a count in it would
        re-alert on every new report."""
        for net in _networks(failure_alert.ALERT_NETWORKS):
            _store(migrated_db, "0.2.1", net)
        now = datetime.now(timezone.utc)
        before = failure_alert.message(failure_alert.crossing(migrated_db, now))
        _store(migrated_db, "0.2.1", "203.0.113.0/24")
        assert failure_alert.message(failure_alert.crossing(migrated_db, now)) == before


@pytest.fixture
def fake_tools(tmp_path):
    """curl and gh stand-ins on PATH: curl exits $CURL_RC, gh prints $TITLE
    for `release view` and records every call."""
    bin_dir, calls = tmp_path / "bin", tmp_path / "calls"
    bin_dir.mkdir()
    for tool, body in (("curl", 'echo "curl $*" >> "$CALLS"; exit "${CURL_RC:-0}"'),
                       ("gh", 'echo "gh $*" >> "$CALLS"\n'
                              '[ "$2" = view ] && printf "%s\\n" "$TITLE"; exit 0')):
        path = bin_dir / tool
        path.write_text(f"#!/bin/sh\n{body}\n")
        path.chmod(0o755)

    def run(version, title, curl_rc=0):
        env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "CALLS": str(calls),
               "CB_SECRET": "s", "TITLE": title, "CURL_RC": str(curl_rc)}
        result = subprocess.run(["sh", "-c", failure_alert.hold_steps(version)], env=env)
        lines = calls.read_text().splitlines() if calls.exists() else []
        calls.unlink(missing_ok=True)
        return result.returncode, lines

    return run


class TestHoldSteps:
    def test_trips_the_breaker_then_marks_the_title(self, fake_tools):
        rc, calls = fake_tools("0.2.1", "v0.2.1 [security] [breaking]")
        assert rc == 0
        assert calls[0].startswith("curl --fail-with-body -X POST")
        assert calls[0].endswith(
            "https://boxmunge.dev/v1/circuit-breaker/trip?version=0.2.1")
        assert calls[-1] == ("gh release edit v0.2.1 --title "
                             "v0.2.1 [security] [breaking] [held]")

    def test_a_refused_trip_leaves_github_alone(self, fake_tools):
        """curl exits 0 on a 401, 429 or 503 unless told to fail: a refused
        trip must not mark the release held on GitHub alone."""
        rc, calls = fake_tools("0.2.1", "v0.2.1 [security]", curl_rc=22)
        assert rc != 0
        assert [c for c in calls if c.startswith("gh")] == []

    def test_running_it_twice_marks_the_title_once(self, fake_tools):
        rc, calls = fake_tools("0.2.1", "v0.2.1 [security] [held]")
        assert rc == 0
        assert [c for c in calls if c.startswith("gh release edit")] == []


class TestCommand:
    def _run(self, db_path):
        return subprocess.run([sys.executable, "failure_alert.py", str(db_path)],
                              cwd=SERVICE_DIR, capture_output=True, text=True,
                              env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})

    def test_quiet_and_healthy_with_nothing_crossing(self, migrated_db):
        result = self._run(migrated_db)
        assert (result.returncode, result.stdout, result.stderr) == (0, "", "")

    def test_warns_with_one_line_when_a_release_crosses(self, migrated_db):
        for net in _networks(failure_alert.ALERT_NETWORKS):
            _store(migrated_db, "0.2.1", net)
        result = self._run(migrated_db)
        assert result.returncode == 1
        assert result.stderr == failure_alert.message(["0.2.1"]) + "\n"

    def test_missing_database_fails_loudly(self, tmp_path):
        result = self._run(tmp_path / "absent.db")
        assert result.returncode == 1
        assert "absent.db" in result.stderr


class TestWiring:
    def test_smoke_script_runs_the_alert_check_on_the_periodic_tick_only(self):
        """Every other smoke run gates an operation (deploy, recover, a lift,
        bring-up); reports anyone can send must not hold one up."""
        smoke = (SERVICE_DIR / "boxmunge-scripts" / "smoke.sh").read_text()
        assert ('if [ "${BOXMUNGE_CHECK:-}" = periodic ]; then\n'
                '    python3 /app/failure_alert.py /data/checks.db || exit 1\nfi') in smoke

    def test_image_ships_the_new_modules(self):
        dockerfile = (SERVICE_DIR / "Dockerfile").read_text()
        assert "failure_alert.py" in dockerfile and "circuit_breaker.py" in dockerfile
