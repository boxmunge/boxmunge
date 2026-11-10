"""Failure reports cannot be multiplied, are bounded, and the schema migrates.

Auto-trip lets public, unauthenticated reports withhold a release fleetwide,
so a report must count once per reporter (an IPv4 /24 or an IPv6 /48, the
network prefix the service stores instead of an address) and only for
versions the service publishes.
"""

import json
import os
import sqlite3
import sys
import subprocess
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import db_schema  # noqa: E402
import failure_store  # noqa: E402
import retention  # noqa: E402

SERVICE_DIR = Path(__file__).parent.parent

PROXY = {"REMOTE_ADDR": "172.18.0.2"}


def _report(version="0.2.1", stage="apply"):
    return {"version": version, "installed_from": "0.2.0", "stage": stage}


@pytest.fixture
def make_client(tmp_path, migrated_db):
    releases_file = tmp_path / "releases.json"
    releases_file.write_text(json.dumps({"releases": [
        {"version": "0.2.1", "class": "security", "breaking": False,
         "url": "https://github.com/boxmunge/boxmunge/releases/tag/v0.2.1"},
        {"version": "0.2.0", "class": "feature", "breaking": False,
         "url": "https://github.com/boxmunge/boxmunge/releases/tag/v0.2.0"},
    ]}))
    started = []

    def build(threshold="0"):
        for p in (patch("app.RELEASES_PATH", releases_file),
                  patch("app.DB_PATH", tmp_path / "checks.db"),
                  patch.dict(os.environ, {"CIRCUIT_BREAKER_AUTO_THRESHOLD": threshold})):
            p.start()
            started.append(p)
        from app import create_app
        return create_app().test_client()

    yield build
    for p in reversed(started):
        p.stop()


def _post(client, addr, version="0.2.1"):
    return client.post("/v1/report-failure", json=_report(version), environ_base=PROXY,
                       headers={"X-Forwarded-For": addr})


def _rows(db_path, columns="version, reporter"):
    conn = sqlite3.connect(db_path)
    try:
        return conn.execute(f"SELECT {columns} FROM failures ORDER BY id").fetchall()
    finally:
        conn.close()


def _held(client):
    return client.get("/v1/check?v=0.2.0").get_json().get("held")


class TestReporterIdentity:
    @pytest.mark.parametrize("first, second, prefix", [
        ("2001:db8:0:1::1", "2001:db8:0:2::2", "2001:db8::/48"),
        ("198.51.100.1", "198.51.100.200", "198.51.100.0/24"),
    ])
    def test_addresses_in_one_network_count_once(self, make_client, tmp_path,
                                                 first, second, prefix):
        client = make_client(threshold="2")
        assert _post(client, first).status_code == 204
        assert _post(client, second).status_code == 204
        assert _rows(tmp_path / "checks.db") == [("0.2.1", prefix)]
        assert _held(client) is None

    @pytest.mark.parametrize("first, second", [
        ("2001:db8:1::1", "2001:db8:2::1"), ("198.51.100.1", "198.51.101.1")])
    def test_distinct_networks_are_distinct_reporters(self, make_client, first, second):
        client = make_client(threshold="2")
        _post(client, first)
        _post(client, second)
        assert _held(client) == [{"version": "0.2.1", "reason": "circuit_breaker"}]

    def test_one_address_counts_once_across_the_auto_trip_window(self, make_client, tmp_path):
        """A reporter that could report again every hour would reach a low
        threshold alone within the six-hour auto-trip window."""
        client = make_client(threshold="2")
        _post(client, "198.51.100.1")
        conn = sqlite3.connect(tmp_path / "checks.db")
        conn.execute("UPDATE failures SET reported_at = ?",
                     ((datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(),))
        conn.commit()
        conn.close()
        _post(client, "198.51.100.1")
        assert len(_rows(tmp_path / "checks.db")) == 1
        assert _held(client) is None

    def test_different_failures_from_one_network_are_all_kept(self, make_client, tmp_path):
        """VC-6: one /48 can hold many customers' boxes. A second box failing
        differently must not lose its detail to the first box's report, and
        the network still counts once towards auto-trip."""
        client = make_client(threshold="2")
        for addr, stage, detail in (("2001:db8:0:1::1", "apply", "install_sh_exit_100"),
                                    ("2001:db8:0:2::1", "preflight", "cosign_verify"),
                                    ("2001:db8:0:3::1", "apply", "install_sh_exit_100")):
            body = {**_report(stage=stage), "detail": detail}
            assert client.post("/v1/report-failure", json=body, environ_base=PROXY,
                               headers={"X-Forwarded-For": addr}).status_code == 204
        assert _rows(tmp_path / "checks.db", "stage, detail") == [
            ("apply", "install_sh_exit_100"), ("preflight", "cosign_verify")]
        assert _held(client) is None
        summary = client.get("/v1/failures?version=0.2.1").get_json()
        assert (summary["total"], summary["reporters"]) == (2, 1)

    def test_one_network_stores_a_bounded_number_of_reports(self, make_client, tmp_path):
        make_client()
        db_path, now = tmp_path / "checks.db", datetime.now(timezone.utc)
        stored = [failure_store.record_failure(db_path, "0.2.1", "0.2.0", "apply",
                                               "198.51.100.0/24", now, f"reason {n}")
                  for n in range(failure_store.REPORTS_PER_REPORTER + 3)]
        assert stored == [True] * failure_store.REPORTS_PER_REPORTER + [False] * 3

    def test_box_ids_never_count_towards_auto_trip(self, make_client):
        """A box ID is whatever the sender puts in the body, so it is forgeable:
        counting it would let one network hold a release fleet-wide. Only the
        network prefix of the connection counts."""
        client = make_client(threshold="2")
        for n in range(3):
            body = {**_report(), "box_id": f"box-{n}", "detail": f"failure {n}"}
            client.post("/v1/report-failure", json=body, environ_base=PROXY,
                        headers={"X-Forwarded-For": f"198.51.100.{n + 1}"})
        assert _held(client) is None

    def test_enabling_auto_trip_warns_in_the_service_log(self, make_client, capsys):
        make_client(threshold="3")
        err = capsys.readouterr().err
        assert "CIRCUIT_BREAKER_AUTO_THRESHOLD=3" in err and "unauthenticated" in err

    def test_auto_trip_off_says_nothing(self, make_client, capsys):
        make_client()
        assert "CIRCUIT_BREAKER_AUTO_THRESHOLD" not in capsys.readouterr().err

    def test_concurrent_reports_from_one_reporter_store_one_row(self, make_client, tmp_path):
        make_client()  # creates the schema
        db_path = tmp_path / "checks.db"
        now = datetime.now(timezone.utc)
        barrier = threading.Barrier(8)
        results = []

        def report():
            barrier.wait()
            results.append(failure_store.record_failure(
                db_path, "0.2.1", "0.2.0", "apply", "198.51.100.0/24", now))

        threads = [threading.Thread(target=report) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert sorted(results) == [False] * 7 + [True]
        assert len(_rows(db_path)) == 1


class TestKnownVersions:
    def test_report_for_unlisted_version_is_rejected(self, make_client, tmp_path):
        client = make_client()
        resp = _post(client, "198.51.100.1", version="999.0.0")
        assert resp.status_code == 400
        assert "999.0.0" in resp.get_json()["error"]
        assert "releases.json" in resp.get_json()["error"]
        assert _rows(tmp_path / "checks.db") == []

    @pytest.mark.parametrize("stage", [["apply"], {"a": 1}, 3])
    def test_non_string_stage_is_rejected(self, make_client, stage):
        client = make_client()
        body = dict(_report(), stage=stage)
        assert client.post("/v1/report-failure", json=body).status_code == 400


def _insert_aged(db_path, *ages_and_reporters):
    now = datetime.now(timezone.utc)
    conn = sqlite3.connect(db_path)
    conn.executemany(
        "INSERT INTO failures (version, installed_from, stage, reported_at, reporter) "
        "VALUES ('0.2.1', '0.2.0', 'apply', ?, ?)",
        [((now - age).isoformat(), reporter) for age, reporter in ages_and_reporters])
    conn.commit()
    conn.close()


AGED = (
    (failure_store.RETENTION + timedelta(minutes=1), "198.51.7.0/24"),   # expired
    (failure_store.RETENTION - timedelta(days=1), "198.51.8.0/24"),      # kept
    (failure_store.REPORT_WINDOW + timedelta(minutes=1), "198.51.9.0/24"),  # kept
)
SWEPT = [("198.51.8.0/24",), ("198.51.9.0/24",)]


class TestRetention:
    def test_sweep_expires_reports_and_keeps_the_rest_with_their_prefix(self, migrated_db):
        _insert_aged(migrated_db, *AGED)
        retention.sweep(migrated_db, datetime.now(timezone.utc))
        assert _rows(migrated_db, "reporter") == SWEPT

    def test_a_reporter_outside_the_window_may_report_again(self, make_client, tmp_path):
        client = make_client()
        _post(client, "198.51.100.1")
        conn = sqlite3.connect(tmp_path / "checks.db")
        conn.execute("UPDATE failures SET reported_at = ?",
                     ((datetime.now(timezone.utc) - failure_store.REPORT_WINDOW
                       - timedelta(minutes=1)).isoformat(),))
        conn.commit()
        conn.close()
        _post(client, "198.51.100.1")
        assert len(_rows(tmp_path / "checks.db")) == 2

    def test_pre_start_step_sweeps(self, migrated_db):
        _insert_aged(migrated_db, *AGED)
        subprocess.run([sys.executable, "db_schema.py", str(migrated_db)],
                       cwd=SERVICE_DIR, check=True)
        assert _rows(migrated_db, "reporter") == SWEPT

    def test_workers_sweep_without_waiting_for_reports(self, migrated_db):
        _insert_aged(migrated_db, *AGED)
        sweeper = retention.Sweeper(migrated_db, timedelta(milliseconds=10))
        sweeper.start()
        try:
            deadline = time.monotonic() + 5
            while _rows(migrated_db, "reporter") != SWEPT and time.monotonic() < deadline:
                time.sleep(0.01)
        finally:
            sweeper.stop()
        assert _rows(migrated_db, "reporter") == SWEPT

    def test_app_starts_a_sweeper(self, make_client):
        client = make_client()
        sweeper = client.application.extensions["retention_sweeper"]
        assert sweeper.interval == retention.SWEEP_INTERVAL
        assert sweeper._thread.is_alive()

    def test_privacy_statement_matches_retention(self):
        """static/index.html is the published promise about reporter data."""
        text = " ".join((SERVICE_DIR / "static" / "index.html").read_text().split())
        assert failure_store.RETENTION == timedelta(days=90)
        assert retention.SWEEP_INTERVAL <= timedelta(minutes=5)
        assert "deleted after 90 days" in text

    @pytest.mark.parametrize("sql", [
        failure_store.WINDOW_SQL,
        failure_store.EXPIRE_SQL, failure_store.COUNT_SQL,
    ])
    def test_report_queries_use_an_index(self, make_client, tmp_path, sql):
        make_client()
        conn = sqlite3.connect(tmp_path / "checks.db")
        try:
            params = (None,) * sql.count("?")
            plan = " ".join(r[-1] for r in conn.execute(f"EXPLAIN QUERY PLAN {sql}", params))
        finally:
            conn.close()
        assert "USING" in plan and "INDEX" in plan, plan


LEGACY_SCHEMA = """
CREATE TABLE version_checks (date TEXT NOT NULL, version TEXT NOT NULL,
    count INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (date, version));
CREATE TABLE failures (id INTEGER PRIMARY KEY AUTOINCREMENT, version TEXT NOT NULL,
    installed_from TEXT NOT NULL, stage TEXT NOT NULL, reported_at TEXT NOT NULL,
    remote_addr TEXT);
CREATE TABLE circuit_breaker (version TEXT PRIMARY KEY, tripped INTEGER NOT NULL DEFAULT 1,
    tripped_by TEXT, tripped_at TEXT NOT NULL);
"""


class TestSchemaMigration:
    def _legacy_db(self, db_path):
        conn = sqlite3.connect(db_path)
        conn.executescript(LEGACY_SCHEMA)
        moment = datetime.now(timezone.utc)
        now = moment.isoformat()
        conn.executemany(
            "INSERT INTO failures (version, installed_from, stage, reported_at, remote_addr) "
            "VALUES ('0.2.1', '0.2.0', 'apply', ?, ?)",
            [(now, "2001:db8::5"), (now, "198.51.100.4"), (now, None),
             ((moment - timedelta(hours=7)).isoformat(), "198.51.100.5"),
             ((moment - timedelta(days=91)).isoformat(), None)])
        conn.execute("INSERT INTO circuit_breaker VALUES ('0.2.1', 1, 'api', ?)", (now,))
        conn.commit()
        conn.close()

    def test_legacy_database_is_migrated_in_place(self, tmp_path):
        db_path = tmp_path / "legacy.db"
        self._legacy_db(db_path)
        db_schema.migrate(db_path)
        assert _rows(db_path) == [
            ("0.2.1", "2001:db8::/48"), ("0.2.1", "198.51.100.0/24"), ("0.2.1", None),
            ("0.2.1", None)]
        conn = sqlite3.connect(db_path)
        try:
            assert conn.execute("PRAGMA user_version").fetchone()[0] == db_schema.SCHEMA_VERSION
            assert conn.execute("SELECT tripped_by FROM circuit_breaker").fetchall() == [("api",)]
        finally:
            conn.close()

    def test_migrated_and_fresh_schemas_match(self, tmp_path):
        legacy, fresh = tmp_path / "legacy.db", tmp_path / "fresh.db"
        self._legacy_db(legacy)
        db_schema.migrate(legacy)
        db_schema.migrate(fresh)

        def schema(path):
            conn = sqlite3.connect(path)
            try:
                return sorted(conn.execute(
                    "SELECT type, name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"))
            finally:
                conn.close()
        assert schema(legacy) == schema(fresh)
        assert ("index", "failures_by_reporter") in schema(fresh)

    def test_migrate_is_idempotent(self, migrated_db):
        failure_store.record_failure(migrated_db, "0.2.1", "0.2.0", "apply", "198.51.100.0/24",
                                     datetime.now(timezone.utc))
        db_schema.migrate(migrated_db)
        assert _rows(migrated_db) == [("0.2.1", "198.51.100.0/24")]

    def test_newer_database_refuses_to_migrate(self, migrated_db):
        conn = sqlite3.connect(migrated_db)
        conn.execute(f"PRAGMA user_version = {db_schema.SCHEMA_VERSION + 1}")
        conn.close()
        with pytest.raises(db_schema.SchemaError, match="newer"):
            db_schema.migrate(migrated_db)


class TestWorkersDoNotMigrate:
    """A worker that migrated could be killed mid-way by gunicorn's timeouts
    and roll back for ever; only the pre-start step migrates."""

    @pytest.mark.parametrize("version", [0, db_schema.SCHEMA_VERSION - 1,
                                         db_schema.SCHEMA_VERSION + 1])
    def test_worker_refuses_a_database_at_another_version(self, make_client, migrated_db,
                                                          version):
        conn = sqlite3.connect(migrated_db)
        conn.execute(f"PRAGMA user_version = {version}")
        conn.close()
        with pytest.raises(db_schema.SchemaError, match="run `python db_schema.py"):
            make_client()
        conn = sqlite3.connect(migrated_db)
        try:
            assert conn.execute("PRAGMA user_version").fetchone()[0] == version
        finally:
            conn.close()

    def test_worker_refuses_a_missing_database(self, make_client, migrated_db):
        migrated_db.unlink()
        with pytest.raises(db_schema.SchemaError, match="does not exist"):
            make_client()
        assert not migrated_db.exists()

    def test_image_migrates_once_before_gunicorn(self):
        import app
        cmd_line = next(line for line in (SERVICE_DIR / "Dockerfile").read_text().splitlines()
                        if line.startswith("CMD "))
        argv = json.loads(cmd_line[len("CMD "):])
        assert argv[:2] == ["sh", "-c"]
        assert argv[2].startswith(f"python db_schema.py {app.DB_PATH} && exec gunicorn ")
        assert "--preload" not in argv[2]

    def test_image_copies_every_service_module(self):
        """A module left out of the COPY line imports fine here and crashes
        every worker in the image."""
        dockerfile = (SERVICE_DIR / "Dockerfile").read_text().replace("\\\n", " ")
        copy = next(line for line in dockerfile.splitlines() if line.startswith("COPY admin_auth"))
        modules = {p.name for p in SERVICE_DIR.glob("*.py")}
        assert modules <= set(copy.split()), modules - set(copy.split())
