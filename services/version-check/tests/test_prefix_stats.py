"""Network prefixes of checking boxes: computed, stored without the address, purged.

During the early beta the maintainer sees which network (IPv4 /24, IPv6 /48)
runs which version, to nudge people off old releases. The full address is
never written to the database: not for checks, failure reports or passkey
challenges.
"""

import json
import sqlite3
import subprocess
import sys
import time
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import db_schema  # noqa: E402
import prefix_store  # noqa: E402
import retention  # noqa: E402

SERVICE_DIR = Path(__file__).parent.parent
PROXY = {"REMOTE_ADDR": "172.18.0.2"}  # Caddy's address on the project network
SECRET = "prefix-secret-0123456789abcdef01234567"


def _via_proxy(addr: str) -> dict:
    return {"environ_base": PROXY, "headers": {"X-Forwarded-For": addr}}


@pytest.fixture
def make_app(tmp_path, migrated_db):
    releases_file = tmp_path / "releases.json"
    releases_file.write_text(json.dumps({"releases": [
        {"version": "0.2.1", "class": "security", "breaking": False,
         "url": "https://github.com/boxmunge/boxmunge/releases/tag/v0.2.1"},
        {"version": "0.2.0", "class": "feature", "breaking": False,
         "url": "https://github.com/boxmunge/boxmunge/releases/tag/v0.2.0"},
    ]}))
    with patch("app.RELEASES_PATH", releases_file), patch("app.DB_PATH", migrated_db):
        from app import create_app

        def build():
            application = create_app()
            application.config["TESTING"] = True
            application.config["STATS_SECRET"] = SECRET
            return application
        yield build


def _sightings(db_path) -> list[tuple]:
    conn = sqlite3.connect(db_path)
    try:
        return conn.execute(
            "SELECT date, prefix, version FROM prefix_checks ORDER BY date, prefix, version"
        ).fetchall()
    finally:
        conn.close()


def _seed(db_path, rows) -> None:
    conn = sqlite3.connect(db_path)
    conn.executemany("INSERT INTO prefix_checks (date, prefix, version) VALUES (?, ?, ?)", rows)
    conn.commit()
    conn.close()


def _today() -> date:
    return datetime.now(timezone.utc).date()


class TestNetworkPrefix:
    @pytest.mark.parametrize("addr, prefix", [
        ("198.51.100.77", "198.51.100.0/24"),
        ("203.0.113.0", "203.0.113.0/24"),
        ("2001:db8:1:2:3:4:5:6", "2001:db8:1::/48"),
        ("2001:db8:ffff::1", "2001:db8:ffff::/48"),
        ("::ffff:198.51.100.77", "198.51.100.0/24"),
        # 6to4: the /48 is 2002: plus the whole IPv4 address, so use its /24.
        ("2002:c633:644d::1", "198.51.100.0/24"),
        ("2002:c633:644d:1:2:3:4:5", "198.51.100.0/24"),
    ])
    def test_prefix(self, addr, prefix):
        assert prefix_store.network_prefix(addr) == prefix

    @pytest.mark.parametrize("addr", [None, "", "unknown", "198.51.100", "not-an-ip"])
    def test_anything_but_an_address_is_refused(self, addr):
        with pytest.raises(ValueError, match="not an IP address"):
            prefix_store.network_prefix(addr)


class TestChecksStorePrefixes:
    def test_check_stores_prefix_version_and_date(self, make_app, migrated_db):
        app = make_app()
        client = app.test_client()
        client.get("/v1/check?v=0.2.0", **_via_proxy("198.51.100.77"))
        client.get("/v1/check?v=0.2.1", **_via_proxy("2001:db8:1:2::9"))
        app.extensions["prefix_log"].flush()
        today = _today().isoformat()
        assert _sightings(migrated_db) == [
            (today, "198.51.100.0/24", "0.2.0"), (today, "2001:db8:1::/48", "0.2.1")]

    def test_repeat_checks_store_one_row(self, make_app, migrated_db):
        app = make_app()
        client = app.test_client()
        for addr in ("198.51.100.1", "198.51.100.2", "198.51.100.1"):
            client.get("/v1/check?v=0.2.0", **_via_proxy(addr))
        app.extensions["prefix_log"].flush()
        assert len(_sightings(migrated_db)) == 1

    def test_unlisted_versions_are_stored_as_unlisted(self, make_app, migrated_db):
        """Any valid X.Y.Z is accepted, so storing it verbatim would let one
        client grow the table by cycling versions."""
        app = make_app()
        client = app.test_client()
        for v in ("9.9.1", "9.9.2", "9.9.3"):
            client.get(f"/v1/check?v={v}", **_via_proxy("198.51.100.1"))
        app.extensions["prefix_log"].flush()
        assert [row[2] for row in _sightings(migrated_db)] == ["unlisted"]

    def test_failure_report_stores_the_reporter_prefix(self, make_app, migrated_db):
        client = make_app().test_client()
        body = {"version": "0.2.1", "installed_from": "0.2.0", "stage": "apply"}
        assert client.post("/v1/report-failure", json=body,
                           **_via_proxy("198.51.100.77")).status_code == 204
        conn = sqlite3.connect(migrated_db)
        try:
            assert conn.execute("SELECT version, reporter FROM failures").fetchall() == [
                ("0.2.1", "198.51.100.0/24")]
        finally:
            conn.close()


class TestClientAddressCannotBeSpoofed:
    """Caddy sets X-Forwarded-For to the address it saw (and, configured to
    trust no proxy, discards what the client sent); only that last entry counts."""

    def test_a_client_supplied_forwarded_for_entry_is_ignored(self, make_app, migrated_db):
        app = make_app()
        app.test_client().get("/v1/check?v=0.2.0", environ_base=PROXY,
                              headers={"X-Forwarded-For": "10.9.9.9, 198.51.100.77"})
        app.extensions["prefix_log"].flush()
        assert [row[1] for row in _sightings(migrated_db)] == ["198.51.100.0/24"]

    @pytest.mark.parametrize("header", ["X-Real-IP", "Forwarded", "Client-IP",
                                        "True-Client-IP", "CF-Connecting-IP"])
    def test_other_address_headers_are_ignored(self, make_app, migrated_db, header):
        app = make_app()
        value = "for=10.9.9.9" if header == "Forwarded" else "10.9.9.9"
        app.test_client().get("/v1/check?v=0.2.0", environ_base=PROXY,
                              headers={"X-Forwarded-For": "198.51.100.77", header: value})
        app.extensions["prefix_log"].flush()
        assert [row[1] for row in _sightings(migrated_db)] == ["198.51.100.0/24"]


class TestNoFullAddressInTheDatabase:
    ADDRESSES = ("198.51.100.77", "2001:db8:1:2:3:4:5:6")

    def test_no_full_address_is_written_anywhere(self, make_app, migrated_db):
        app = make_app()
        client = app.test_client()
        body = {"version": "0.2.1", "installed_from": "0.2.0", "stage": "apply"}
        for addr in self.ADDRESSES:
            client.get("/v1/check?v=0.2.0", **_via_proxy(addr))
            client.post("/v1/report-failure", json=body, **_via_proxy(addr))
            client.post("/v1/admin/register/options", json={"code": SECRET},
                        **_via_proxy(addr))
        app.extensions["prefix_log"].flush()
        app.extensions["check_counter"].flush()
        conn = sqlite3.connect(migrated_db)
        try:
            dump = "\n".join(conn.iterdump())
            assert conn.execute("SELECT COUNT(*) FROM admin_challenges").fetchone()[0] == 2
        finally:
            conn.close()
        raw = migrated_db.read_bytes()
        assert "198.51.100.0/24" in dump and "2001:db8:1::/48" in dump
        for fragment in ("198.51.100.77", "2001:db8:1:2"):
            assert fragment not in dump
            assert fragment.encode() not in raw


class TestDailyPrefixCap:
    def test_new_prefixes_beyond_the_cap_are_dropped_loudly(self, migrated_db, capsys):
        log = prefix_store.PrefixLog(migrated_db, 60, 1000, frozenset({"0.2.0"}),
                                     max_prefixes_per_day=2)
        for third in (1, 2, 3, 4):
            log.record(f"198.51.{third}.0/24", "0.2.0")
        log.record("198.51.1.0/24", "0.2.0")
        log.flush()
        assert [row[1] for row in _sightings(migrated_db)] == ["198.51.1.0/24", "198.51.2.0/24"]
        assert "dropped 2 sighting(s) beyond the daily caps" in capsys.readouterr().err
        log.record("198.51.1.0/24", "9.9.9")  # a known prefix is still recorded
        log.flush()
        assert ("unlisted" in [row[2] for row in _sightings(migrated_db)])

    def test_the_version_cap_keeps_the_oldest_versions_in_numeric_order(self, migrated_db):
        listed = frozenset({"0.9.0", "0.10.0", "0.11.0"})
        log = prefix_store.PrefixLog(migrated_db, 60, 1000, listed, max_versions_per_prefix=2)
        for v in ("0.11.0", "0.10.0", "0.9.0"):
            log.record("198.51.1.0/24", v)
        log.flush()
        assert sorted(r[2] for r in _sightings(migrated_db)) == ["0.10.0", "0.9.0"]

    def test_versions_beyond_the_cap_for_a_prefix_are_dropped_loudly(self, migrated_db, capsys):
        listed = frozenset({"0.2.0", "0.2.1", "0.2.2", "0.2.3"})
        log = prefix_store.PrefixLog(migrated_db, 60, 1000, listed, max_versions_per_prefix=2)
        for v in ("0.2.0", "0.2.1", "0.2.2"):
            log.record("198.51.1.0/24", v)
        log.flush()
        log.record("198.51.1.0/24", "0.2.3")   # a later flush still sees the cap
        log.record("198.51.1.0/24", "0.2.0")   # a version already stored is fine
        log.record("198.51.2.0/24", "0.2.3")   # another prefix has its own cap
        log.flush()
        assert _sightings(migrated_db)[0][0] == _today().isoformat()
        assert [(r[1], r[2]) for r in _sightings(migrated_db)] == [
            ("198.51.1.0/24", "0.2.0"), ("198.51.1.0/24", "0.2.1"), ("198.51.2.0/24", "0.2.3")]
        assert capsys.readouterr().err.count("dropped 1 sighting(s)") == 2


class TestPurge:
    def test_sightings_older_than_90_days_are_purged(self, migrated_db):
        today = _today()
        _seed(migrated_db, [((today - timedelta(days=age)).isoformat(), f"198.51.{age}.0/24",
                             "0.2.0") for age in (0, 89, 90, 91)])
        retention.sweep(migrated_db, datetime.now(timezone.utc))
        assert sorted(row[1] for row in _sightings(migrated_db)) == [
            "198.51.0.0/24", "198.51.89.0/24"]

    def test_expired_rows_are_gone_from_the_file_bytes(self, migrated_db):
        old = datetime.now(timezone.utc) - timedelta(days=120)
        _seed(migrated_db, [(old.date().isoformat(), "203.0.113.0/24", "0.2.0")])
        conn = sqlite3.connect(migrated_db)
        conn.execute("INSERT INTO failures (version, installed_from, stage, detail, reported_at, "
                     "reporter) VALUES ('0.2.1', '0.2.0', 'apply', 'expired-detail-marker', ?, "
                     "'192.0.2.0/24')", (old.isoformat(),))
        conn.commit()
        conn.close()
        assert b"203.0.113.0/24" in migrated_db.read_bytes()
        retention.sweep(migrated_db, datetime.now(timezone.utc))
        raw = migrated_db.read_bytes()
        for gone in (b"203.0.113.0/24", b"192.0.2.0/24", b"expired-detail-marker"):
            assert gone not in raw

    def test_pre_start_step_purges(self, migrated_db):
        _seed(migrated_db, [((_today() - timedelta(days=120)).isoformat(),
                             "198.51.100.0/24", "0.2.0")])
        subprocess.run([sys.executable, "db_schema.py", str(migrated_db)],
                       cwd=SERVICE_DIR, check=True)
        assert _sightings(migrated_db) == []

    def test_workers_purge_on_a_schedule(self, migrated_db):
        _seed(migrated_db, [((_today() - timedelta(days=120)).isoformat(),
                             "198.51.100.0/24", "0.2.0")])
        sweeper = retention.Sweeper(migrated_db, timedelta(milliseconds=10))
        sweeper.start()
        try:
            deadline = time.monotonic() + 5
            while _sightings(migrated_db) and time.monotonic() < deadline:
                time.sleep(0.01)
        finally:
            sweeper.stop()
        assert _sightings(migrated_db) == []

    def test_each_tick_flushes_buffers_even_if_one_flush_fails(self, migrated_db):
        flushed = []

        def broken():
            raise RuntimeError("disk full")
        sweeper = retention.Sweeper(migrated_db, timedelta(milliseconds=10),
                                    flushes=(broken, lambda: flushed.append(1)))
        sweeper.start()
        try:
            deadline = time.monotonic() + 5
            while not flushed and time.monotonic() < deadline:
                time.sleep(0.01)
        finally:
            sweeper.stop()
        assert flushed

    def test_app_sweeper_flushes_the_check_counter_and_prefix_log(self, make_app):
        app = make_app()
        sweeper = app.extensions["retention_sweeper"]
        assert sweeper.flushes == (app.extensions["check_counter"].flush,
                                   app.extensions["prefix_log"].flush)

    def test_purge_uses_an_index(self, migrated_db):
        conn = sqlite3.connect(migrated_db)
        try:
            plan = " ".join(r[-1] for r in conn.execute(
                f"EXPLAIN QUERY PLAN {prefix_store.PURGE_SQL}", (None,)))
        finally:
            conn.close()
        assert "USING" in plan and "INDEX" in plan, plan


class TestAdminPrefixTable:
    @pytest.fixture
    def session(self, migrated_db):
        import admin_auth
        import webauthn_store
        value = admin_auth.session_cookie_value(SECRET, webauthn_store.session_key(migrated_db))
        return {"Cookie": f"{admin_auth.SESSION_COOKIE}={value}"}

    def _page(self, make_app, session) -> str:
        client = make_app().test_client(use_cookies=False)
        return client.get("/v1/admin/stats", headers=session).get_data(as_text=True)

    def test_table_shows_prefix_latest_version_first_and_last_seen(
            self, make_app, migrated_db, session):
        today = _today()
        d = [(today - timedelta(days=n)).isoformat() for n in range(4)]
        _seed(migrated_db, [
            (d[3], "198.51.100.0/24", "0.2.0"), (d[1], "198.51.100.0/24", "0.2.1"),
            (d[2], "2001:db8:1::/48", "0.2.0"),
        ])
        html = self._page(make_app, session)
        assert "<th class=\"l\">network prefix</th>" in html
        assert (f'<tr><td class="l">198.51.100.0/24</td><td class="l">0.2.1</td>'
                f'<td class="l">{d[3]}</td><td class="l">{d[1]}</td></tr>') in html
        assert (f'<tr><td class="l">2001:db8:1::/48</td><td class="l">0.2.0</td>'
                f'<td class="l">{d[2]}</td><td class="l">{d[2]}</td></tr>') in html
        # Most recently seen first.
        assert html.index("198.51.100.0/24") < html.index("2001:db8:1::/48")

    def test_every_version_seen_on_the_last_day_is_shown(self, make_app, migrated_db, session):
        today = _today().isoformat()
        _seed(migrated_db, [(today, "198.51.100.0/24", v) for v in ("0.2.1", "unlisted", "0.2.0")])
        assert '<td class="l">0.2.0, 0.2.1, unlisted</td>' in self._page(make_app, session)

    def test_a_check_appears_on_the_page_straight_away(self, make_app, migrated_db, session):
        app = make_app()
        app.test_client().get("/v1/check?v=0.2.0", **_via_proxy("198.51.100.77"))
        page = app.test_client(use_cookies=False).get("/v1/admin/stats", headers=session)
        assert "198.51.100.0/24" in page.get_data(as_text=True)

    def test_failure_reports_show_their_prefix(self, make_app, migrated_db, session):
        app = make_app()
        body = {"version": "0.2.1", "installed_from": "0.2.0", "stage": "apply"}
        app.test_client().post("/v1/report-failure", json=body, **_via_proxy("198.51.100.77"))
        html = app.test_client(use_cookies=False).get(
            "/v1/admin/stats", headers=session).get_data(as_text=True)
        failures = html[html.index("Recent failure reports"):]
        assert '<td class="l">198.51.100.0/24</td>' in failures

    def test_empty_state(self, make_app, session):
        assert "No boxes checked in the last 90 days." in self._page(make_app, session)

    def test_long_tables_are_cut_and_say_so(self, make_app, migrated_db, session):
        today = _today().isoformat()
        _seed(migrated_db, [(today, f"198.51.{n}.0/24", "0.2.0") for n in range(3)])
        with patch("app.PREFIXES_SHOWN", 2):
            html = self._page(make_app, session)
        assert "Boxes by network prefix (2 of 3)" in html

    def test_stored_text_is_escaped(self, make_app, migrated_db, session):
        _seed(migrated_db, [(_today().isoformat(), "<b>p</b>", "0.2.0")])
        html = self._page(make_app, session)
        assert "<b>p</b>" not in html and "&lt;b&gt;p&lt;/b&gt;" in html


def _v4_database(path, residue: bool = True) -> None:
    """A database as release 4 of the schema left it, holding full addresses."""
    conn = sqlite3.connect(path, isolation_level=None)  # secure_delete off, as before
    for step in db_schema.MIGRATIONS[:4]:
        step(conn)
    now = datetime.now(timezone.utc).isoformat()
    conn.executemany(
        "INSERT INTO failures (version, installed_from, stage, reported_at, reporter) "
        "VALUES ('0.2.1', '0.2.0', 'apply', ?, ?)",
        [(now, "198.51.100.4"), (now, "2001:db8:5:6::/64"), (now, "unknown"), (now, None)])
    conn.execute("INSERT INTO admin_challenges VALUES (x'01', 'login', '198.51.100.5', 1)")
    if residue:
        # A reporter forgotten by an earlier release: deleted, but its bytes
        # stay in the file's free space until something overwrites them.
        conn.execute("INSERT INTO failures (version, installed_from, stage, reported_at, "
                     "reporter) VALUES ('0.2.1', '0.2.0', 'apply', ?, '198.51.100.99')", (now,))
        conn.execute("DELETE FROM failures WHERE reporter = '198.51.100.99'")
    conn.execute("PRAGMA user_version = 4")
    conn.close()


def _scalar(path, sql):
    conn = sqlite3.connect(path)
    try:
        return conn.execute(sql).fetchone()[0]
    finally:
        conn.close()


class TestMigration:
    def test_stored_addresses_become_prefixes(self, tmp_path, capsys):
        path = tmp_path / "v4.db"
        _v4_database(path)
        db_schema.prepare(path, datetime.now(timezone.utc))
        conn = sqlite3.connect(path)
        try:
            assert [r[0] for r in conn.execute("SELECT reporter FROM failures ORDER BY id")] == [
                "198.51.100.0/24", "2001:db8:5::/48", None, None]
            assert conn.execute("SELECT COUNT(*) FROM admin_challenges").fetchone()[0] == 0
            assert "client" not in [r[1] for r in conn.execute(
                "PRAGMA table_info(admin_challenges)")]
            assert conn.execute("SELECT COUNT(*) FROM prefix_checks").fetchone()[0] == 0
        finally:
            conn.close()
        assert "cleared 1 failure reporter(s) that were not IP addresses" in capsys.readouterr().out
        raw = path.read_bytes()
        for addr in (b"198.51.100.4", b"198.51.100.5", b"198.51.100.99", b"2001:db8:5:6"):
            assert addr not in raw

    def test_an_interrupted_first_start_still_vacuums(self, tmp_path):
        """migrate() commits schema version 5 before the VACUUM; a start cut
        off between the two must vacuum on the next start."""
        path = tmp_path / "v4.db"
        _v4_database(path)
        db_schema.migrate(path)  # the first start dies here
        assert _scalar(path, "SELECT COUNT(*) FROM pending_vacuum") == 1
        db_schema.prepare(path, datetime.now(timezone.utc))
        assert _scalar(path, "SELECT COUNT(*) FROM pending_vacuum") == 0
        assert b"198.51.100.99" not in path.read_bytes()

    def test_migrate_alone_zeroes_the_addresses_it_replaces(self, tmp_path):
        path = tmp_path / "v4.db"
        _v4_database(path, residue=False)
        db_schema.migrate(path)
        raw = path.read_bytes()
        for addr in (b"198.51.100.4", b"198.51.100.5", b"2001:db8:5:6"):
            assert addr not in raw

    def test_every_connection_zeroes_what_it_frees(self, migrated_db):
        import db
        conn = db.connect(migrated_db)
        try:
            assert conn.execute("PRAGMA secure_delete").fetchone()[0] == 1
        finally:
            conn.close()


class TestPrivacyStatement:
    """static/index.html is the published promise; it must match the code."""

    def _text(self) -> str:
        return " ".join((SERVICE_DIR / "static" / "index.html").read_text().split())

    def test_states_what_is_stored_and_for_how_long(self):
        text = self._text()
        assert prefix_store.RETENTION_DAYS == 90
        assert "/24" in text and "/48" in text
        assert "90 days" in text
        assert "never stored in the service's database" in text

    def test_states_that_the_web_server_logs_full_addresses(self):
        assert "Request logs:" in self._text()
        assert "full IP address" in self._text()

    def test_states_what_the_code_does_with_deleted_and_embedded_addresses(self):
        text = self._text()
        assert "Deleted data is overwritten in the database file" in text  # db.connect
        assert "embeds an IPv4 address counts as that IPv4 address" in text  # 6to4, mapped
        assert "A prefix is not anonymous" in text
        assert "Backups taken before this service switched to prefixes" in text
        assert "shared with CrowdSec's community blocklist service" in text

    def test_no_longer_claims_no_addresses_are_stored(self):
        assert "No IP addresses" not in self._text()

    def test_states_that_both_request_logs_keep_full_addresses(self):
        """gunicorn's access log, like Caddy's, records full addresses; the
        statement must name both and their rotation."""
        cmd = next(line for line in (SERVICE_DIR / "Dockerfile").read_text().splitlines()
                   if line.startswith("CMD "))
        assert "--access-logfile -" in cmd
        text = self._text()
        assert "never stored in the service's database" in text
        assert "the service itself each log every request, with the full IP address" in text
        assert "five files of 50&nbsp;MB" in text
