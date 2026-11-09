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
        assert "dropped 2 new network prefixes" in capsys.readouterr().err
        log.record("198.51.1.0/24", "9.9.9")  # a known prefix is still recorded
        log.flush()
        assert ("unlisted" in [row[2] for row in _sightings(migrated_db)])


class TestPurge:
    def test_sightings_older_than_90_days_are_purged(self, migrated_db):
        today = _today()
        _seed(migrated_db, [((today - timedelta(days=age)).isoformat(), f"198.51.{age}.0/24",
                             "0.2.0") for age in (0, 89, 90, 91)])
        retention.sweep(migrated_db, datetime.now(timezone.utc))
        assert sorted(row[1] for row in _sightings(migrated_db)) == [
            "198.51.0.0/24", "198.51.89.0/24"]

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


class TestMigration:
    def _db_at_version_4(self, path):
        db_schema.migrate(path)
        conn = sqlite3.connect(path)
        now = datetime.now(timezone.utc).isoformat()
        conn.execute("DROP TABLE prefix_checks")
        conn.executemany(
            "INSERT INTO failures (version, installed_from, stage, reported_at, reporter) "
            "VALUES ('0.2.1', '0.2.0', 'apply', ?, ?)",
            [(now, "198.51.100.4"), (now, "2001:db8:5:6::/64"), (now, "unknown"), (now, None)])
        conn.execute("INSERT INTO admin_challenges VALUES (x'01', 'login', '198.51.100.4', 1)")
        # A reporter forgotten before this release: deleted, but its bytes
        # stay in the file's free space until something overwrites them.
        conn.execute("INSERT INTO failures (version, installed_from, stage, reported_at, "
                     "reporter) VALUES ('0.2.1', '0.2.0', 'apply', ?, '198.51.100.99')", (now,))
        conn.execute("DELETE FROM failures WHERE reporter = '198.51.100.99'")
        conn.execute("PRAGMA user_version = 4")
        conn.commit()
        conn.close()

    def test_stored_addresses_become_prefixes(self, tmp_path):
        path = tmp_path / "v4.db"
        self._db_at_version_4(path)
        db_schema.prepare(path, datetime.now(timezone.utc))
        conn = sqlite3.connect(path)
        try:
            assert [r[0] for r in conn.execute("SELECT reporter FROM failures ORDER BY id")] == [
                "198.51.100.0/24", "2001:db8:5::/48", None, None]
            assert conn.execute("SELECT COUNT(*) FROM admin_challenges").fetchone()[0] == 0
            assert conn.execute("SELECT COUNT(*) FROM prefix_checks").fetchone()[0] == 0
        finally:
            conn.close()
        raw = path.read_bytes()
        assert b"198.51.100.4" not in raw and b"198.51.100.99" not in raw


class TestPrivacyStatement:
    """static/index.html is the published promise; it must match the code."""

    def _text(self) -> str:
        return " ".join((SERVICE_DIR / "static" / "index.html").read_text().split())

    def test_states_what_is_stored_and_for_how_long(self):
        text = self._text()
        assert prefix_store.RETENTION_DAYS == 90
        assert "/24" in text and "/48" in text
        assert "90 days" in text
        assert "never stored" in text

    def test_states_that_the_web_server_logs_full_addresses(self):
        assert "access log" in self._text()
        assert "full IP address" in self._text()

    def test_no_longer_claims_no_addresses_are_stored(self):
        assert "No IP addresses" not in self._text()

    def test_the_service_keeps_no_request_log_of_its_own(self):
        """The full address is in Caddy's access log only; gunicorn's would
        be a second, unannounced copy."""
        cmd = next(line for line in (SERVICE_DIR / "Dockerfile").read_text().splitlines()
                   if line.startswith("CMD "))
        assert "access-logfile" not in cmd

