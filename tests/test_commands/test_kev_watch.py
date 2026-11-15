# SPDX-License-Identifier: Apache-2.0
"""The KEV watch: a newly listed CVE rescans the projects whose stored
findings contain it, and only those."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from boxmunge.commands import kev_watch
from boxmunge.cve.exploited import ExploitedIndex, ExploitedSource
from boxmunge.cve.kev import KevCatalog
from boxmunge.cve.kev_watch_state import WatchState, read_watch, write_watch
from boxmunge.fileutil import LockError
from boxmunge.health_checks.security import check_kev_watch_freshness
from boxmunge.state import StateError
from tests.test_commands.cve_helpers import make_box

NOW = datetime(2026, 11, 15, 12, 0, tzinfo=timezone.utc)
CISA = frozenset({ExploitedSource.CISA})


class Env:
    """A box with two deployed projects and stubbed refresh and rescan."""

    def __init__(self, paths, monkeypatch) -> None:
        self.paths = paths
        self.listed: set[str] = set()
        self.scanned: list[str] = []
        self.locked: set[str] = set()
        self.stale: dict = {}
        kev = KevCatalog(frozenset(), NOW, NOW, "https://kev.example/feed.json")
        monkeypatch.setattr(kev_watch, "refresh_kev_and_alert", lambda p, n: kev)
        monkeypatch.setattr(
            kev_watch, "load_exploited",
            lambda p, today, cisa=None: ExploitedIndex({c: CISA for c in self.listed}, self.stale))
        monkeypatch.setattr("boxmunge.commands.security_actions.scan_one_project", self._scan)

    def _scan(self, paths, project, **kw):
        if project in self.locked:
            raise LockError(project)
        self.scanned.append(project)
        return _Scan()

    def store(self, project: str, *cves: str) -> None:
        path = self.paths.project_scan_state(project)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"scanned_at": NOW.isoformat(), "decisions": [
            {"image_ref": f"{project}-web:1", "findings": [{"cve_id": c} for c in cves]}]}))

    def seen(self, *cves: str, at: datetime = NOW) -> None:
        write_watch(self.paths, WatchState(at, frozenset(cves)))

    def tick(self):
        return kev_watch.run_kev_watch(self.paths, NOW)


class _Scan:
    record_error = None
    warnings = ()
    lifted = kept = headline = None
    host_expired = ()
    complete = True
    decisions = ()


@pytest.fixture
def env(tmp_path, monkeypatch) -> Env:
    return Env(make_box(tmp_path, projects=("shop", "blog")), monkeypatch)


def test_new_listing_rescans_only_affected_projects(env) -> None:
    env.store("shop", "CVE-1", "CVE-2")
    env.store("blog", "CVE-3")
    env.seen("CVE-1")
    env.listed = {"CVE-1", "CVE-2", "CVE-3", "CVE-9"}
    result = env.tick()
    assert env.scanned == ["blog", "shop"]
    assert result.new_cves == {"CVE-2", "CVE-3", "CVE-9"}
    assert read_watch(env.paths).cve_ids == env.listed


def test_unaffected_new_listing_scans_nothing_but_is_recorded(env) -> None:
    env.store("shop", "CVE-1")
    env.seen("CVE-1")
    env.listed = {"CVE-1", "CVE-9"}
    env.tick()
    assert env.scanned == []
    assert "CVE-9" in read_watch(env.paths).cve_ids


def test_no_new_listing_does_no_scan(env) -> None:
    env.store("shop", "CVE-1")
    env.seen("CVE-1", at=NOW - timedelta(minutes=30))
    env.listed = {"CVE-1"}
    env.tick()
    assert env.scanned == []
    assert read_watch(env.paths).seen_at == NOW  # the tick is the heartbeat


def test_first_run_records_the_set_and_rescans_nothing(env) -> None:
    env.store("shop", "CVE-1")
    env.listed = {"CVE-1"}
    env.tick()
    assert env.scanned == []
    assert read_watch(env.paths).cve_ids == {"CVE-1"}


def test_busy_project_is_retried_next_tick(env) -> None:
    env.store("shop", "CVE-2")
    env.store("blog", "CVE-3")
    env.seen("CVE-1")
    env.listed = {"CVE-1", "CVE-2", "CVE-3"}
    env.locked = {"shop"}
    result = env.tick()
    assert result.busy == ("shop",) and not result.failed
    assert read_watch(env.paths).cve_ids == {"CVE-1", "CVE-3"}
    env.locked = set()
    env.scanned.clear()
    env.tick()
    assert env.scanned == ["shop"]
    assert read_watch(env.paths).cve_ids == env.listed


def test_crash_before_set_write_reprocesses(env, monkeypatch) -> None:
    env.store("shop", "CVE-2")
    env.seen("CVE-1")
    env.listed = {"CVE-1", "CVE-2"}

    def crash(paths, state):
        raise StateError("disk full")

    monkeypatch.setattr(kev_watch, "write_watch", crash)
    with pytest.raises(StateError):
        env.tick()
    assert read_watch(env.paths).cve_ids == {"CVE-1"}
    monkeypatch.undo()
    env2 = Env(env.paths, monkeypatch)
    env2.listed = env.listed
    env2.tick()
    assert env2.scanned == ["shop"]


def test_a_source_going_stale_does_not_make_its_cves_new_again(env) -> None:
    env.store("shop", "CVE-2")
    env.seen("CVE-1", "CVE-2")
    env.listed = {"CVE-1"}  # CVE-2's source is stale now
    env.tick()
    env.listed = {"CVE-1", "CVE-2"}  # and back
    env.tick()
    assert env.scanned == []


def test_project_without_stored_scan_is_skipped(env) -> None:
    env.seen("CVE-1")
    env.listed = {"CVE-1", "CVE-2"}
    env.tick()
    assert env.scanned == []


def test_malformed_watch_record_is_a_state_error(env) -> None:
    env.paths.kev_watch.parent.mkdir(parents=True, exist_ok=True)
    env.paths.kev_watch.write_text('{"seen_at": "x"')
    with pytest.raises(StateError, match="watch.json"):
        env.tick()


def _box(tmp_path, monkeypatch, kev_block):
    import yaml
    from boxmunge.health_checks import security
    paths = make_box(tmp_path)
    paths.config_file.write_text(yaml.safe_dump({"hostname": "box.example.com", "admin_email": "ops@example.com", "kev": kev_block}))
    timer = tmp_path / "kev-watch.timer"
    timer.write_text("")
    old = NOW.timestamp() - 3600 * 5
    import os
    os.utime(timer, (old, old))
    monkeypatch.setattr(security, "KEV_WATCH_TIMER", timer)
    return paths


EU_OFF = {"sources": ["https://kev.example/feed.json"], "enisa": {"enabled": False}}


def test_watch_freshness_warns_after_two_missed_ticks(tmp_path, monkeypatch) -> None:
    paths = _box(tmp_path, monkeypatch, EU_OFF)
    never = check_kev_watch_freshness(paths, now=NOW)
    assert never.status == "warn" and "never run" in never.detail
    write_watch(paths, WatchState(NOW - timedelta(minutes=70), frozenset()))
    assert check_kev_watch_freshness(paths, now=NOW).status == "ok"
    write_watch(paths, WatchState(NOW - timedelta(minutes=80), frozenset()))
    check = check_kev_watch_freshness(paths, now=NOW)
    assert check.status == "warn" and "80 minutes" in check.detail


def test_watch_freshness_without_the_timer_installed_is_quiet(tmp_path, monkeypatch) -> None:
    paths = _box(tmp_path, monkeypatch, EU_OFF)
    monkeypatch.setattr("boxmunge.health_checks.security.KEV_WATCH_TIMER", tmp_path / "absent")
    assert check_kev_watch_freshness(paths, now=NOW).status == "ok"


def test_watch_freshness_names_a_stale_optional_source(tmp_path, monkeypatch) -> None:
    paths = _box(tmp_path, monkeypatch, {"sources": ["https://kev.example/feed.json"]})
    write_watch(paths, WatchState(NOW, frozenset()))
    check = check_kev_watch_freshness(paths, now=NOW)
    assert check.status == "warn" and "eu_kev not usable: never fetched" in check.detail
    assert "cisa_kev" not in check.detail  # CISA staleness has its own alert


def test_deploy_shell_refuses_kev_watch(capsys) -> None:
    from boxmunge.shell import run_command
    assert run_command("security", ["kev-watch"]) == 1
    assert "operator-only" in capsys.readouterr().err
