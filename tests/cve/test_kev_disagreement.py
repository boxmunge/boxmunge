# SPDX-License-Identifier: Apache-2.0
"""Sources that disagree: an earlier-ranked source serves a catalog older
than the cached one, from a later source, and lacks CVEs it lists (CVE-03).

That is a lagging source, not CISA withdrawing entries, so the catalog is
not rolled back: the later sources are tried and the one that agrees with
the cache is kept, with a notice; if none answers, the cache is kept and
the operator alerted. An earlier source that is older but drops nothing is
still accepted, so a later one stamping a newer date cannot lock it out.

Offline: urlopen is stubbed per URL.
"""
from __future__ import annotations

import json
import urllib.error
from datetime import datetime, timedelta, timezone

from boxmunge.commands import security_actions, security_kev, security_scan_core
from boxmunge.cve import kev_refresh
from boxmunge.cve.kev import KEV_DEFAULT_SOURCES, load_kev
from boxmunge.cve.kev_refresh import (
    DISAGREES, REJECTED, UNREACHABLE, refresh_from, refresh_kev,
)
from boxmunge.cve.kev_source_history import load_history
from boxmunge.cve.kev_withdrawals import load_withdrawals
from boxmunge.paths import BoxPaths
from tests.test_commands.cve_helpers import Pushover, make_box, scan_result

CISA = KEV_DEFAULT_SOURCES[0]
OWN = "https://kev-mirror.example/kev.json"  # ranked first in kev.sources
SOURCES = (OWN, CISA)
NEW = ["CVE-2026-7001", "CVE-2026-7002"]  # added by CISA since OWN last synced
NOW = datetime.now(timezone.utc)
CACHED_AT = (NOW - timedelta(days=1)).isoformat()
LAGGED_AT = (NOW - timedelta(days=4)).isoformat()


class _Resp:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read1(self, limit: int = -1) -> bytes:
        body, self._body = self._body, b""
        return body


def _ids(n: int = 1400) -> list[str]:
    return [f"CVE-2020-{i:05d}" for i in range(n)]


def _feed(ids: list[str], released: str) -> bytes:
    return json.dumps({"dateReleased": released,
                       "vulnerabilities": [{"cveID": c} for c in ids]}).encode()


def _serve(monkeypatch, answers: dict) -> None:
    def open_(req):
        answer = answers[req.full_url]
        if isinstance(answer, Exception):
            raise answer
        return _Resp(answer)
    monkeypatch.setattr(kev_refresh, "_open", open_)


def _cache_from_cisa(paths: BoxPaths) -> None:
    """OWN served LAGGED_AT before; it was down last night, and CISA
    answered with the newest catalog."""
    paths.kev_catalog.parent.mkdir(parents=True, exist_ok=True)
    paths.kev_catalog.write_text(json.dumps({
        "source": CISA, "released_at": CACHED_AT, "fetched_at": CACHED_AT,
        "cve_ids": _ids() + NEW}))
    paths.kev_sources.write_text(json.dumps({"sources": {
        OWN: {"released_at": LAGGED_AT, "disagreed_runs": 0},
        CISA: {"released_at": CACHED_AT, "disagreed_runs": 0}}}))


def test_a_lagging_earlier_source_does_not_roll_the_catalog_back(tmp_path, monkeypatch):
    paths = BoxPaths(root=tmp_path)
    _cache_from_cisa(paths)
    _serve(monkeypatch, {OWN: _feed(_ids(), LAGGED_AT), CISA: _feed(_ids() + NEW, CACHED_AT)})
    result = refresh_from(paths, SOURCES)
    assert result.source == CISA and result.withdrawn == ()
    [failure] = result.failures
    assert (failure.source, failure.kind) == (OWN, DISAGREES)
    assert "lacks 2 of its CVEs (CVE-2026-7001, CVE-2026-7002)" in failure.error
    assert set(NEW) <= load_kev(paths).cve_ids
    assert load_withdrawals(paths) == {}


def test_with_no_later_source_answering_the_cache_is_kept_and_alerted(tmp_path, monkeypatch):
    paths = BoxPaths(root=tmp_path)
    _cache_from_cisa(paths)
    _serve(monkeypatch, {OWN: _feed(_ids(), LAGGED_AT), CISA: urllib.error.HTTPError(
        CISA, 403, "Forbidden", None, None)})
    result = refresh_from(paths, SOURCES)
    assert result.source is None and result.needs_alert
    assert [f.kind for f in result.failures] == [DISAGREES, UNREACHABLE]
    cat = load_kev(paths)
    assert cat.source == CISA and set(NEW) <= cat.cve_ids


def test_an_older_earlier_source_dropping_nothing_is_still_accepted(tmp_path, monkeypatch):
    """Ranking holds when the sources agree on content: a later source that
    stamps a newer date cannot lock the earlier one out."""
    paths = BoxPaths(root=tmp_path)
    _cache_from_cisa(paths)
    _serve(monkeypatch, {OWN: _feed(_ids() + NEW + ["CVE-2026-7003"], LAGGED_AT)})
    result = refresh_from(paths, SOURCES)
    assert result.source == OWN and result.failures == ()
    assert load_kev(paths).source == OWN


def test_a_newer_earlier_source_may_still_withdraw_entries(tmp_path, monkeypatch):
    """A newer catalog that drops a CVE is CISA withdrawing it, as before."""
    paths = BoxPaths(root=tmp_path)
    _cache_from_cisa(paths)
    _serve(monkeypatch, {OWN: _feed(_ids() + NEW[:1], NOW.isoformat())})
    result = refresh_from(paths, SOURCES)
    assert result.source == OWN and result.withdrawn == (NEW[1],)


def test_an_earlier_source_that_moved_on_without_cached_ids_wins_by_rank(
        tmp_path, monkeypatch):
    """Newer than what OWN served last time: it has not stalled, it moved on
    without those IDs. Ranking wins, and the drops are withdrawals."""
    paths = BoxPaths(root=tmp_path)
    _cache_from_cisa(paths)
    moved_on = (NOW - timedelta(days=2)).isoformat()
    _serve(monkeypatch, {OWN: _feed(_ids(), moved_on)})
    result = refresh_from(paths, SOURCES)
    assert result.source == OWN and result.withdrawn == tuple(NEW)
    assert set(load_withdrawals(paths)) == set(NEW)


def test_the_refresh_records_what_each_source_served(tmp_path, monkeypatch):
    paths = BoxPaths(root=tmp_path)
    _cache_from_cisa(paths)
    _serve(monkeypatch, {OWN: _feed(_ids(), LAGGED_AT), CISA: _feed(_ids() + NEW, CACHED_AT)})
    refresh_from(paths, SOURCES)
    history = load_history(paths)
    assert history[OWN].disagreed_runs == 1
    assert history[CISA].disagreed_runs == 0


# ---------- a later source cannot lock the first one out (#157 review) ----------

MIRROR = "https://mirror.example/kev.json"
FAKE = "CVE-2026-9999"


def _night(paths, monkeypatch, cisa, mirror) -> object:
    _serve(monkeypatch, {CISA: cisa, MIRROR: mirror})
    return refresh_from(paths, (CISA, MIRROR))


def test_a_later_source_inventing_an_id_cannot_lock_cisa_out(tmp_path, monkeypatch):
    """Night 0 CISA times out and the mirror's list (CISA's plus one ID of
    its own, stamped ahead) is cached. CISA has served nothing before, so
    its older catalog without that ID is not a stall: it wins by rank, the
    invented ID is a withdrawal, and the mirror never withdraws a real one."""
    paths = BoxPaths(root=tmp_path)
    real = _ids()
    ahead = (NOW + timedelta(minutes=30)).isoformat()
    first = _night(paths, monkeypatch, urllib.error.URLError(TimeoutError("t")),
                   _feed(real + [FAKE], ahead))
    assert first.source == MIRROR
    dropped: list[str] = []
    for night in range(1, 6):
        dropped += real[(night - 1) * 3: night * 3]
        result = _night(paths, monkeypatch, _feed(real, (NOW - timedelta(hours=1)).isoformat()),
                        _feed([c for c in real if c not in dropped] + [FAKE],
                              (NOW + timedelta(minutes=30 + night)).isoformat()))
        assert result.source == CISA and result.disagreements == (), night
    assert load_kev(paths).source == CISA
    assert set(real) <= load_kev(paths).cve_ids
    assert set(load_withdrawals(paths)) == {FAKE}


def _override(paths, monkeypatch) -> None:
    """CISA served D0, then timed out; the mirror (D0's list plus FAKE,
    stamped later) was cached."""
    d0 = (NOW - timedelta(days=1)).isoformat()
    paths.d0 = d0
    _night(paths, monkeypatch, _feed(_ids(), d0), b"")
    _night(paths, monkeypatch, urllib.error.URLError(TimeoutError("t")),
           _feed(_ids() + [FAKE], (NOW - timedelta(hours=2)).isoformat()))
    assert load_kev(paths).source == MIRROR


def test_the_first_source_overridden_twice_running_escalates(tmp_path, monkeypatch):
    paths = BoxPaths(root=tmp_path)
    _override(paths, monkeypatch)
    mirror = _feed(_ids() + [FAKE], (NOW - timedelta(hours=1)).isoformat())
    once = _night(paths, monkeypatch, _feed(_ids(), paths.d0), mirror)
    assert once.source == MIRROR and [f.kind for f in once.failures] == [DISAGREES]
    assert once.overridden == ()
    twice = _night(paths, monkeypatch, _feed(_ids(), paths.d0), mirror)
    assert [f.source for f in twice.overridden] == [CISA]
    # CISA publishes again: it moved on, so it wins by rank and FAKE goes.
    newer = _night(paths, monkeypatch, _feed(_ids(), NOW.isoformat()), mirror)
    assert newer.source == CISA and newer.withdrawn == (FAKE,)
    assert load_history(paths)[CISA].disagreed_runs == 0


def test_a_later_source_cannot_withdraw_what_an_earlier_one_still_lists(
        tmp_path, monkeypatch):
    paths = BoxPaths(root=tmp_path)
    _override(paths, monkeypatch)
    dropping = _feed(_ids()[3:] + [FAKE], (NOW - timedelta(hours=1)).isoformat())
    result = _night(paths, monkeypatch, _feed(_ids(), paths.d0), dropping)
    assert result.source is None and result.needs_alert
    assert [f.kind for f in result.failures] == [DISAGREES, REJECTED]
    assert f"which {CISA}, ranked above it, still lists" in result.failures[1].error
    assert set(_ids()) <= load_kev(paths).cve_ids


def test_a_mirror_never_withdraws_a_cve_cisa_still_lists(tmp_path, monkeypatch):
    """CISA's own list never stops guarding: however many runs CISA is
    passed over serving the same date, the overriding mirror cannot drop a
    CVE CISA lists (#157 final check). The refresh is refused instead, and
    it heals once CISA publishes again."""
    paths = BoxPaths(root=tmp_path)
    _override(paths, monkeypatch)
    real = _ids()
    for night in range(1, 7):
        kept = real[3:]  # 3 real IDs: within the removal limit every night
        stamp = (NOW - timedelta(hours=2) + timedelta(minutes=night)).isoformat()
        result = _night(paths, monkeypatch, _feed(real, paths.d0), _feed(kept + [FAKE], stamp))
        assert result.source is None and result.needs_alert, night
        assert set(real) <= load_kev(paths).cve_ids
    assert load_history(paths)[CISA].disagreed_runs == 6
    assert set(load_withdrawals(paths)).isdisjoint(real)
    healed = _night(paths, monkeypatch, _feed(real, NOW.isoformat()), b"")
    assert healed.source == CISA and healed.withdrawn == (FAKE,)


def test_a_dead_first_mirror_does_not_freeze_the_catalog_for_good(tmp_path, monkeypatch):
    """A first-ranked mirror stops syncing; CISA's newer catalog is cached
    on a night the mirror is down; then CISA withdraws an ID the frozen
    mirror still lists. The guard refuses that withdrawal while the mirror's
    stall is young, and stops trusting the mirror's list once it is
    overridden (#157 re-review), so the catalog moves on."""
    dead = "https://dead-mirror.example/kev.json"
    paths = BoxPaths(root=tmp_path)
    base, d0 = _ids(), (NOW - timedelta(days=10)).isoformat()
    d1, d2 = (NOW - timedelta(days=3)).isoformat(), (NOW - timedelta(days=1)).isoformat()
    for answers in ({dead: _feed(base, d0), CISA: _feed(base, d0)},
                    {dead: urllib.error.URLError(TimeoutError("t")),
                     CISA: _feed(base + NEW, d1)}):
        _serve(monkeypatch, answers)
        assert refresh_from(paths, (dead, CISA)).updated
    assert load_kev(paths).source == CISA
    _serve(monkeypatch, {dead: _feed(base, d0), CISA: _feed(base[1:] + NEW, d2)})
    young = refresh_from(paths, (dead, CISA))
    assert young.source is None and [f.kind for f in young.failures] == [DISAGREES, REJECTED]
    healed = refresh_from(paths, (dead, CISA))
    assert healed.source == CISA and healed.withdrawn == (base[0],)
    assert [f.kind for f in healed.failures] == [DISAGREES]


# ---------- the scan run's alerts ----------


def _scan(monkeypatch, tmp_path) -> list:
    paths = make_box(tmp_path)
    Pushover(monkeypatch, paths)
    paths.config_file.write_text(paths.config_file.read_text()
                                 + f"kev:\n  sources: [{OWN}, {CISA}]\n")
    _cache_from_cisa(paths)
    monkeypatch.setattr(security_kev, "refresh_kev", refresh_kev)
    monkeypatch.setattr(security_kev, "load_kev", load_kev)
    monkeypatch.setattr(security_actions, "refresh_db", lambda: None)
    monkeypatch.setattr(security_scan_core, "scan_image", lambda r, timeout: scan_result(r))
    sent: list = []
    monkeypatch.setattr(security_kev, "send_alerts", lambda a, p: sent.extend(a))
    assert security_actions.cmd_security_scan([], paths) == 0
    return [a for a in sent if a.kind.startswith("kev_")]


def test_a_disagreement_resolved_by_a_later_source_sends_a_notice(tmp_path, monkeypatch):
    _serve(monkeypatch, {OWN: _feed(_ids(), LAGGED_AT), CISA: _feed(_ids() + NEW, CACHED_AT)})
    [alert] = _scan(monkeypatch, tmp_path)
    assert (alert.kind, alert.priority) == ("kev_sources_disagree", 0)
    assert OWN in alert.body and CISA in alert.body and "CVE-2026-7001" in alert.body
    assert "kev_withdrawn" not in alert.kind


def test_an_unresolved_disagreement_is_a_priority_alert(tmp_path, monkeypatch):
    _serve(monkeypatch, {OWN: _feed(_ids(), LAGGED_AT),
                         CISA: urllib.error.URLError(TimeoutError("timed out"))})
    [alert] = _scan(monkeypatch, tmp_path)
    assert (alert.kind, alert.priority) == ("kev_stale", 1)
    assert f"- {OWN}: catalog released" in alert.body
    assert f"- {CISA}: timed out after 30s" in alert.body


def test_an_override_of_cisa_alerts_at_priority_one_naming_it(tmp_path, monkeypatch):
    """The second run in a row CISA is passed over: the notice becomes a
    priority-1 alert that says the first source is overridden, without the
    "a mirror you run" advice."""
    paths = make_box(tmp_path)
    Pushover(monkeypatch, paths)
    paths.config_file.write_text(paths.config_file.read_text()
                                 + f"kev:\n  sources: [{CISA}, {MIRROR}]\n")
    _override(paths, monkeypatch)
    mirror = _feed(_ids() + [FAKE], (NOW - timedelta(hours=1)).isoformat())
    _night(paths, monkeypatch, _feed(_ids(), paths.d0), mirror)
    _serve(monkeypatch, {CISA: _feed(_ids(), paths.d0), MIRROR: mirror})
    monkeypatch.setattr(security_kev, "refresh_kev", refresh_kev)
    monkeypatch.setattr(security_kev, "load_kev", load_kev)
    monkeypatch.setattr(security_actions, "refresh_db", lambda: None)
    monkeypatch.setattr(security_scan_core, "scan_image", lambda r, timeout: scan_result(r))
    sent: list = []
    monkeypatch.setattr(security_kev, "send_alerts", lambda a, p: sent.extend(a))
    assert security_actions.cmd_security_scan([], paths) == 0
    [alert] = [a for a in sent if a.kind == "kev_sources_disagree"]
    assert alert.priority == 1
    assert alert.title == f"CISA KEV first source overridden by {MIRROR}"
    assert "mirror you run" not in alert.body and "CISA's own feed" in alert.body
