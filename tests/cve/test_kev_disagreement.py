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
from boxmunge.cve.kev_refresh import DISAGREES, UNREACHABLE, refresh_from, refresh_kev
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

    def read(self, limit: int = -1) -> bytes:
        return self._body


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
    """OWN was down last night; CISA answered with the newest catalog."""
    paths.kev_catalog.parent.mkdir(parents=True, exist_ok=True)
    paths.kev_catalog.write_text(json.dumps({
        "source": CISA, "released_at": CACHED_AT, "fetched_at": CACHED_AT,
        "cve_ids": _ids() + NEW}))


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
