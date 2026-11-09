# SPDX-License-Identifier: Apache-2.0
"""KEV refresh checks (audit B-06, #121 review), for a single source.
Offline: the HTTP open is stubbed. The ordered source list is
test_kev_sources.py."""
from __future__ import annotations

import http.client
import json
import urllib.error
import urllib.request
from datetime import date, datetime, timedelta, timezone

from boxmunge.cve import kev_refresh
from boxmunge.cve.kev import KevCatalog, load_kev
from boxmunge.cve.kev_refresh import (
    KEV_MAX_BYTES, KEV_MAX_REMOVALS, KEV_MIN_ENTRIES, LAGGING, REJECTED, UNREACHABLE,
    refresh_from,
)
from boxmunge.paths import BoxPaths

SOURCE = "https://kev.example/feed.json"
RELEASED = "2026-10-12T19:44:45.1797Z"


def refresh_kev(paths):
    return refresh_from(paths, (SOURCE,))


class _FakeResp:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, limit: int = -1) -> bytes:
        return self._body if limit < 0 else self._body[:limit]


def _feed(ids, released=RELEASED) -> bytes:
    return json.dumps({"dateReleased": released,
                       "vulnerabilities": [{"cveID": c} for c in ids]}).encode()


def _ids(n: int, start: int = 0) -> list[str]:
    return [f"CVE-2020-{i:05d}" for i in range(start, start + n)]


def _seed_cache(paths, ids, released="2026-10-11T00:00:00+00:00") -> None:
    paths.kev_catalog.parent.mkdir(parents=True, exist_ok=True)
    paths.kev_catalog.write_text(json.dumps({
        "fetched_at": "2026-10-12T00:00:00+00:00", "released_at": released,
        "source": SOURCE, "cve_ids": ids}))


def _serve(monkeypatch, body: bytes) -> None:
    monkeypatch.setattr(kev_refresh, "_open", lambda req: _FakeResp(body))


def _raise(monkeypatch, error: BaseException) -> None:
    def fail(req):
        raise error
    monkeypatch.setattr(kev_refresh, "_open", fail)


def test_refresh_kev_rejects_empty_feed_and_keeps_cache(tmp_path, monkeypatch):
    """Audit B-06: {"vulnerabilities": []} must not wipe the catalog."""
    paths = BoxPaths(root=tmp_path)
    _seed_cache(paths, ["CVE-2024-3094"] + _ids(1400))
    _serve(monkeypatch, _feed([]))
    result = refresh_kev(paths)
    assert result.updated is False
    assert "below the floor" in result.failures[0].error
    assert result.needs_alert
    cat = load_kev(paths)
    assert len(cat.cve_ids) == 1401
    assert cat.is_known_exploited("CVE-2024-3094", today=date(2026, 10, 13))


def test_first_fetch_still_needs_the_floor(tmp_path, monkeypatch):
    paths = BoxPaths(root=tmp_path)
    _serve(monkeypatch, _feed(_ids(KEV_MIN_ENTRIES - 1)))
    result = refresh_kev(paths)
    assert result.needs_alert
    assert not paths.kev_catalog.exists()
    _serve(monkeypatch, _feed(_ids(KEV_MIN_ENTRIES)))
    assert refresh_kev(paths).updated


def test_up_to_the_removal_limit_is_accepted_and_reported(tmp_path, monkeypatch):
    paths = BoxPaths(root=tmp_path)
    _seed_cache(paths, _ids(1400))
    kept = _ids(1400)[KEV_MAX_REMOVALS:]
    _serve(monkeypatch, _feed(kept + ["CVE-2026-99999"]))
    result = refresh_kev(paths)
    assert result.updated is True and result.failures == ()
    assert result.withdrawn == tuple(_ids(KEV_MAX_REMOVALS))
    cat = load_kev(paths)
    assert "CVE-2026-99999" in cat.cve_ids and "CVE-2020-00000" not in cat.cve_ids
    assert cat.source == SOURCE
    assert cat.released_at == datetime(2026, 10, 12, 19, 44, 45, 179700, tzinfo=timezone.utc)


def test_a_same_size_list_dropping_more_than_the_limit_is_rejected(tmp_path, monkeypatch):
    """A poisoned or rolled-back list can keep the count: compare the IDs.
    Dropping a KEV CVE would otherwise lift its quarantines."""
    paths = BoxPaths(root=tmp_path)
    _seed_cache(paths, _ids(1400))
    swapped = _ids(1400)[KEV_MAX_REMOVALS + 1:] + _ids(KEV_MAX_REMOVALS + 1, start=5000)
    _serve(monkeypatch, _feed(swapped))
    result = refresh_kev(paths)
    assert not result.updated and result.needs_alert
    error = result.failures[0].error
    assert result.failures[0].kind == REJECTED
    assert f"{KEV_MAX_REMOVALS + 1} cached CVEs are missing" in error
    assert "CVE-2020-00000, CVE-2020-00001, CVE-2020-00002, CVE-2020-00003" in error
    assert f"rm {paths.kev_catalog}" in error
    assert "CVE-2020-00000" in load_kev(paths).cve_ids


def test_removals_are_checked_against_an_old_format_cache(tmp_path, monkeypatch):
    paths = BoxPaths(root=tmp_path)
    paths.kev_catalog.parent.mkdir(parents=True, exist_ok=True)
    paths.kev_catalog.write_text(json.dumps({
        "fetched_at": "2026-10-12T00:00:00+00:00", "cve_ids": _ids(1400)}))
    _serve(monkeypatch, _feed(_ids(1200)))
    assert "200 cached CVEs are missing" in refresh_kev(paths).failures[0].error


def test_malformed_payload_is_rejected(tmp_path, monkeypatch):
    paths = BoxPaths(root=tmp_path)
    _seed_cache(paths, _ids(1400))
    _serve(monkeypatch, b'{"error": "maintenance"}')
    result = refresh_kev(paths)
    assert "malformed" in result.failures[0].error
    assert len(load_kev(paths).cve_ids) == 1400


def test_network_failure_is_not_a_rejection(tmp_path, monkeypatch):
    paths = BoxPaths(root=tmp_path)
    _raise(monkeypatch, OSError("connection refused"))
    result = refresh_kev(paths)
    assert result.updated is False and not result.needs_alert
    assert result.failures[0].error == "connection refused"


def test_a_body_cut_short_is_unreachable_not_a_crash(tmp_path, monkeypatch):
    paths = BoxPaths(root=tmp_path)
    _raise(monkeypatch, http.client.IncompleteRead(b"{", 100))
    failure = refresh_kev(paths).failures[0]
    assert failure.kind == UNREACHABLE and "IncompleteRead" in failure.error


def test_deeply_nested_json_is_rejected_not_a_crash(tmp_path, monkeypatch):
    paths = BoxPaths(root=tmp_path)
    _serve(monkeypatch, b"[" * 200_000 + b"]" * 200_000)
    failure = refresh_kev(paths).failures[0]
    assert failure.kind == REJECTED and "nested too deeply" in failure.error


def test_an_oversized_response_is_rejected(tmp_path, monkeypatch):
    paths = BoxPaths(root=tmp_path)
    _serve(monkeypatch, b" " * (KEV_MAX_BYTES + 1))
    failure = refresh_kev(paths).failures[0]
    assert failure.kind == REJECTED and "larger than 16 MiB" in failure.error


def test_redirects_to_non_https_are_refused():
    handler = kev_refresh._HttpsOnlyRedirects()
    req = urllib.request.Request(SOURCE)
    try:
        handler.redirect_request(req, None, 302, "Found", {}, "http://kev.example/feed.json")
    except urllib.error.HTTPError as e:
        assert "redirect to non-https URL http://kev.example/feed.json refused" in str(e.reason)
    else:
        raise AssertionError("an http:// redirect was followed")
    followed = handler.redirect_request(req, None, 302, "Found", {}, "https://b.example/x")
    assert followed.full_url == "https://b.example/x"


def test_a_catalog_without_a_release_date_is_rejected(tmp_path, monkeypatch):
    paths = BoxPaths(root=tmp_path)
    _seed_cache(paths, _ids(1400))
    _serve(monkeypatch, json.dumps({"vulnerabilities": [{"cveID": c} for c in _ids(1400)]}).encode())
    result = refresh_kev(paths)
    assert "dateReleased" in result.failures[0].error
    assert load_kev(paths).fetched_at.isoformat() == "2026-10-12T00:00:00+00:00"


def test_a_catalog_released_in_the_future_is_rejected(tmp_path, monkeypatch):
    """A bogus date (a compromised mirror, a typo) must not be cached: the
    rollback check would then refuse every genuine catalog."""
    paths = BoxPaths(root=tmp_path)
    _seed_cache(paths, _ids(1400))
    _serve(monkeypatch, _feed(_ids(1400), released="2099-01-01T00:00:00Z"))
    result = refresh_kev(paths)
    assert result.failures[0].kind == REJECTED and result.needs_alert
    assert "'dateReleased' 2099-01-01T00:00:00Z is in the future" in result.failures[0].error
    assert load_kev(paths).released_at.year == 2026


def test_a_future_cached_release_is_no_rollback_baseline(tmp_path, monkeypatch):
    """A cache that already holds a future dateReleased must not block every
    genuine catalog as older than it."""
    paths = BoxPaths(root=tmp_path)
    _seed_cache(paths, _ids(1400), released="2099-01-01T00:00:00+00:00")
    recent = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    _serve(monkeypatch, _feed(_ids(1400), released=recent))
    assert refresh_kev(paths).updated
    assert load_kev(paths).released_at.isoformat() == recent


def test_an_older_catalog_is_lagging_and_does_not_alert(tmp_path, monkeypatch):
    """A lagging source must not roll the catalog back. It is logged, but it
    is not a P1 while the cached catalog is fresh."""
    paths = BoxPaths(root=tmp_path)
    _seed_cache(paths, _ids(1400))
    _serve(monkeypatch, _feed(_ids(1390), released="2026-10-01T00:00:00Z"))
    result = refresh_kev(paths)
    assert result.failures[0].kind == LAGGING and not result.needs_alert
    assert "older than the cached one" in result.failures[0].error


def test_future_dates_are_stale():
    """Clock skew at write time must not make a catalog fresh for years."""
    far = datetime(2031, 1, 1, tzinfo=timezone.utc)
    now = datetime(2026, 10, 13, tzinfo=timezone.utc)
    assert KevCatalog(frozenset({"CVE-1"}), far, now, SOURCE).is_stale(date(2026, 10, 13))
    assert KevCatalog(frozenset({"CVE-1"}), now, far, SOURCE).is_stale(date(2026, 10, 13))
    tomorrow = datetime(2026, 10, 14, tzinfo=timezone.utc)
    assert KevCatalog(frozenset({"CVE-1"}), tomorrow, tomorrow, SOURCE).is_stale(
        date(2026, 10, 13)) is False


def test_fleet_scan_alerts_once_on_rejected_refresh(tmp_path, monkeypatch):
    """A rejected refresh fires the priority-1 KEV alert even though the
    kept cache is still fresh."""
    from boxmunge.commands import security_actions, security_kev, security_scan_core
    from boxmunge.cve.kev_refresh import KevRefresh, SourceFailure
    from tests.test_commands.cve_helpers import make_box, scan_result

    paths = make_box(tmp_path)
    fresh = KevCatalog(frozenset(_ids(1400)), datetime.now(timezone.utc),
                       datetime.now(timezone.utc), SOURCE)
    monkeypatch.setattr(security_actions, "refresh_db", lambda: None)
    monkeypatch.setattr(
        security_kev, "refresh_kev",
        lambda p: KevRefresh(source=None, failures=(
            SourceFailure(SOURCE, REJECTED, "rejected: feed returned 0 entries"),)),
    )
    monkeypatch.setattr(security_kev, "load_kev", lambda p: fresh)
    monkeypatch.setattr(security_scan_core, "scan_image", lambda r, timeout: scan_result(r))
    sent: list = []
    monkeypatch.setattr(security_kev, "send_alerts", lambda a, p: sent.extend(a))
    assert security_actions.cmd_security_scan([], paths) == 0
    kev_alerts = [a for a in sent if a.kind == "kev_stale"]
    assert len(kev_alerts) == 1
    assert kev_alerts[0].priority == 1
    assert "refresh rejected" in kev_alerts[0].title
    assert "feed returned 0 entries" in kev_alerts[0].body
