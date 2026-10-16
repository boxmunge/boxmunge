# SPDX-License-Identifier: Apache-2.0
"""KEV refresh sanity floor (audit B-06). Offline: urlopen is stubbed."""
from __future__ import annotations

import json
from datetime import date, datetime, timezone

from boxmunge.cve import kev as kev_module
from boxmunge.cve.kev import (
    KEV_MIN_ENTRIES,
    KevCatalog,
    check_catalog_sanity,
    load_kev,
    refresh_kev,
)
from boxmunge.paths import BoxPaths


class _FakeResp:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self) -> bytes:
        return self._body


def _feed(ids) -> bytes:
    return json.dumps({"vulnerabilities": [{"cveID": c} for c in ids]}).encode()


def _ids(n: int, start: int = 0) -> list[str]:
    return [f"CVE-2020-{i:05d}" for i in range(start, start + n)]


def _seed_cache(paths, ids, fetched_at="2026-10-12T00:00:00+00:00") -> None:
    paths.kev_catalog.parent.mkdir(parents=True, exist_ok=True)
    paths.kev_catalog.write_text(json.dumps({"fetched_at": fetched_at, "cve_ids": ids}))


def _serve(monkeypatch, body: bytes) -> None:
    monkeypatch.setattr(
        kev_module.urllib.request, "urlopen", lambda req, timeout=None: _FakeResp(body),
    )


def test_refresh_kev_rejects_empty_feed_and_keeps_cache(tmp_path, monkeypatch):
    """Audit B-06: {"vulnerabilities": []} must not wipe the catalog."""
    paths = BoxPaths(root=tmp_path)
    _seed_cache(paths, ["CVE-2024-3094"] + _ids(1400))
    _serve(monkeypatch, _feed([]))
    result = refresh_kev(paths)
    assert result.updated is False
    assert "below the floor" in result.rejected
    cat = load_kev(paths)
    assert len(cat.cve_ids) == 1401
    assert cat.is_known_exploited("CVE-2024-3094", today=date(2026, 10, 13))


def test_refresh_kev_rejects_truncated_feed(tmp_path, monkeypatch):
    paths = BoxPaths(root=tmp_path)
    _seed_cache(paths, _ids(1400))
    _serve(monkeypatch, _feed(_ids(1200)))  # lost 200 of 1400: more than 5%
    result = refresh_kev(paths)
    assert "shrink" in result.rejected
    assert len(load_kev(paths).cve_ids) == 1400


def test_refresh_kev_accepts_small_withdrawal_and_growth(tmp_path, monkeypatch):
    paths = BoxPaths(root=tmp_path)
    _seed_cache(paths, _ids(1400))
    _serve(monkeypatch, _feed(_ids(1395) + ["CVE-2026-99999"]))
    result = refresh_kev(paths)
    assert result.updated is True and result.rejected is None
    assert "CVE-2026-99999" in load_kev(paths).cve_ids


def test_refresh_kev_first_fetch_still_needs_the_floor(tmp_path, monkeypatch):
    paths = BoxPaths(root=tmp_path)
    _serve(monkeypatch, _feed(_ids(10)))
    result = refresh_kev(paths)
    assert result.rejected is not None
    assert not paths.kev_catalog.exists()


def test_refresh_kev_malformed_payload_is_rejected(tmp_path, monkeypatch):
    paths = BoxPaths(root=tmp_path)
    _seed_cache(paths, _ids(1400))
    _serve(monkeypatch, b'{"error": "maintenance"}')
    result = refresh_kev(paths)
    assert "malformed" in result.rejected
    assert len(load_kev(paths).cve_ids) == 1400


def test_refresh_kev_network_failure_is_not_a_rejection(tmp_path, monkeypatch):
    paths = BoxPaths(root=tmp_path)

    def down(req, timeout=None):
        raise OSError("connection refused")

    monkeypatch.setattr(kev_module.urllib.request, "urlopen", down)
    result = refresh_kev(paths)
    assert result.updated is False and result.rejected is None


def test_check_catalog_sanity_boundaries():
    assert check_catalog_sanity(KEV_MIN_ENTRIES, 0) is None
    assert check_catalog_sanity(KEV_MIN_ENTRIES - 1, 0) is not None
    assert check_catalog_sanity(1900, 2000) is None  # exactly 5% shrink
    assert check_catalog_sanity(1899, 2000) is not None


def test_future_fetched_at_is_stale():
    """Clock skew at write time must not make a catalog fresh for years."""
    far = KevCatalog(frozenset({"CVE-1"}), datetime(2031, 1, 1, tzinfo=timezone.utc))
    assert far.is_stale(date(2026, 10, 13)) is True
    tomorrow = KevCatalog(frozenset({"CVE-1"}), datetime(2026, 10, 14, tzinfo=timezone.utc))
    assert tomorrow.is_stale(date(2026, 10, 13)) is False


def test_fleet_scan_alerts_once_on_rejected_refresh(tmp_path, monkeypatch):
    """A rejected refresh fires the priority-1 KEV alert even though the
    kept cache is still fresh."""
    from boxmunge.commands import security_actions, security_scan_core
    from boxmunge.cve.kev import KevRefresh
    from tests.test_commands.cve_helpers import make_box, scan_result

    paths = make_box(tmp_path)
    fresh = KevCatalog(frozenset(_ids(1400)), datetime.now(timezone.utc))
    monkeypatch.setattr(security_actions, "refresh_db", lambda: None)
    monkeypatch.setattr(
        security_actions, "refresh_kev",
        lambda p: KevRefresh(updated=False, rejected="feed returned 0 entries"),
    )
    monkeypatch.setattr(security_actions, "load_kev", lambda p: fresh)
    monkeypatch.setattr(security_scan_core, "scan_image", lambda r, timeout: scan_result(r))
    sent: list = []
    monkeypatch.setattr(security_actions, "send_alerts", lambda a, p: sent.extend(a))
    assert security_actions.cmd_security_scan([], paths) == 0
    kev_alerts = [a for a in sent if a.kind == "kev_stale"]
    assert len(kev_alerts) == 1
    assert kev_alerts[0].priority == 1
    assert "refresh rejected" in kev_alerts[0].title
    assert "feed returned 0 entries" in kev_alerts[0].body
