# SPDX-License-Identifier: Apache-2.0
import json
from datetime import date, datetime, timezone

from boxmunge.cve import kev as kev_module
from boxmunge.cve.kev import KevCatalog, load_kev, refresh_kev, KEV_MAX_AGE_DAYS
from boxmunge.paths import BoxPaths


def _catalog(cve_ids, fetched_at):
    return KevCatalog(cve_ids=frozenset(cve_ids), fetched_at=fetched_at)


def test_is_known_exploited_true_when_present_and_fresh():
    cat = _catalog({"CVE-2021-44228"}, datetime(2026, 7, 1, tzinfo=timezone.utc))
    # Pin `today` to the fetch date so freshness is deterministic — without it
    # the check reads the wall clock and the test rots once real time passes
    # KEV_MAX_AGE_DAYS beyond the hard-coded fetched_at.
    assert cat.is_known_exploited(
        "CVE-2021-44228", today=date(2026, 7, 1),
    ) is True
    assert cat.is_known_exploited(
        "CVE-2000-0001", today=date(2026, 7, 1),
    ) is False


def test_is_known_exploited_fail_safe_when_stale():
    # Fetched 30 days ago → stale → treat as "cannot verify" → False.
    cat = _catalog({"CVE-2021-44228"}, datetime(2026, 6, 1, tzinfo=timezone.utc))
    assert cat.is_stale(date(2026, 7, 1)) is True
    assert cat.is_known_exploited(
        "CVE-2021-44228", today=date(2026, 7, 1),
    ) is False


def test_is_known_exploited_fail_safe_when_never_fetched():
    cat = _catalog(set(), None)
    assert cat.is_stale(date(2026, 7, 1)) is True
    assert cat.is_known_exploited("CVE-1", today=date(2026, 7, 1)) is False


def test_load_kev_missing_cache_returns_empty_stale_catalog(tmp_path):
    paths = BoxPaths(root=tmp_path)
    cat = load_kev(paths)
    assert cat.fetched_at is None
    assert cat.is_stale(date(2026, 7, 1)) is True


def test_load_kev_reads_written_catalog(tmp_path):
    paths = BoxPaths(root=tmp_path)
    paths.kev_catalog.parent.mkdir(parents=True, exist_ok=True)
    paths.kev_catalog.write_text(json.dumps({
        "fetched_at": "2026-07-01T00:00:00+00:00",
        "cve_ids": ["CVE-2021-44228"],
    }))
    cat = load_kev(paths)
    assert cat.is_known_exploited(
        "CVE-2021-44228", today=date(2026, 7, 1),
    ) is True


def test_load_kev_corrupt_cve_ids_non_list_is_fail_safe(tmp_path):
    # A truthy non-iterable cve_ids must not raise; treat as empty + stale.
    paths = BoxPaths(root=tmp_path)
    paths.kev_catalog.parent.mkdir(parents=True, exist_ok=True)
    paths.kev_catalog.write_text(json.dumps({
        "fetched_at": "2026-07-01T00:00:00+00:00",
        "cve_ids": 42,
    }))
    cat = load_kev(paths)
    assert cat.cve_ids == frozenset()
    assert cat.fetched_at is None
    assert cat.is_stale(date(2026, 7, 1)) is True


def test_is_stale_day_8_fresh_day_9_stale():
    # max_age_days=8: age of exactly 8 days is still fresh; 9 is stale.
    fetched = datetime(2026, 6, 1, tzinfo=timezone.utc)
    cat = _catalog({"CVE-1"}, fetched)
    assert cat.is_stale(date(2026, 6, 9), max_age_days=KEV_MAX_AGE_DAYS) is False
    assert cat.is_stale(date(2026, 6, 10), max_age_days=KEV_MAX_AGE_DAYS) is True


class _FakeResp:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self) -> bytes:
        return self._body


def test_refresh_kev_non_dict_payload_does_not_raise(tmp_path, monkeypatch):
    # Valid JSON that is not an object (e.g. []) must not raise. Offline.
    paths = BoxPaths(root=tmp_path)

    def fake_urlopen(req, timeout=None):
        return _FakeResp(b"[]")

    monkeypatch.setattr(
        kev_module.urllib.request, "urlopen", fake_urlopen,
    )
    refresh_kev(paths)  # must not raise
    # Nothing valid to write → cache absent → load is fail-safe empty.
    cat = load_kev(paths)
    assert cat.cve_ids == frozenset()
    assert cat.fetched_at is None
