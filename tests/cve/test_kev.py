# SPDX-License-Identifier: Apache-2.0
import json
from datetime import date, datetime, timezone

from boxmunge.cve.kev import (
    KEV_MAX_AGE_DAYS, KEV_MAX_RELEASE_AGE_DAYS, KevCatalog, load_kev,
)
from boxmunge.cve.kev_refresh import refresh_from
from boxmunge.paths import BoxPaths

MIRROR = "https://mirror.example/kev.json"


def _catalog(cve_ids, fetched_at, released_at=None):
    """A catalog fetched at ``fetched_at`` and released then too unless given."""
    return KevCatalog(cve_ids=frozenset(cve_ids), fetched_at=fetched_at,
                      released_at=released_at or fetched_at, source=MIRROR)


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
    cat = KevCatalog(frozenset(), None, None, None)
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
        "source": MIRROR,
        "released_at": "2026-06-30T19:44:45.179700+00:00",
        "fetched_at": "2026-07-01T00:00:00+00:00",
        "cve_ids": ["CVE-2021-44228"],
    }))
    cat = load_kev(paths)
    assert cat.source == MIRROR
    assert cat.released_at == datetime(2026, 6, 30, 19, 44, 45, 179700, tzinfo=timezone.utc)
    assert cat.is_known_exploited(
        "CVE-2021-44228", today=date(2026, 7, 1),
    ) is True


def test_old_format_cache_keeps_its_ids_but_reads_stale(tmp_path):
    """A cache written before source tracking has no released_at: it needs
    a refresh, and says why, but its IDs still guard the shrink check."""
    paths = BoxPaths(root=tmp_path)
    paths.kev_catalog.parent.mkdir(parents=True, exist_ok=True)
    paths.kev_catalog.write_text(json.dumps({
        "fetched_at": "2026-07-01T00:00:00+00:00", "cve_ids": ["CVE-2021-44228"],
    }))
    cat = load_kev(paths)
    assert cat.cve_ids == frozenset({"CVE-2021-44228"})
    assert "older boxmunge" in cat.stale_reason(date(2026, 7, 1))
    assert cat.is_known_exploited("CVE-2021-44228", today=date(2026, 7, 1)) is False


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
    # No source answering: an age of exactly 8 days is still fresh; 9 is stale.
    assert KEV_MAX_AGE_DAYS == 8
    fetched = datetime(2026, 6, 1, tzinfo=timezone.utc)
    cat = _catalog({"CVE-1"}, fetched)
    assert cat.is_stale(date(2026, 6, 9)) is False
    assert cat.is_stale(date(2026, 6, 10)) is True
    assert "no KEV source has answered for 9 days" in cat.stale_reason(date(2026, 6, 10))


def test_staleness_follows_the_catalogs_release_date_not_the_fetch():
    """A mirror that stopped syncing still answers every day; its catalog's
    own dateReleased is what ages it out (issue #121)."""
    released = datetime(2026, 6, 1, 19, 0, tzinfo=timezone.utc)
    limit = date(2026, 6, 1 + KEV_MAX_RELEASE_AGE_DAYS)
    fresh_fetch = datetime.combine(limit, datetime.min.time(), timezone.utc)
    cat = _catalog({"CVE-1"}, fresh_fetch, released_at=released)
    assert cat.is_stale(limit) is False
    later = KevCatalog(cat.cve_ids, fresh_fetch.replace(day=fresh_fetch.day + 1),
                       released, MIRROR)
    reason = later.stale_reason(date(2026, 6, 2 + KEV_MAX_RELEASE_AGE_DAYS))
    assert reason is not None and "lagging" in reason
    assert MIRROR in reason and "2026-06-01 19:00 UTC" in reason
    assert later.is_known_exploited("CVE-1", today=date(2026, 6, 23)) is False


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
        "boxmunge.cve.kev_refresh.urllib.request.urlopen", fake_urlopen,
    )
    refresh_from(paths, (MIRROR,))  # must not raise
    # Nothing valid to write → cache absent → load is fail-safe empty.
    cat = load_kev(paths)
    assert cat.cve_ids == frozenset()
    assert cat.fetched_at is None
