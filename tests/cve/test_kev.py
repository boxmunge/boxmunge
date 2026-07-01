# SPDX-License-Identifier: Apache-2.0
from datetime import date, datetime, timezone

import pytest

from boxmunge.cve.kev import KevCatalog, load_kev, KEV_MAX_AGE_DAYS
from boxmunge.paths import BoxPaths


def _catalog(cve_ids, fetched_at):
    return KevCatalog(cve_ids=frozenset(cve_ids), fetched_at=fetched_at)


def test_is_known_exploited_true_when_present_and_fresh():
    cat = _catalog({"CVE-2021-44228"}, datetime(2026, 7, 1, tzinfo=timezone.utc))
    assert cat.is_known_exploited("CVE-2021-44228") is True
    assert cat.is_known_exploited("CVE-2000-0001") is False


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
    import json
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
