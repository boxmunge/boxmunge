# SPDX-License-Identifier: Apache-2.0
"""CISA KEV (Known Exploited Vulnerabilities) catalog: the cached copy and
its freshness. Fetching it from the configured sources is kev_refresh.py.

The CVE policy engine's lowest tiers (relaxed, balanced) quarantine only on
findings that CISA lists as actively exploited; higher tiers use KEV as an
override that bypasses every de-escalation.

Fail-safe philosophy: a KEV signal we cannot currently verify (missing or
stale cache) must NOT take a site down. is_known_exploited returns False when
the catalog is stale or empty, and callers alert the operator that the feed
is degraded so the gap is never silent.

Freshness has two conditions (issue #121), because the catalog can come from
a mirror:
- a catalog must have been accepted from a source within KEV_MAX_AGE_DAYS
  (``fetched_at``): a box that gets no usable catalog goes stale after a
  week, as before;
- the catalog's own ``dateReleased`` must be within KEV_MAX_RELEASE_AGE_DAYS:
  a mirror that stopped syncing keeps answering, so the fetch time alone
  would make its old catalog look fresh forever.

EPSS seam: the policy engine consumes only the is_known_exploited predicate.
A future EPSS layer becomes a second predicate on this object, wired into the
same decision point — no change to the policy engine's shape.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Any

from boxmunge.paths import BoxPaths
from boxmunge.fs_nofollow import read_text_nofollow

_LOGGER = logging.getLogger("boxmunge")

# Tried in order; the first whose catalog passes the sanity checks wins.
# cisagov/kev-data is CISA's own mirror of the feed on GitHub, for boxes
# whose address range CISA's CDN refuses (HTTP 403, issue #121). Override
# with kev.sources in boxmunge.yml.
KEV_DEFAULT_SOURCES = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json",
    "https://raw.githubusercontent.com/cisagov/kev-data/main/"
    "known_exploited_vulnerabilities.json",
)
# A week of failed refreshes (from every source) before the gate degrades.
KEV_MAX_AGE_DAYS = 8
# CISA does not publish daily. The mirror's history of file changes from
# 2025-01 to 2026-11 has gaps of 8.9, 11.9, 12.0 and 17.9 days with no new
# dateReleased (e.g. 2025-05-22 to 2025-06-09), and since 2023 the longest
# run without a new entry was 18 days. 21 days clears those quiet spells
# while still catching a mirror that stopped syncing.
KEV_MAX_RELEASE_AGE_DAYS = 21
# A timestamp further than this in the future is clock skew or a bogus
# catalog, not freshness.
KEV_MAX_FUTURE_DAYS = 1


def _extra(detail: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"component": "cve-scan", "project": None, "detail": detail}


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _when(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


@dataclass(frozen=True)
class KevCatalog:
    """In-memory view of the cached KEV catalog.

    ``fetched_at`` is when a source last answered with a catalog we
    accepted, ``released_at`` the catalog's own ``dateReleased`` and
    ``source`` the URL that answered. ``unreadable`` is why the cache file
    could not be read (the catalog is then empty).
    """

    cve_ids: frozenset[str]
    fetched_at: datetime | None
    released_at: datetime | None
    source: str | None
    unreadable: str | None = None

    def stale_reason(self, today: date) -> str | None:
        """Why this catalog cannot be trusted on ``today``, or None if fresh."""
        if self.unreadable is not None:
            return (f"the KEV cache is unreadable ({self.unreadable}); the next "
                    f"successful refresh replaces it")
        if self.fetched_at is None:
            return "no KEV catalog has been fetched yet"
        fetch_age = (today - self.fetched_at.date()).days
        if fetch_age < -KEV_MAX_FUTURE_DAYS:
            return (f"the cached catalog was fetched in the future "
                    f"({_when(self.fetched_at)}): check the box clock")
        if fetch_age > KEV_MAX_AGE_DAYS:
            return (f"no KEV catalog has been accepted for {fetch_age} days (limit "
                    f"{KEV_MAX_AGE_DAYS}); last accepted {_when(self.fetched_at)} "
                    f"from {self.source or 'an unrecorded source'}")
        # A cache written before release dates were recorded has an unknown
        # release age, not a stale one: only the fetch condition applies
        # until the next successful refresh records dateReleased.
        if self.released_at is None:
            return None
        release_age = (today - self.released_at.date()).days
        if release_age < -KEV_MAX_FUTURE_DAYS:
            return (f"the cached catalog's release date is in the future "
                    f"({_when(self.released_at)}): check the box clock")
        if release_age > KEV_MAX_RELEASE_AGE_DAYS:
            return (f"the catalog is lagging: {self.source} last served a catalog "
                    f"released {_when(self.released_at)}, {release_age} days ago "
                    f"(limit {KEV_MAX_RELEASE_AGE_DAYS})")
        return None

    def is_stale(self, today: date) -> bool:
        return self.stale_reason(today) is not None

    def fresh_ids(self, today: date) -> frozenset[str] | None:
        """The listed CVE ids when the catalog is fresh on ``today``; None
        when it is stale, and then nothing may be treated as exploited. A
        scan judges freshness once with this, not once per finding."""
        return None if self.is_stale(today) else self.cve_ids

    def is_known_exploited(
        self, cve_id: str, *, today: date | None = None,
    ) -> bool:
        """True iff cve_id is on a fresh KEV catalog. Fail-safe: stale → False.

        `today` defaults to UTC today; passing it explicitly keeps the check
        deterministic in tests and matches the policy engine's injected date.
        """
        ids = self.fresh_ids(today or datetime.now(timezone.utc).date())
        return ids is not None and cve_id in ids


_EMPTY = KevCatalog(cve_ids=frozenset(), fetched_at=None, released_at=None, source=None)


def _optional_time(data: dict[str, Any], key: str) -> datetime | None:
    raw = data.get(key)
    return _utc(datetime.fromisoformat(raw)) if raw else None


def load_kev(paths: BoxPaths) -> KevCatalog:
    """Load the cached KEV catalog. Missing/malformed cache → empty + stale.

    A cache from before source tracking has no ``released_at`` or
    ``source``: it is judged by its fetch time alone until a refresh
    replaces it (see KevCatalog.stale_reason).
    """
    path = paths.kev_catalog
    if not path.exists():
        return _EMPTY
    try:
        data = json.loads(read_text_nofollow(path))
        raw_ids = data.get("cve_ids")
        # A well-formed document has cve_ids as a list. A truthy non-list
        # (e.g. cve_ids: 42) is a corrupt document, not a partial one:
        # trusting its timestamp would let a fresh-but-broken cache be
        # treated as authoritative. Fail safe — discard the whole document.
        if not isinstance(raw_ids, list):
            raise ValueError(f"cve_ids is not a list: {type(raw_ids).__name__}")
        source = data.get("source")
        return KevCatalog(
            cve_ids=frozenset(c for c in raw_ids if isinstance(c, str)),
            fetched_at=_optional_time(data, "fetched_at"),
            released_at=_optional_time(data, "released_at"),
            source=source if isinstance(source, str) else None,
        )
    except (ValueError, TypeError, OSError, AttributeError) as e:
        # A corrupt cache must not wedge the scan; treat as "no catalog",
        # and say why wherever its staleness is reported.
        _LOGGER.warning(
            "KEV catalog cache unreadable (%s) — treating as empty", e,
            extra=_extra(detail={"error": str(e)}),
        )
        return KevCatalog(frozenset(), None, None, None, unreadable=f"{path}: {e}")


def kev_status(paths: BoxPaths, today: date) -> dict[str, Any]:
    """The cached catalog's provenance and freshness, for status views."""
    kev = load_kev(paths)
    return {
        "source": kev.source,
        "released_at": kev.released_at.isoformat() if kev.released_at else None,
        "fetched_at": kev.fetched_at.isoformat() if kev.fetched_at else None,
        "entries": len(kev.cve_ids),
        "stale_reason": kev.stale_reason(today),
    }
