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
- a source must have answered within KEV_MAX_AGE_DAYS (``fetched_at``): a box
  that can reach no source goes stale after a week, as before;
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
# A timestamp further than this in the future is clock skew, not freshness.
_MAX_FUTURE_DAYS = 1


def _extra(detail: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"component": "cve-scan", "project": None, "detail": detail}


def _utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _when(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


@dataclass(frozen=True)
class KevCatalog:
    """In-memory view of the cached KEV catalog.

    ``fetched_at`` is when a source last answered with a catalog we
    accepted, ``released_at`` the catalog's own ``dateReleased`` and
    ``source`` the URL that answered.
    """

    cve_ids: frozenset[str]
    fetched_at: datetime | None
    released_at: datetime | None
    source: str | None

    def stale_reason(self, today: date) -> str | None:
        """Why this catalog cannot be trusted on ``today``, or None if fresh."""
        if self.fetched_at is None:
            return "no KEV catalog has been fetched yet"
        if self.released_at is None:
            return ("the cached catalog has no release date (written by an older "
                    "boxmunge); the next successful refresh replaces it")
        fetch_age = (today - self.fetched_at.date()).days
        release_age = (today - self.released_at.date()).days
        if fetch_age < -_MAX_FUTURE_DAYS or release_age < -_MAX_FUTURE_DAYS:
            return (f"the cached catalog is dated in the future (fetched "
                    f"{_when(self.fetched_at)}, released {_when(self.released_at)}): "
                    f"check the box clock")
        if fetch_age > KEV_MAX_AGE_DAYS:
            return (f"no KEV source has answered for {fetch_age} days (limit "
                    f"{KEV_MAX_AGE_DAYS}); last answer {_when(self.fetched_at)} "
                    f"from {self.source}")
        if release_age > KEV_MAX_RELEASE_AGE_DAYS:
            return (f"the catalog is lagging: {self.source} last served a catalog "
                    f"released {_when(self.released_at)}, {release_age} days ago "
                    f"(limit {KEV_MAX_RELEASE_AGE_DAYS})")
        return None

    def is_stale(self, today: date) -> bool:
        return self.stale_reason(today) is not None

    def is_known_exploited(
        self, cve_id: str, *, today: date | None = None,
    ) -> bool:
        """True iff cve_id is on a fresh KEV catalog. Fail-safe: stale → False.

        `today` defaults to UTC today; passing it explicitly keeps the check
        deterministic in tests and matches the policy engine's injected date.
        """
        when = today or datetime.now(timezone.utc).date()
        if self.is_stale(when):
            return False
        return cve_id in self.cve_ids


_EMPTY = KevCatalog(cve_ids=frozenset(), fetched_at=None, released_at=None, source=None)


def _optional_time(data: dict[str, Any], key: str) -> datetime | None:
    raw = data.get(key)
    return _utc(datetime.fromisoformat(raw)) if raw else None


def load_kev(paths: BoxPaths) -> KevCatalog:
    """Load the cached KEV catalog. Missing/malformed cache → empty + stale.

    A cache from before source tracking has no ``released_at``: its IDs
    still count for the shrink check, but it reads as stale until a refresh
    replaces it.
    """
    path = paths.kev_catalog
    if not path.exists():
        return _EMPTY
    try:
        data = json.loads(path.read_text())
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
        # A corrupt cache must not wedge the scan; treat as "no catalog".
        _LOGGER.warning(
            "KEV catalog cache unreadable (%s) — treating as empty", e,
            extra=_extra(detail={"error": str(e)}),
        )
        return _EMPTY


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
