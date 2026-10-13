# SPDX-License-Identifier: Apache-2.0
"""CISA KEV (Known Exploited Vulnerabilities) feed — active-exploitation signal.

The CVE policy engine's lowest tier (relaxed) quarantines only on findings
that CISA lists as actively exploited; higher tiers use KEV as an override
that bypasses every de-escalation. This module fetches, caches, and looks up
that catalog.

Fail-safe philosophy: a KEV signal we cannot currently verify (missing or
stale cache) must NOT take a site down. is_known_exploited returns False when
the catalog is stale or empty, and callers alert the operator that the feed
is degraded so the gap is never silent.

Sanity floor (audit B-06): CISA's catalog only grows. A refresh that would
replace the cache with fewer than KEV_MIN_ENTRIES IDs, or that shrinks the
cached catalog by more than KEV_MAX_SHRINK, is rejected: the previous cache
is kept, and the caller alerts. An empty or truncated feed (an error page,
a CDN hiccup) would otherwise be accepted as a fresh catalog and switch the
exploitation gate off with no staleness alert.

EPSS seam: the policy engine consumes only the is_known_exploited predicate.
A future EPSS layer becomes a second predicate on this object, wired into the
same decision point — no change to the policy engine's shape.
"""
from __future__ import annotations

import json
import logging
import urllib.request
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Any

from boxmunge.fileutil import atomic_write_text
from boxmunge.paths import BoxPaths

_LOGGER = logging.getLogger("boxmunge")

KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
KEV_MAX_AGE_DAYS = 8  # daily feed; >1 week stale = degraded.
# The catalog held ~1,400 entries in late 2026 and only grows. A refresh
# below this floor is a broken feed, not a smaller catalog.
KEV_MIN_ENTRIES = 1000
# Entries are very rarely withdrawn; losing more than 5% at once is a
# truncated feed.
KEV_MAX_SHRINK = 0.05
# A fetched_at further than this in the future is clock skew at write time,
# not a fresh catalog.
_MAX_FUTURE_DAYS = 1
_FETCH_TIMEOUT = 30


def _extra(detail: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"component": "cve-scan", "project": None, "detail": detail}


@dataclass(frozen=True)
class KevCatalog:
    """In-memory view of the cached KEV catalog."""

    cve_ids: frozenset[str]
    fetched_at: datetime | None

    def is_stale(self, today: date, max_age_days: int = KEV_MAX_AGE_DAYS) -> bool:
        if self.fetched_at is None:
            return True
        age = today - self.fetched_at.date()
        return age.days > max_age_days or age.days < -_MAX_FUTURE_DAYS

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


def load_kev(paths: BoxPaths) -> KevCatalog:
    """Load the cached KEV catalog. Missing/malformed cache → empty + stale."""
    path = paths.kev_catalog
    if not path.exists():
        return KevCatalog(cve_ids=frozenset(), fetched_at=None)
    try:
        data = json.loads(path.read_text())
        fetched_raw = data.get("fetched_at")
        fetched_at = (
            datetime.fromisoformat(fetched_raw) if fetched_raw else None
        )
        if fetched_at is not None and fetched_at.tzinfo is None:
            fetched_at = fetched_at.replace(tzinfo=timezone.utc)
        raw_ids = data.get("cve_ids")
        # A well-formed document has cve_ids as a list. A truthy non-list
        # (e.g. cve_ids: 42) is a corrupt document, not a partial one:
        # trusting its timestamp would let a fresh-but-broken cache be
        # treated as authoritative. Fail safe — discard the whole document.
        if not isinstance(raw_ids, list):
            raise ValueError(f"cve_ids is not a list: {type(raw_ids).__name__}")
        cve_ids = frozenset(c for c in raw_ids if isinstance(c, str))
        return KevCatalog(cve_ids=cve_ids, fetched_at=fetched_at)
    except (ValueError, TypeError, OSError, AttributeError) as e:
        # A corrupt cache must not wedge the scan; treat as "no catalog".
        _LOGGER.warning(
            "KEV catalog cache unreadable (%s) — treating as empty", e,
            extra=_extra(detail={"error": str(e)}),
        )
        return KevCatalog(cve_ids=frozenset(), fetched_at=None)


@dataclass(frozen=True)
class KevRefresh:
    """Outcome of one refresh attempt.

    ``rejected`` carries the reason when the feed answered but its content
    failed the sanity floor (or was malformed). The cache is untouched in
    that case and the caller must alert: unlike a transient network
    failure, a bad feed would otherwise go unnoticed until the cache aged
    out a week later.
    """

    updated: bool
    rejected: str | None = None


def check_catalog_sanity(new_count: int, cached_count: int) -> str | None:
    """Return why a refreshed catalog of ``new_count`` IDs is implausible."""
    if new_count < KEV_MIN_ENTRIES:
        return (
            f"feed returned {new_count} entries, below the floor of "
            f"{KEV_MIN_ENTRIES} (the catalog only grows)"
        )
    if cached_count and new_count < cached_count * (1 - KEV_MAX_SHRINK):
        return (
            f"feed returned {new_count} entries, {cached_count - new_count} "
            f"fewer than the {cached_count} cached (more than "
            f"{KEV_MAX_SHRINK:.0%} shrink)"
        )
    return None


def _reject(reason: str, detail: dict[str, Any]) -> KevRefresh:
    _LOGGER.warning(
        "KEV feed refresh rejected (%s) — keeping the cached catalog", reason,
        extra=_extra(detail={"reason": reason, **detail}),
    )
    return KevRefresh(updated=False, rejected=reason)


def refresh_kev(paths: BoxPaths) -> KevRefresh:
    """Fetch the CISA KEV catalog and, if it is plausible, cache it.

    A network failure is logged at WARNING and the scan proceeds against
    the cache (possibly stale, which the policy engine handles fail-safe
    and the caller alerts on). A malformed or implausible payload is
    rejected: the cache is kept and the result says why.
    """
    req = urllib.request.Request(
        KEV_FEED_URL, headers={"User-Agent": "boxmunge"},
    )
    try:
        with urllib.request.urlopen(req, timeout=_FETCH_TIMEOUT) as resp:
            payload = json.loads(resp.read())
    except (OSError, ValueError) as e:
        _LOGGER.warning(
            "KEV feed refresh failed (%s) — continuing with cached catalog", e,
            extra=_extra(detail={"error": str(e)}),
        )
        return KevRefresh(updated=False)

    # The feed may return valid JSON that is not an object (e.g. [] or null
    # from an error page).
    vulns = payload.get("vulnerabilities") if isinstance(payload, dict) else None
    if not isinstance(vulns, list):
        return _reject(
            "feed payload malformed (no 'vulnerabilities' list)",
            {"payload_type": type(payload).__name__},
        )
    cve_ids = sorted({
        v["cveID"] for v in vulns
        if isinstance(v, dict) and isinstance(v.get("cveID"), str)
    })
    cached = load_kev(paths)
    reason = check_catalog_sanity(len(cve_ids), len(cached.cve_ids))
    if reason is not None:
        return _reject(reason, {"new_count": len(cve_ids),
                                "cached_count": len(cached.cve_ids)})
    doc = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "cve_ids": cve_ids,
    }
    try:
        atomic_write_text(paths.kev_catalog, json.dumps(doc, indent=2) + "\n")
    except OSError as e:
        _LOGGER.warning(
            "KEV catalog write failed (%s)", e,
            extra=_extra(detail={"error": str(e)}),
        )
        return KevRefresh(updated=False)
    return KevRefresh(updated=True)
