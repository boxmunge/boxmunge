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
        return age.days > max_age_days

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
        cve_ids = frozenset(
            c for c in (data.get("cve_ids") or []) if isinstance(c, str)
        )
        return KevCatalog(cve_ids=cve_ids, fetched_at=fetched_at)
    except (ValueError, OSError) as e:
        # A corrupt cache must not wedge the scan; treat as "no catalog".
        _LOGGER.warning(
            "KEV catalog cache unreadable (%s) — treating as empty", e,
            extra=_extra(detail={"error": str(e)}),
        )
        return KevCatalog(cve_ids=frozenset(), fetched_at=None)


def refresh_kev(paths: BoxPaths) -> None:
    """Best-effort fetch of the CISA KEV catalog → atomic cache write.

    Mirrors scanner.refresh_db: a failed refresh is logged at WARNING and
    swallowed. The scan proceeds against whatever cache exists (possibly
    stale, which the policy engine handles fail-safe).
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
        return

    vulns = payload.get("vulnerabilities") or []
    cve_ids = sorted(
        v["cveID"] for v in vulns
        if isinstance(v, dict) and isinstance(v.get("cveID"), str)
    )
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
