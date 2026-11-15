# SPDX-License-Identifier: Apache-2.0
"""Refresh the cached VulnCheck KEV list (state/kev/vulncheck.json), opt-in.

Runs only when boxmunge.yml has ``kev.vulncheck.token``. The cache is
``{"fetched_at": ISO8601, "entries": [cve_id, ...]}``, read by cve.exploited.

API, from VulnCheck's public documentation (docs.vulncheck.com/api/v3/indice,
docs.vulncheck.com/community/vulncheck-kev/schema). No token was available
when this was written, so the authenticated API was never called and the
test responses follow the documented example, not a captured reply:

- ``GET https://api.vulncheck.com/v3/index/vulncheck-kev`` with
  ``Authorization: Bearer <token>`` and ``Accept: application/json``.
- ``limit`` sets the page size; ``start_cursor=true`` starts a paginated
  session and ``cursor=<_meta.next_cursor>`` continues it, until a page has
  no ``next_cursor``.
- The reply is ``{"_benchmark", "_meta", "data": [record, ...]}``; each
  record's ``cve`` is a list of CVE id strings.

The paginated index is used rather than ``/v3/backup/vulncheck-kev``, which
only returns a link to an archive: that would mean following the link to
another host and unpacking it, for a list of a few thousand ids.

The token is only ever sent to api.vulncheck.com (it is not carried across
redirects) and appears in no log, alert or error. Like ENISA's source, a
failure here is returned as a failed SourceResult, never raised, and leaves
the previous cache alone.
"""
from __future__ import annotations

import http.client
import json
import logging
from datetime import datetime
from typing import Any

from boxmunge.cve.kev_config import KevConfig
from boxmunge.cve.kev_http import ResponseTooLarge, SourceResult, describe, download
from boxmunge.fileutil import atomic_write_text
from boxmunge.paths import BoxPaths

_LOGGER = logging.getLogger("boxmunge")

VULNCHECK_URL = "https://api.vulncheck.com/v3/index/vulncheck-kev"
_PAGE_SIZE = 300
# VulnCheck's list is larger than CISA's (over 1,400 in November 2026) and
# only grows. Fewer is a broken reply, not a smaller list.
VULNCHECK_MIN_ENTRIES = 1000
# A list this size is ~20 pages: a cursor that never ends is a fault.
_MAX_PAGES = 100


class _Rejected(Exception):
    """The reply came back but is not a usable list."""


def _page(body: bytes) -> tuple[list[str], str | None]:
    """(CVE ids, next cursor) from one reply, or _Rejected."""
    try:
        doc = json.loads(body)
    except RecursionError:
        raise _Rejected("response JSON is nested too deeply") from None
    except ValueError as e:
        raise _Rejected(f"response is not JSON: {e}") from None
    if not isinstance(doc, dict):
        raise _Rejected("response is not a JSON object")
    data = doc.get("data")
    if not isinstance(data, list):
        raise _Rejected("response has no 'data' list")
    ids: list[str] = []
    for i, record in enumerate(data):
        cves = record.get("cve") if isinstance(record, dict) else None
        if not (isinstance(cves, list) and all(isinstance(c, str) and c for c in cves)):
            raise _Rejected(f"record {i} has no 'cve' list of strings")
        ids.extend(cves)
    meta: Any = doc.get("_meta")
    cursor = meta.get("next_cursor") if isinstance(meta, dict) else None
    if cursor is not None and not (isinstance(cursor, str) and cursor):
        raise _Rejected("'_meta.next_cursor' is not a string")
    return ids, cursor


def _entries(token: str) -> list[str]:
    seen: dict[str, None] = {}
    query = "start_cursor=true"
    for _ in range(_MAX_PAGES):
        got = download(f"{VULNCHECK_URL}?limit={_PAGE_SIZE}&{query}", bearer=token)
        ids, cursor = _page(got.body)  # no validators are sent, so never NotModified
        seen.update(dict.fromkeys(ids))
        if cursor is None:
            break
        query = f"cursor={cursor}"
    else:
        raise _Rejected(f"it still had more after {_MAX_PAGES} pages")
    if len(seen) < VULNCHECK_MIN_ENTRIES:
        raise _Rejected(f"it lists {len(seen)} CVEs, below the floor of "
                        f"{VULNCHECK_MIN_ENTRIES} (the list only grows)")
    return list(seen)


def refresh_vulncheck(paths: BoxPaths, config: KevConfig, now: datetime) -> SourceResult | None:
    """Refresh VulnCheck's list; None when the operator has not set a token."""
    if config.vulncheck_token is None:
        return None
    try:
        entries = _entries(config.vulncheck_token)
        atomic_write_text(paths.kev_vulncheck, json.dumps(
            {"fetched_at": now.isoformat(), "entries": entries}, indent=2) + "\n")
        return SourceResult(VULNCHECK_URL, "updated")
    except (_Rejected, ResponseTooLarge) as e:
        error = f"rejected: {e}"
    except (OSError, http.client.HTTPException) as e:
        error = describe(e)
    _LOGGER.warning("VulnCheck KEV list not refreshed (%s)", error,
                    extra={"component": "cve-scan", "project": None,
                           "detail": {"source": VULNCHECK_URL, "error": error}})
    return SourceResult(VULNCHECK_URL, "failed", error)
