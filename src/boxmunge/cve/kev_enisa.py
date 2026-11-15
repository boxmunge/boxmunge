# SPDX-License-Identifier: Apache-2.0
"""Refresh the cached ENISA EU KEV list (state/kev/enisa.json).

ENISA's EU Vulnerability Database publishes its known-exploited list as one
JSON dump: a list of objects with ``cveId``, ``sources`` (the catalogs that
list the CVE, ``cisa_kev`` and ``eukev_kev``) and ``dateAdded``. The cache
format is read by cve.exploited. The dump is asked for with the validators
the last one came with, so an unchanged list is a 304 that only renews the
cache's ``fetched_at``.

This source is additional to CISA's: whatever goes wrong here is logged and
returned as a failed SourceResult, never raised, so it cannot hold up the
CISA refresh. A dump that fails its checks leaves the previous cache alone.
"""
from __future__ import annotations

import http.client
import json
import logging
from datetime import datetime
from typing import Any

from boxmunge.cve.exploited import ENISA_TAGS
from boxmunge.cve.kev_config import KevConfig
from boxmunge.cve.kev_http import (
    NotModified, ResponseTooLarge, SourceResult, describe, download,
)
from boxmunge.fileutil import atomic_write_text
from boxmunge.fs_nofollow import read_text_nofollow_or_none
from boxmunge.paths import BoxPaths

_LOGGER = logging.getLogger("boxmunge")

ENISA_URL = "https://euvdservices.enisa.europa.eu/api/kev/dump"
# The dump held ~1,500 entries in November 2026 and only grows. Fewer is a
# broken feed, not a smaller list.
ENISA_MIN_ENTRIES = 1000


class _Rejected(Exception):
    """The dump came back but is not a usable list."""


def _entries(body: bytes) -> dict[str, list[str]]:
    """{cve_id: sources} from a dump, or _Rejected."""
    try:
        dump = json.loads(body)
    except RecursionError:
        raise _Rejected("response JSON is nested too deeply") from None
    except ValueError as e:
        raise _Rejected(f"response is not JSON: {e}") from None
    if not isinstance(dump, list):
        raise _Rejected("response is not a JSON list")
    entries: dict[str, list[str]] = {}
    for i, item in enumerate(dump):
        if not isinstance(item, dict):
            raise _Rejected(f"entry {i} is not an object")
        cve, sources, added = item.get("cveId"), item.get("sources"), item.get("dateAdded")
        if not isinstance(cve, str) or not cve:
            raise _Rejected(f"entry {i} has no 'cveId'")
        if not (isinstance(sources, list) and all(isinstance(s, str) for s in sources)):
            raise _Rejected(f"entry {i} ({cve}) has no 'sources' list of strings")
        if not isinstance(added, str):
            raise _Rejected(f"entry {i} ({cve}) has no 'dateAdded'")
        unknown = sorted(set(sources) - ENISA_TAGS.keys())
        if unknown:
            raise _Rejected(f"entry {i} ({cve}) has an unknown source tag "
                            f"{', '.join(map(repr, unknown))}: ENISA's list changed, so "
                            f"it was not cached")
        merged = entries.setdefault(cve, [])
        merged.extend(s for s in sources if s not in merged)
    if len(entries) < ENISA_MIN_ENTRIES:
        raise _Rejected(f"it lists {len(entries)} CVEs, below the floor of "
                        f"{ENISA_MIN_ENTRIES} (the list only grows)")
    return entries


def _cached(paths: BoxPaths) -> dict[str, Any] | None:
    """The cache document when it is usable, else None (a full fetch then
    replaces it). A cache is only confirmed unchanged if it can be rewritten."""
    raw = read_text_nofollow_or_none(paths.kev_enisa)
    if raw is None:
        return None
    try:
        doc = json.loads(raw)
        ok = (isinstance(doc, dict) and isinstance(doc["entries"], dict)
              and isinstance(doc["fetched_at"], str)
              and all(isinstance(doc[k], (str, type(None))) for k in ("etag", "last_modified")))
    except (ValueError, KeyError):
        ok = False
    if not ok:
        _LOGGER.warning("ENISA cache %s is unreadable: fetching the list afresh", paths.kev_enisa,
                        extra={"component": "cve-scan", "project": None, "detail": None})
        return None
    return doc


def _store(paths: BoxPaths, now: datetime, etag: str | None, last_modified: str | None,
           entries: dict[str, list[str]]) -> None:
    doc = {"fetched_at": now.isoformat(), "etag": etag, "last_modified": last_modified,
           "entries": entries}
    atomic_write_text(paths.kev_enisa, json.dumps(doc, indent=2) + "\n")


def _fetch(paths: BoxPaths, now: datetime) -> str:
    """Refresh the cache; ``updated`` or ``unchanged``. Raises on failure."""
    cached = _cached(paths)
    got = download(ENISA_URL, **({"etag": cached["etag"], "last_modified": cached["last_modified"]}
                                 if cached else {}))
    if isinstance(got, NotModified):
        assert cached is not None  # validators were only sent with a cache
        _store(paths, now, cached["etag"], cached["last_modified"], cached["entries"])
        return "unchanged"
    _store(paths, now, got.etag, got.last_modified, _entries(got.body))
    return "updated"


def refresh_enisa(paths: BoxPaths, config: KevConfig, now: datetime) -> SourceResult:
    """Refresh ENISA's list unless the operator turned it off."""
    if not config.enisa_enabled:
        return SourceResult(ENISA_URL, "disabled")
    try:
        return SourceResult(ENISA_URL, _fetch(paths, now))
    except (_Rejected, ResponseTooLarge) as e:
        error = f"rejected: {e}"
    except (OSError, http.client.HTTPException) as e:
        error = describe(e)
    _LOGGER.warning("ENISA KEV list not refreshed (%s)", error,
                    extra={"component": "cve-scan", "project": None,
                           "detail": {"source": ENISA_URL, "error": error}})
    return SourceResult(ENISA_URL, "failed", error)
