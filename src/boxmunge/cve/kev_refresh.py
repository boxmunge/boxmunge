# SPDX-License-Identifier: Apache-2.0
"""Refresh the cached CISA KEV catalog from an ordered list of sources.

The sources (kev.KEV_DEFAULT_SOURCES, or kev.sources in boxmunge.yml) are
all trusted copies of CISA's catalog. They are tried in order and the first
whose catalog passes every check is cached, with the URL that answered.
Every source that failed is logged with its error and reported in the
result, so the stale/rejected alert can name each one (issue #121).

Checks per source (audit B-06 and #121). CISA's catalog only grows, so a
catalog is rejected when it:
- is not a JSON object with a 'vulnerabilities' list and a valid
  'dateReleased';
- holds fewer than KEV_MIN_ENTRIES IDs, or shrinks the cached catalog by
  more than KEV_MAX_SHRINK (an error page, a truncated download);
- was released before the cached one (a lagging source must not roll the
  catalog back).
"""
from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from boxmunge.config import ConfigError, load_config
from boxmunge.cve.kev import KevCatalog, load_kev
from boxmunge.fileutil import atomic_write_text
from boxmunge.paths import BoxPaths

_LOGGER = logging.getLogger("boxmunge")

# The catalog held ~1,770 entries in November 2026 and only grows. A refresh
# below this floor is a broken feed, not a smaller catalog.
KEV_MIN_ENTRIES = 1000
# Entries are very rarely withdrawn; losing more than 5% at once is a
# truncated feed.
KEV_MAX_SHRINK = 0.05
_FETCH_TIMEOUT = 30

# SourceFailure.kind values.
UNREACHABLE = "unreachable"  # no catalog came back (HTTP error, timeout, DNS)
REJECTED = "rejected"        # a catalog came back but failed a check
CONFIG = "config"            # boxmunge.yml could not say which sources to use


def _extra(detail: dict[str, Any]) -> dict[str, Any]:
    return {"component": "cve-scan", "project": None, "detail": detail}


@dataclass(frozen=True)
class SourceFailure:
    source: str
    kind: str
    error: str

    def line(self) -> str:
        return f"{self.source}: {self.error}"


@dataclass(frozen=True)
class KevRefresh:
    """Outcome of one refresh run.

    ``source`` is the URL whose catalog was cached (None if none was).
    ``failures`` lists every source tried before it, or all of them.
    """

    source: str | None
    failures: tuple[SourceFailure, ...] = ()

    @property
    def updated(self) -> bool:
        return self.source is not None

    @property
    def needs_alert(self) -> bool:
        """True when nothing was cached and a failure was not mere
        unreachability. A broken catalog or config would otherwise go
        unnoticed until the cache aged out."""
        return not self.updated and any(f.kind != UNREACHABLE for f in self.failures)


class _Rejected(Exception):
    """A source answered with a catalog that failed a check."""


def kev_sources(paths: BoxPaths) -> tuple[str, ...]:
    """The configured source list (validated by load_config)."""
    return tuple(load_config(paths)["kev"]["sources"])


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


def _fetch(url: str) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": "boxmunge"})
    with urllib.request.urlopen(req, timeout=_FETCH_TIMEOUT) as resp:
        return json.loads(resp.read())


def _describe(e: Exception) -> str:
    if isinstance(e, urllib.error.HTTPError):
        return f"HTTP {e.code} {e.reason}"
    if isinstance(e, TimeoutError) or (
        isinstance(e, urllib.error.URLError) and isinstance(e.reason, TimeoutError)
    ):
        return f"timed out after {_FETCH_TIMEOUT}s"
    if isinstance(e, ValueError):
        return f"response is not JSON: {e}"
    return str(e)


def _released_at(payload: dict[str, Any]) -> datetime:
    raw = payload.get("dateReleased")
    if not isinstance(raw, str):
        raise _Rejected("feed payload has no 'dateReleased'")
    try:
        released = datetime.fromisoformat(raw)
    except ValueError:
        raise _Rejected(f"feed 'dateReleased' is not a timestamp: {raw!r}") from None
    return released if released.tzinfo else released.replace(tzinfo=timezone.utc)


def _validate(payload: Any, cached: KevCatalog) -> tuple[list[str], datetime]:
    """The catalog's sorted IDs and release time, or _Rejected."""
    # The feed may return valid JSON that is not an object (e.g. [] or null
    # from an error page).
    vulns = payload.get("vulnerabilities") if isinstance(payload, dict) else None
    if not isinstance(vulns, list):
        raise _Rejected("feed payload malformed (no 'vulnerabilities' list)")
    released = _released_at(payload)
    cve_ids = sorted({
        v["cveID"] for v in vulns
        if isinstance(v, dict) and isinstance(v.get("cveID"), str)
    })
    reason = check_catalog_sanity(len(cve_ids), len(cached.cve_ids))
    if reason is not None:
        raise _Rejected(reason)
    if cached.released_at is not None and released < cached.released_at:
        raise _Rejected(
            f"catalog released {released.isoformat()} is older than the cached "
            f"one released {cached.released_at.isoformat()} "
            f"(from {cached.source}): the source is lagging")
    return cve_ids, released


def _try_source(paths: BoxPaths, url: str, cached: KevCatalog) -> SourceFailure | None:
    """Fetch, check and cache one source's catalog; None on success."""
    try:
        payload = _fetch(url)
    except (OSError, ValueError) as e:
        # HTTPError/URLError are OSErrors; a body that is not JSON is a
        # ValueError (an HTML error page served with 200).
        return SourceFailure(url, UNREACHABLE, _describe(e))
    try:
        cve_ids, released = _validate(payload, cached)
    except _Rejected as e:
        return SourceFailure(url, REJECTED, f"rejected: {e}")
    doc = {
        "source": url,
        "released_at": released.isoformat(),
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "cve_ids": cve_ids,
    }
    try:
        atomic_write_text(paths.kev_catalog, json.dumps(doc, indent=2) + "\n")
    except OSError as e:
        return SourceFailure(url, REJECTED, f"fetched, but the cache write failed: {e}")
    return None


def refresh_from(paths: BoxPaths, sources: tuple[str, ...]) -> KevRefresh:
    """Try ``sources`` in order; cache the first catalog that passes."""
    cached = load_kev(paths)
    failures: list[SourceFailure] = []
    for url in sources:
        failure = _try_source(paths, url, cached)
        if failure is None:
            if failures:
                _LOGGER.info(
                    "KEV catalog refreshed from %s", url,
                    extra=_extra({"source": url}),
                )
            return KevRefresh(source=url, failures=tuple(failures))
        _LOGGER.warning(
            "KEV source %s failed (%s)", url, failure.error,
            extra=_extra({"source": url, "kind": failure.kind, "error": failure.error}),
        )
        failures.append(failure)
    _LOGGER.warning(
        "KEV refresh failed from every source — keeping the cached catalog",
        extra=_extra({"failures": [f.line() for f in failures]}),
    )
    return KevRefresh(source=None, failures=tuple(failures))


def refresh_kev(paths: BoxPaths) -> KevRefresh:
    """Refresh the cache from the sources configured in boxmunge.yml."""
    try:
        sources = kev_sources(paths)
    except ConfigError as e:
        _LOGGER.warning(
            "KEV refresh skipped: %s", e, extra=_extra({"error": str(e)}),
        )
        return KevRefresh(source=None, failures=(
            SourceFailure("boxmunge.yml", CONFIG, f"cannot read the KEV sources: {e}"),
        ))
    return refresh_from(paths, sources)
