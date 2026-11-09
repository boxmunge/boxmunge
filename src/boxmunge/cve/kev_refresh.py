# SPDX-License-Identifier: Apache-2.0
"""Refresh the cached CISA KEV catalog from an ordered list of sources.

The sources (kev.KEV_DEFAULT_SOURCES, or kev.sources in boxmunge.yml) are
all trusted copies of CISA's catalog. They are tried in order and the first
whose catalog passes every check is cached, with the URL that answered.
Every source that failed is logged with its error and reported in the
result, so the stale/rejected alert can name each one (issue #121).

Checks per source (audit B-06 and #121). A catalog is rejected when it:
- is larger than KEV_MAX_BYTES, is not a JSON object with a
  'vulnerabilities' list, or has no valid 'dateReleased';
- was released more than KEV_MAX_FUTURE_DAYS in the future (a bogus date
  would otherwise block every genuine catalog as "older than the cache");
- was released before the cached one (a lagging source must not roll the
  catalog back; logged, but not alerted while the cache is fresh);
- holds fewer than KEV_MIN_ENTRIES IDs (an error page, a truncated file);
- drops more than KEV_MAX_REMOVALS of the cached IDs (a poisoned or
  rolled-back list: dropping a KEV CVE would lift its quarantines).
Up to KEV_MAX_REMOVALS dropped IDs are accepted (CISA does withdraw the odd
entry) and reported in the result as ``withdrawn``.
"""
from __future__ import annotations

import http.client
import json
import logging
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from boxmunge.config import ConfigError, load_config
from boxmunge.cve.kev import KEV_DEFAULT_SOURCES, KEV_MAX_FUTURE_DAYS, KevCatalog, load_kev
from boxmunge.fileutil import atomic_write_text
from boxmunge.paths import BoxPaths

_LOGGER = logging.getLogger("boxmunge")

# The catalog held ~1,770 entries in November 2026 and only grows. A refresh
# below this floor is a broken feed, not a smaller catalog.
KEV_MIN_ENTRIES = 1000
# CISA very rarely withdraws an entry, and never many at once. More than
# this many cached IDs missing from a new catalog is a poisoned or
# rolled-back list.
KEV_MAX_REMOVALS = 3
# The catalog was ~1.8 MB in November 2026; anything past this is not it.
KEV_MAX_BYTES = 16 * 1024 * 1024
_FETCH_TIMEOUT = 30
_MAX_LISTED = 10

# SourceFailure.kind values.
UNREACHABLE = "unreachable"  # no catalog came back (HTTP error, timeout, DNS)
REJECTED = "rejected"        # a catalog came back but failed a check
LAGGING = "lagging"          # a catalog came back, older than the cached one
CONFIG = "config"            # kev.sources in boxmunge.yml is unreadable or invalid
# Kinds that need the operator even while the cached catalog is fresh: a
# broken catalog or config would otherwise go unnoticed until it aged out.
_ALERTING_KINDS = (REJECTED, CONFIG)


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
    ``withdrawn`` holds the cached IDs the accepted catalog no longer lists.
    """

    source: str | None
    failures: tuple[SourceFailure, ...] = ()
    withdrawn: tuple[str, ...] = ()

    @property
    def updated(self) -> bool:
        return self.source is not None

    @property
    def needs_alert(self) -> bool:
        """True when nothing was cached and a failure needs the operator."""
        return not self.updated and any(f.kind in _ALERTING_KINDS for f in self.failures)


class _Failed(Exception):
    """A source answered with a catalog that cannot be used."""

    def __init__(self, kind: str, reason: str) -> None:
        super().__init__(reason)
        self.kind = kind


def _listed(ids: list[str]) -> str:
    more = len(ids) - _MAX_LISTED
    return ", ".join(ids[:_MAX_LISTED]) + (f" and {more} more" if more > 0 else "")


def kev_sources(paths: BoxPaths) -> tuple[str, ...]:
    """The KEV sources from boxmunge.yml, or the defaults if it sets none.

    Validated here rather than in load_config, so a mistake in kev.sources
    fails only the KEV refresh (with an alert that can still be sent), not
    every command that reads the config.
    """
    config = load_config(paths)
    if "kev" not in config:
        return KEV_DEFAULT_SOURCES
    block = config["kev"]
    where = paths.config_file
    if not isinstance(block, dict) or set(block) != {"sources"}:
        raise ConfigError(
            f"'kev' in {where} must be a mapping with only 'sources', e.g. "
            f"'kev: {{sources: [{KEV_DEFAULT_SOURCES[0]}]}}'; remove it to use the defaults")
    sources = block["sources"]
    if not isinstance(sources, list) or not sources:
        raise ConfigError(f"'kev.sources' in {where} must be a non-empty list of URLs; "
                          f"remove it to use the defaults")
    bad = [s for s in sources if not (isinstance(s, str) and s.startswith("https://"))]
    if bad:
        raise ConfigError(f"'kev.sources' in {where} must hold https:// URLs, got "
                          f"{', '.join(map(repr, bad))}")
    return tuple(sources)


class _HttpsOnlyRedirects(urllib.request.HTTPRedirectHandler):
    """Follow a redirect only to another https:// URL."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.startswith("https://"):
            raise urllib.error.HTTPError(
                newurl, code, f"redirect to non-https URL {newurl} refused", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_HttpsOnlyRedirects)


def _open(req: urllib.request.Request) -> Any:
    return _OPENER.open(req, timeout=_FETCH_TIMEOUT)


def _download(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "boxmunge"})
    with _open(req) as resp:
        body = resp.read(KEV_MAX_BYTES + 1)
    if len(body) > KEV_MAX_BYTES:
        raise _Failed(REJECTED, f"response is larger than {KEV_MAX_BYTES // 2**20} MiB")
    return body


def _describe(e: Exception) -> str:
    if isinstance(e, urllib.error.HTTPError):
        return f"HTTP {e.code} {e.reason}"
    if isinstance(e, TimeoutError) or (
        isinstance(e, urllib.error.URLError) and isinstance(e.reason, TimeoutError)
    ):
        return f"timed out after {_FETCH_TIMEOUT}s"
    if isinstance(e, http.client.HTTPException):
        return f"bad HTTP response: {e!r}"
    return str(e)


def _parse(body: bytes) -> Any:
    try:
        return json.loads(body)
    except RecursionError:
        raise _Failed(REJECTED, "response JSON is nested too deeply") from None
    except ValueError as e:
        # An HTML error page served with 200: the source did not answer.
        raise _Failed(UNREACHABLE, f"response is not JSON: {e}") from None


def _released_at(payload: dict[str, Any], now: datetime) -> datetime:
    raw = payload.get("dateReleased")
    if not isinstance(raw, str):
        raise _Failed(REJECTED, "feed payload has no 'dateReleased'")
    try:
        released = datetime.fromisoformat(raw)
    except ValueError:
        raise _Failed(REJECTED, f"feed 'dateReleased' is not a timestamp: {raw!r}") from None
    released = released.astimezone(timezone.utc) if released.tzinfo else (
        released.replace(tzinfo=timezone.utc))
    if released > now + timedelta(days=KEV_MAX_FUTURE_DAYS):
        raise _Failed(REJECTED, f"feed 'dateReleased' {raw} is in the future")
    return released


def _baseline(cached: KevCatalog, now: datetime) -> datetime | None:
    """The cached release time to guard against rollback, if trustworthy.
    A future one (cached before future dates were refused) is no baseline."""
    released = cached.released_at
    if released is None or released > now + timedelta(days=KEV_MAX_FUTURE_DAYS):
        return None
    return released


def _validate(
    payload: Any, cached: KevCatalog, now: datetime, paths: BoxPaths,
) -> tuple[list[str], datetime, list[str]]:
    """The catalog's sorted IDs, its release time and the cached IDs it
    drops, or _Failed."""
    # The feed may return valid JSON that is not an object (e.g. [] or null
    # from an error page).
    vulns = payload.get("vulnerabilities") if isinstance(payload, dict) else None
    if not isinstance(vulns, list):
        raise _Failed(REJECTED, "feed payload malformed (no 'vulnerabilities' list)")
    released = _released_at(payload, now)
    baseline = _baseline(cached, now)
    # Before the content checks: a lagging catalog also lacks the entries
    # added since, which would otherwise read as mass withdrawal.
    if baseline is not None and released < baseline:
        raise _Failed(LAGGING, f"catalog released {released.isoformat()} is older than "
                               f"the cached one released {baseline.isoformat()} "
                               f"(from {cached.source}): the source is lagging")
    cve_ids = sorted({
        v["cveID"] for v in vulns
        if isinstance(v, dict) and isinstance(v.get("cveID"), str)
    })
    if len(cve_ids) < KEV_MIN_ENTRIES:
        raise _Failed(REJECTED, f"feed returned {len(cve_ids)} entries, below the floor "
                                f"of {KEV_MIN_ENTRIES} (the catalog only grows)")
    withdrawn = sorted(cached.cve_ids - set(cve_ids))
    if len(withdrawn) > KEV_MAX_REMOVALS:
        raise _Failed(REJECTED, (
            f"{len(withdrawn)} cached CVEs are missing from it (more than "
            f"{KEV_MAX_REMOVALS}): {_listed(withdrawn)}. If CISA really withdrew them, "
            f"remove the cache as root (rm {paths.kev_catalog}) and the next scan "
            f"accepts the catalog"))
    return cve_ids, released, withdrawn


def _try_source(
    paths: BoxPaths, url: str, cached: KevCatalog,
) -> tuple[SourceFailure | None, list[str]]:
    """Fetch, check and cache one source's catalog: (failure, withdrawn IDs)."""
    now = datetime.now(timezone.utc)
    try:
        cve_ids, released, withdrawn = _validate(_parse(_download(url)), cached, now, paths)
    except _Failed as e:
        prefix = "rejected: " if e.kind == REJECTED else ""
        return SourceFailure(url, e.kind, f"{prefix}{e}"), []
    except (OSError, http.client.HTTPException) as e:
        # HTTPError/URLError and socket errors are OSErrors; a body cut
        # short is an http.client.IncompleteRead.
        return SourceFailure(url, UNREACHABLE, _describe(e)), []
    doc = {
        "source": url,
        "released_at": released.isoformat(),
        "fetched_at": now.isoformat(),
        "cve_ids": cve_ids,
    }
    try:
        atomic_write_text(paths.kev_catalog, json.dumps(doc, indent=2) + "\n")
    except OSError as e:
        return SourceFailure(url, REJECTED, f"fetched, but the cache write failed: {e}"), []
    return None, withdrawn


def refresh_from(paths: BoxPaths, sources: tuple[str, ...]) -> KevRefresh:
    """Try ``sources`` in order; cache the first catalog that passes."""
    cached = load_kev(paths)
    failures: list[SourceFailure] = []
    for url in sources:
        failure, withdrawn = _try_source(paths, url, cached)
        if failure is None:
            if withdrawn:
                _LOGGER.warning(
                    "KEV catalog from %s no longer lists %s", url, ", ".join(withdrawn),
                    extra=_extra({"source": url, "withdrawn": withdrawn}),
                )
            return KevRefresh(source=url, failures=tuple(failures),
                              withdrawn=tuple(withdrawn))
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
