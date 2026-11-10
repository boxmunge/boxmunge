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
- was released more than KEV_MAX_FUTURE_RELEASE in the future (a bogus
  date would otherwise block every genuine catalog as "older than the
  cache");
- was released before the cached one, when the cache came from this source
  or one earlier in the list (a lagging source must not roll the catalog
  back; logged, but not alerted while the cache is fresh). A source earlier
  in the list than the cache's own is not held to the cached date, so a
  later source stamping a newer date (a compromised mirror, an internal
  mirror stamping its sync time) cannot lock the earlier ones out;
- holds fewer than KEV_MIN_ENTRIES IDs (an error page, a truncated file);
- is older than the cached one AND lacks any of its IDs AND is no newer
  than the catalog the same source served last time (cve.kev_source_history),
  from a source earlier in the list than the cache's own (CVE-03): the
  sources disagree. That source has not caught up; taking its catalog
  would roll back the newest KEV CVEs. The later sources are tried
  instead; the first that passes (held to the cached date, so it agrees
  with the cache or is newer) is cached and the disagreement is reported
  for a notice. If none passes, the cache is kept and the disagreement
  alerts like a rejection. While an earlier source disagrees, a later one
  may not drop a CVE the earlier one still lists (rejected), until that
  stall passes the override bound below (a mirror that stopped syncing
  must not freeze the catalog for good). An earlier
  source that has moved on (newer than its last catalog, or never seen
  before) or drops nothing wins by rank, and what it drops is a withdrawal:
  otherwise a later source that invented an ID would lock it out for good
  (#157 review). The first source in the list, and CISA's own feed
  wherever it is listed, passed over on KEV_OVERRIDE_RUNS runs since it
  last served a catalog that was not passed over (runs it did not answer
  do not count either way), or against a cache released over
  KEV_OVERRIDE_DAYS ago, is ``overridden``, and alerts at priority 1;
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
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Any

from boxmunge.config import ConfigError, load_config
from boxmunge.cve.kev import KEV_DEFAULT_SOURCES, KevCatalog, load_kev
from boxmunge.cve.kev_source_history import KevHistoryError, load_history, note_served
from boxmunge.cve.kev_withdrawals import KevWithdrawalsError, record_withdrawals
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
# A dateReleased further ahead than this is bogus, not clock skew: CISA
# stamps the catalog when it publishes it.
KEV_MAX_FUTURE_RELEASE = timedelta(hours=1)
# A source passed over as stalled on this many runs since it last served a
# catalog that was not (runs it did not answer do not count), or at once
# against a cache released this long ago, is past the bound: an override of
# the first source (or CISA's feed) alerts at priority 1, and its list stops
# guarding later sources' withdrawals.
KEV_OVERRIDE_RUNS = 2
KEV_OVERRIDE_DAYS = 7
_FETCH_TIMEOUT = 30
_MAX_LISTED = 10

# SourceFailure.kind values.
UNREACHABLE = "unreachable"  # no catalog came back (HTTP error, timeout, DNS)
REJECTED = "rejected"        # a catalog came back but failed a check
LAGGING = "lagging"          # a catalog came back, older than the cached one
DISAGREES = "disagrees"      # an earlier source's older catalog lacks cached IDs
CONFIG = "config"            # kev.sources in boxmunge.yml is unreadable or invalid
# Kinds that need the operator even while the cached catalog is fresh: a
# broken catalog or config would otherwise go unnoticed until it aged out.
_ALERTING_KINDS = (REJECTED, CONFIG, DISAGREES)


def _extra(detail: dict[str, Any]) -> dict[str, Any]:
    return {"component": "cve-scan", "project": None, "detail": detail}


@dataclass(frozen=True)
class SourceFailure:
    source: str
    kind: str
    error: str
    overridden: bool = False  # a DISAGREES of the first source, past the bound

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
    def disagreements(self) -> tuple[SourceFailure, ...]:
        """Earlier sources passed over because they lag the cached catalog."""
        return tuple(f for f in self.failures if f.kind == DISAGREES)

    @property
    def overridden(self) -> tuple[SourceFailure, ...]:
        """Disagreements of the first source (or CISA's) past the bound."""
        return tuple(f for f in self.failures if f.overridden)

    @property
    def needs_alert(self) -> bool:
        """True when nothing was cached and a failure needs the operator."""
        return not self.updated and any(f.kind in _ALERTING_KINDS for f in self.failures)


class _Failed(Exception):
    """A source answered with a catalog that cannot be used."""

    def __init__(self, kind: str, reason: str, ids: frozenset[str] = frozenset()) -> None:
        super().__init__(reason)
        self.kind = kind
        self.ids = ids  # a disagreeing source's IDs, which later ones may not drop
        self.released: datetime | None = None  # set once the catalog's date is known


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
        released = released.astimezone(timezone.utc) if released.tzinfo else (
            released.replace(tzinfo=timezone.utc))
    except (ValueError, OverflowError):
        # OverflowError: a valid-looking date that leaves datetime's range
        # in UTC (0001-01-01T00:00:00+14:00).
        raise _Failed(REJECTED, f"feed 'dateReleased' is not a timestamp: {raw!r}") from None
    if released > now + KEV_MAX_FUTURE_RELEASE:
        raise _Failed(REJECTED, f"feed 'dateReleased' {raw} is in the future "
                                f"(or this box's clock is behind)")
    return released


def _baseline(cached: KevCatalog, now: datetime, *, held_to_cache: bool) -> datetime | None:
    """The cached release time to guard against rollback, or None.

    Only a source no earlier in the list than the cache's own is held to it
    (``held_to_cache``). A future cached date (stored before future dates
    were refused) is no baseline either."""
    released = cached.released_at
    if not held_to_cache or released is None or released > now + KEV_MAX_FUTURE_RELEASE:
        return None
    return released


def _held_to_cache(url: str, sources: tuple[str, ...], cached: KevCatalog) -> bool:
    """Whether ``url`` ranks no higher than the source the cache came from.
    A cache from a source not on the list ranks below every listed one."""
    cache_rank = (sources.index(cached.source) if cached.source in sources
                  else len(sources))
    return sources.index(url) >= cache_rank


@dataclass(frozen=True)
class _Context:
    """What a source's catalog is judged against, beyond the cache."""
    held_to_cache: bool
    last_served: datetime | None   # what this source served last time, if seen
    contradicting: dict[str, frozenset[str]]  # earlier disagreeing source: its IDs


def _validate(
    payload: Any, cached: KevCatalog, now: datetime, paths: BoxPaths, ctx: _Context,
) -> tuple[list[str], datetime, list[str]]:
    """The catalog's sorted IDs, its release time and the cached IDs it
    drops, or _Failed (carrying the release time once it is known)."""
    # The feed may return valid JSON that is not an object (e.g. [] or null
    # from an error page).
    vulns = payload.get("vulnerabilities") if isinstance(payload, dict) else None
    if not isinstance(vulns, list):
        raise _Failed(REJECTED, "feed payload malformed (no 'vulnerabilities' list)")
    released = _released_at(payload, now)
    try:
        cve_ids, withdrawn = _check_content(vulns, released, cached, now, paths, ctx)
    except _Failed as e:
        e.released = released
        raise
    return cve_ids, released, withdrawn


def _check_content(
    vulns: list[Any], released: datetime, cached: KevCatalog, now: datetime,
    paths: BoxPaths, ctx: _Context,
) -> tuple[list[str], list[str]]:
    held_to_cache = ctx.held_to_cache
    baseline = _baseline(cached, now, held_to_cache=held_to_cache)
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
    # Not held to the cache, so not refused above: older, missing cached IDs
    # and no newer than its own last catalog means it has not caught up
    # (CVE-03). Before the removal limit, so a source far behind is not
    # misread as a mass withdrawal.
    newer = _baseline(cached, now, held_to_cache=True)
    stalled = ctx.last_served is not None and released <= ctx.last_served
    if withdrawn and newer is not None and released < newer and stalled:
        raise _Failed(DISAGREES, (
            f"catalog released {released.isoformat()} is older than the cached one "
            f"released {newer.isoformat()} (from {cached.source}), lacks "
            f"{len(withdrawn)} of its CVEs ({_listed(withdrawn)}) and is no newer than "
            f"the last one it served: the source is lagging, so the catalog was not "
            f"rolled back"), frozenset(cve_ids))
    for other, listed in ctx.contradicting.items():
        still = [c for c in withdrawn if c in listed]
        if still:
            raise _Failed(REJECTED, (
                f"it drops {_listed(still)}, which {other}, ranked above it, still lists: "
                f"the sources disagree, so neither catalog was cached"))
    if len(withdrawn) > KEV_MAX_REMOVALS:
        raise _Failed(REJECTED, (
            f"{len(withdrawn)} cached CVEs are missing from it (more than "
            f"{KEV_MAX_REMOVALS}): {_listed(withdrawn)}. If CISA really withdrew them, "
            f"remove the cache as root (rm {paths.kev_catalog}) and the next scan "
            f"accepts the catalog"))
    return cve_ids, withdrawn


def _failed(paths: BoxPaths, url: str, e: _Failed, cached: KevCatalog, now: datetime, *,
            protected: bool) -> tuple[SourceFailure, frozenset[str]]:
    """The failure of a source whose catalog failed a check, and the IDs
    later sources may not drop (a young disagreement's). One that came with
    a release date is recorded as served."""
    failure = SourceFailure(url, e.kind, f"{'rejected: ' if e.kind == REJECTED else ''}{e}")
    if e.released is None:
        return failure, frozenset()
    try:
        served = note_served(paths, url, e.released, disagreed=e.kind == DISAGREES)
    except KevHistoryError as h:
        return SourceFailure(url, REJECTED, f"{failure.error}; and {h}. Repair or remove "
                                            f"it as root"), frozenset()
    old = cached.released_at is not None and (
        now - cached.released_at > timedelta(days=KEV_OVERRIDE_DAYS))
    # Past the bound, a stalled source's list no longer guards withdrawals:
    # a mirror that stopped syncing must not freeze the catalog for good.
    long = e.kind == DISAGREES and (served.disagreed_runs >= KEV_OVERRIDE_RUNS or old)
    return replace(failure, overridden=long and protected), frozenset() if long else e.ids


def _try_source(
    paths: BoxPaths, url: str, cached: KevCatalog, ctx: _Context, *, protected: bool,
) -> tuple[SourceFailure | None, list[str], frozenset[str]]:
    """Fetch, check and cache one source's catalog: (failure, withdrawn IDs,
    the IDs of a disagreeing catalog)."""
    now = datetime.now(timezone.utc)
    try:
        cve_ids, released, withdrawn = _validate(
            _parse(_download(url)), cached, now, paths, ctx)
    except _Failed as e:
        failure, listed = _failed(paths, url, e, cached, now, protected=protected)
        return failure, [], listed
    except (OSError, http.client.HTTPException) as e:
        # HTTPError/URLError and socket errors are OSErrors; a body cut
        # short is an http.client.IncompleteRead.
        return SourceFailure(url, UNREACHABLE, _describe(e)), [], frozenset()
    try:
        # Before the cache: a withdrawal must outlive the catalog that made it.
        record_withdrawals(paths, url, withdrawn, cve_ids)
        note_served(paths, url, released, disagreed=False)
    except (KevWithdrawalsError, KevHistoryError) as e:
        return SourceFailure(url, REJECTED, f"fetched, but not cached: {e}. Repair or "
                                            f"remove it as root"), [], frozenset()
    doc = {
        "source": url,
        "released_at": released.isoformat(),
        "fetched_at": now.isoformat(),
        "cve_ids": cve_ids,
    }
    try:
        atomic_write_text(paths.kev_catalog, json.dumps(doc, indent=2) + "\n")
    except OSError as e:
        return (SourceFailure(url, REJECTED, f"fetched, but the cache write failed: {e}"),
                [], frozenset())
    return None, withdrawn, frozenset()


def _protected(url: str, sources: tuple[str, ...]) -> bool:
    """The first source, and CISA's own feed wherever it is listed: an
    override of either by a later source escalates."""
    return url == sources[0] or url == KEV_DEFAULT_SOURCES[0]


def refresh_from(paths: BoxPaths, sources: tuple[str, ...]) -> KevRefresh:
    """Try ``sources`` in order; cache the first catalog that passes."""
    cached = load_kev(paths)
    try:
        history = load_history(paths)
    except KevHistoryError as e:
        _LOGGER.warning("KEV refresh skipped: %s", e, extra=_extra({"error": str(e)}))
        return KevRefresh(source=None, failures=(SourceFailure(
            str(paths.kev_sources), REJECTED,
            f"{e}. Repair or remove it as root; until then no catalog is accepted"),))
    failures: list[SourceFailure] = []
    contradicting: dict[str, frozenset[str]] = {}
    for url in sources:
        seen = history.get(url)
        ctx = _Context(_held_to_cache(url, sources, cached),
                       seen.released_at if seen else None, dict(contradicting))
        failure, withdrawn, listed = _try_source(paths, url, cached, ctx,
                                                 protected=_protected(url, sources))
        if listed:
            contradicting[url] = listed
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
