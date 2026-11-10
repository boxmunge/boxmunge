# SPDX-License-Identifier: Apache-2.0
"""The KEV catalog step of `boxmunge security scan`: refresh it once per
run, load it, and alert on what the refresh found."""
from __future__ import annotations

from datetime import datetime

from boxmunge.cve.alerting import (
    Alert,
    format_kev_sources_disagree_alert,
    format_kev_stale_alert,
    format_kev_withdrawn_alert,
    send_alerts,
)
from boxmunge.cve.kev import KevCatalog, load_kev
from boxmunge.cve.kev_refresh import DISAGREES, LAGGING, KevRefresh, refresh_kev
from boxmunge.log import log_warning
from boxmunge.paths import BoxPaths


def refresh_kev_and_alert(paths: BoxPaths, now: datetime) -> KevCatalog:
    """Refresh the CISA KEV catalog once per run and load it.

    The one catalog is threaded into every project scan so the exploitation
    signal is consistent fleet-wide. Fail-safe: a stale catalog never
    quarantines, and a rejected refresh keeps the previous cache (B-06), but
    either fires ONE priority-1 alert per run naming each source's error.
    Entries CISA withdrew (a few, accepted) get a normal-priority notice;
    the refresh recorded them (cve.kev_withdrawals), so a quarantine held
    for one is kept, not lifted (kev_withdrawal). An earlier source passed
    over because it lags the cache (sources disagree) gets a notice when a
    later source was cached (priority 1 once that overrides the first
    source, kev_refresh.KEV_OVERRIDE_RUNS), and the priority-1 alert when
    none was.
    """
    refresh = refresh_kev(paths)
    kev = load_kev(paths)
    if refresh.withdrawn:
        _send(paths, format_kev_withdrawn_alert(refresh.source, refresh.withdrawn))
    if refresh.updated and refresh.disagreements:
        _send(paths, format_kev_sources_disagree_alert(
            refresh.source, [f.line() for f in refresh.disagreements],
            overridden=[f.source for f in refresh.overridden]))
    stale_reason = kev.stale_reason(now.date())
    if stale_reason is None and not refresh.needs_alert:
        return kev
    if stale_reason is not None and _all_lagging(refresh):
        stale_reason += ("; every source answered this run, but with a catalog "
                         "older than the cached one"
                         + (" (or older and missing some of its CVEs)"
                            if refresh.disagreements else ""))
    tried = _tried(refresh)
    log_warning(
        "cve-scan",
        "CISA KEV catalog degraded — exploitation-based quarantine at risk ("
        + (stale_reason or "refresh failed") + ")",
        paths, project=None,
        detail={"kev_source": kev.source, "stale_reason": stale_reason, "tried": tried},
    )
    _send(paths, format_kev_stale_alert(kev, stale_reason=stale_reason, tried=tried))
    return kev


def _all_lagging(refresh: KevRefresh) -> bool:
    return bool(refresh.failures) and all(
        f.kind in (LAGGING, DISAGREES) for f in refresh.failures)


def _tried(refresh: KevRefresh) -> list[str]:
    tried = [f.line() for f in refresh.failures]
    if refresh.source is not None:
        tried.append(f"{refresh.source}: answered")
    return tried


def _send(paths: BoxPaths, alert: Alert) -> None:
    try:
        send_alerts((alert,), paths)
    except Exception as e:  # noqa: BLE001 — alerting must never block scan
        log_warning("cve-scan", f"KEV alert emission failed: {e}", paths, project=None)
