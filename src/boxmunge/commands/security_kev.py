# SPDX-License-Identifier: Apache-2.0
"""The KEV catalog step of `boxmunge security scan`: refresh it once per
run, load it, and alert on what the refresh found."""
from __future__ import annotations

from datetime import datetime

from boxmunge.cve.alerting import (
    Alert,
    format_kev_stale_alert,
    format_kev_withdrawn_alert,
    send_alerts,
)
from boxmunge.cve.kev import KevCatalog, load_kev
from boxmunge.cve.kev_refresh import KevRefresh, refresh_kev
from boxmunge.log import log_warning
from boxmunge.paths import BoxPaths


def refresh_kev_and_alert(paths: BoxPaths, now: datetime) -> KevCatalog:
    """Refresh the CISA KEV catalog once per run and load it.

    The one catalog is threaded into every project scan so the exploitation
    signal is consistent fleet-wide. Fail-safe: a stale catalog never
    quarantines, and a rejected refresh keeps the previous cache (B-06), but
    either fires ONE priority-1 alert per run naming each source's error.
    Entries CISA withdrew (a few, accepted) get a normal-priority notice.
    """
    refresh = refresh_kev(paths)
    kev = load_kev(paths)
    if refresh.withdrawn:
        _send(paths, format_kev_withdrawn_alert(refresh.source, refresh.withdrawn))
    stale_reason = kev.stale_reason(now.date())
    if stale_reason is None and not refresh.needs_alert:
        return kev
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
