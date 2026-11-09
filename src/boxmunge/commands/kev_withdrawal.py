# SPDX-License-Identifier: Apache-2.0
"""Hold a quarantine whose CVE this scan's KEV refresh withdrew.

Under balanced, a quarantine is held only for a KEV-listed CVE, so a
catalog that drops it clears the scan and would lift the quarantine on its
own. A single source can drop an entry (up to KEV_MAX_REMOVALS are accepted
from one refresh), so that lift waits for the operator. The record is
marked (quarantine.KEV_WITHDRAWAL_HOLD), so later scans keep it too, and
one priority-1 alert names the project, the CVE and the source.
`security resume` accepts the withdrawal: it lifts the quarantine and
removes the record.
"""
from __future__ import annotations

from boxmunge.cve.alerting import format_kev_withdrawal_hold_alert, send_alerts
from boxmunge.cve.kev import KevCatalog
from boxmunge.cve.quarantine import (
    KEV_WITHDRAWAL_HOLD, hold_for_kev_withdrawal, read_quarantine_state,
)
from boxmunge.log import log_warning
from boxmunge.paths import BoxPaths


def withdrawal_hold(paths: BoxPaths, project: str, kev: KevCatalog | None) -> str | None:
    """Why ``project``'s cleared quarantine is kept for a KEV withdrawal, or
    None. Marks the record and alerts the first time. Raises QuarantineError
    when the record cannot be read or written."""
    state = read_quarantine_state(project, paths) or {}
    cve = state.get("cve_id")
    source = state.get(KEV_WITHDRAWAL_HOLD)
    if source is None:
        if kev is None or cve not in kev.withdrawn:
            return None
        source = kev.source or "an unrecorded source"
        hold_for_kev_withdrawal(project, paths, source)
        _alert(paths, project, cve, source)
    return (f"quarantine kept: CISA KEV no longer lists {cve} (catalog from {source}); "
            f"`boxmunge security resume {project}` accepts the withdrawal")


def _alert(paths: BoxPaths, project: str, cve: str, source: str) -> None:
    try:
        send_alerts((format_kev_withdrawal_hold_alert(project, cve, source),), paths)
    except Exception as e:  # noqa: BLE001 — alerting must never block scan
        log_warning("cve-scan", f"KEV withdrawal hold alert failed for {project}: {e}",
                    paths, project=project, detail={"error": str(e)})
