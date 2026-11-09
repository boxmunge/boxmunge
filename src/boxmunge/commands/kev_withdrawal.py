# SPDX-License-Identifier: Apache-2.0
"""Hold a quarantine whose CVE a KEV refresh withdrew.

Under balanced, a quarantine is held only for a KEV-listed CVE, so a
catalog that drops it would let the next clean scan, or a deploy that
still ships the CVE, lift the quarantine. A single source can drop an
entry (up to KEV_MAX_REMOVALS are accepted from one refresh), so that lift
waits for the operator. The refresh records each withdrawal
(cve.kev_withdrawals) before it caches the catalog, so the hold applies in
every later run, including one that did not scan this project or whose scan
of it was incomplete, until `security resume` accepts the withdrawal (it
lifts the quarantine) or the catalog lists the CVE again.

The hold applies only while the images still contain the CVE: a scan or a
release without it is a fix, not a withdrawal. One priority-1 alert per
withdrawal names the project, the CVE and the source; the quarantine
record remembers it was sent (quarantine.KEV_WITHDRAWAL_HOLD).
"""
from __future__ import annotations

from collections.abc import Sequence

from boxmunge.cve.alerting import format_kev_withdrawal_hold_alert, send_alerts
from boxmunge.cve.kev_withdrawals import KevWithdrawalsError, load_withdrawals
from boxmunge.cve.policy import ProjectDecision
from boxmunge.cve.quarantine import (
    KEV_WITHDRAWAL_HOLD, hold_for_kev_withdrawal, read_quarantine_state,
)
from boxmunge.log import log_warning
from boxmunge.paths import BoxPaths


def _still_found(cve: str, decisions: Sequence[ProjectDecision]) -> bool:
    return any(f.finding.cve_id == cve for d in decisions for f in d.findings)


def _resume(project: str) -> str:
    return f"`boxmunge security resume {project}` accepts the withdrawal"


def withdrawal_hold(
    paths: BoxPaths, project: str, decisions: Sequence[ProjectDecision],
) -> str | None:
    """Why the quarantine that ``decisions`` (a clear scan) would lift is
    kept, or None. Marks the record and alerts once per withdrawal. Raises
    QuarantineError when the record cannot be read or written."""
    state = read_quarantine_state(project, paths) or {}
    cve = state.get("cve_id")
    try:
        withdrawals = load_withdrawals(paths)
    except KevWithdrawalsError as e:
        return f"quarantine kept: {e}; repair or remove it as root"
    withdrawal = withdrawals.get(cve)
    if withdrawal is None or not _still_found(cve, decisions):
        return None
    source, at = withdrawal
    if state.get(KEV_WITHDRAWAL_HOLD) != at:
        hold_for_kev_withdrawal(project, paths, at)
        _alert(paths, project, cve, source)
    return (f"quarantine kept: CISA KEV no longer lists {cve} (catalog from {source}); "
            f"{_resume(project)}")


def gate_hold(
    paths: BoxPaths, project: str, cve: str, decisions: Sequence[ProjectDecision],
) -> list[str] | None:
    """Why a release that clears ``project``'s quarantine must not lift it,
    as refusal lines, or None."""
    try:
        withdrawal = load_withdrawals(paths).get(cve)
    except KevWithdrawalsError as e:
        return [f"{e}. Repair or remove it as root, then deploy again."]
    if withdrawal is None or not _still_found(cve, decisions):
        return None
    return [f"This release still contains {cve}, which the CISA KEV catalog from "
            f"{withdrawal[0]} no longer lists. A single source can withdraw an entry, so "
            f"the quarantine stays until the operator accepts it: {_resume(project)}. "
            f"Or ship a release without {cve}. Nothing was started."]


def _alert(paths: BoxPaths, project: str, cve: str, source: str) -> None:
    try:
        send_alerts((format_kev_withdrawal_hold_alert(project, cve, source),), paths)
    except Exception as e:  # noqa: BLE001 — alerting must never block scan
        log_warning("cve-scan", f"KEV withdrawal hold alert failed for {project}: {e}",
                    paths, project=project, detail={"error": str(e)})
