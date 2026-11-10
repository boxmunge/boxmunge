# SPDX-License-Identifier: Apache-2.0
"""Hold a quarantine while its images contain a CVE a KEV refresh withdrew.

Under balanced, a quarantine stands only on KEV-listed CVEs. If a catalog
drops one the images still contain, the next clean scan, or a deploy that
still ships it, would lift the quarantine. That holds whether it is the
CVE the quarantine was recorded for or another one in the same images: fix
A, and B (withdrawn by one source, maybe still exploited) would go live. A
single source can drop an entry (up to KEV_MAX_REMOVALS are accepted from
one refresh), so that lift waits for the operator.

The refresh records each withdrawal (cve.kev_withdrawals) before it caches
the catalog, so the hold applies in every later run, including one that
did not scan this project or whose scan of it was incomplete. It lasts
until `security resume` accepts the withdrawal for this project (recorded,
so it is not held for it again) or the catalog lists the CVE again.

The hold applies only to withdrawn CVEs the images still contain: a scan or
release without them is a fix. One priority-1 alert per withdrawal names
the project, the CVE and the source; the quarantine record remembers which
were delivered (quarantine.KEV_WITHDRAWAL_HOLD), so one that did not go out
is sent again by the next scan.
"""
from __future__ import annotations

from collections.abc import Sequence

from boxmunge.cve.alerting import format_kev_withdrawal_hold_alert, send_alerts
from boxmunge.cve.kev_withdrawals import KevWithdrawalsError, Withdrawal, load_withdrawals
from boxmunge.cve.policy import ProjectDecision
from boxmunge.cve.quarantine import (
    KEV_WITHDRAWAL_HOLD, hold_for_kev_withdrawal, read_quarantine_state,
)
from boxmunge.log import log_warning
from boxmunge.paths import BoxPaths


def held_withdrawals(
    paths: BoxPaths, project: str, decisions: Sequence[ProjectDecision],
) -> dict[str, Withdrawal]:
    """The withdrawn CVEs ``decisions`` still find that ``project`` has not
    accepted. Raises KevWithdrawalsError."""
    found = {f.finding.cve_id for d in decisions for f in d.findings}
    return {cve: w for cve, w in sorted(load_withdrawals(paths).items())
            if cve in found and project not in w.accepted}


def _resume(project: str) -> str:
    return f"`boxmunge security resume {project}` accepts the withdrawal"


def _named(held: dict[str, Withdrawal]) -> str:
    return ", ".join(f"{cve} (catalog from {w.source})" for cve, w in held.items())


def withdrawal_hold(
    paths: BoxPaths, project: str, decisions: Sequence[ProjectDecision],
) -> str | None:
    """Why the quarantine that ``decisions`` (a clear scan) would lift is
    kept, or None. Alerts once per withdrawal: sent first, recorded once
    delivered. Raises QuarantineError when the record cannot be read or
    written."""
    try:
        held = held_withdrawals(paths, project, decisions)
    except KevWithdrawalsError as e:
        return f"quarantine kept: {e}; repair or remove it as root"
    if not held:
        return None
    announced = dict((read_quarantine_state(project, paths) or {}).get(KEV_WITHDRAWAL_HOLD) or {})
    new = {cve: w for cve, w in held.items() if announced.get(cve) != w.at}
    delivered = {cve: w.at for cve, w in new.items() if _alert(paths, project, cve, w.source)}
    if delivered:
        hold_for_kev_withdrawal(project, paths, {**announced, **delivered})
    return (f"quarantine kept: CISA KEV no longer lists {_named(held)}, still in the images; "
            f"{_resume(project)}")


def gate_hold(
    paths: BoxPaths, project: str, decisions: Sequence[ProjectDecision],
) -> list[str] | None:
    """Why a release that clears ``project``'s quarantine must not lift it,
    as refusal lines, or None."""
    try:
        held = held_withdrawals(paths, project, decisions)
    except KevWithdrawalsError as e:
        return [f"{e}. Repair or remove it as root, then deploy again."]
    if not held:
        return None
    return [f"This release still contains {_named(held)}, which the CISA KEV catalog no "
            f"longer lists. A single source can withdraw an entry, so the quarantine stays "
            f"until the operator accepts it: {_resume(project)}. Or ship a release without "
            f"{', '.join(held)}. Nothing was started."]


def _alert(paths: BoxPaths, project: str, cve: str, source: str) -> bool:
    """Whether the alert was delivered (notify logs every non-delivery)."""
    try:
        return send_alerts((format_kev_withdrawal_hold_alert(project, cve, source),), paths) > 0
    except Exception as e:  # noqa: BLE001 — alerting must never block scan
        log_warning("cve-scan", f"KEV withdrawal hold alert failed for {project}: {e}",
                    paths, project=project, detail={"error": str(e)})
        return False
