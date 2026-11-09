# SPDX-License-Identifier: Apache-2.0
"""May a quarantine be lifted on this CISA KEV catalog?

The one rule the scan's automatic lift, `security resume` and the quarantine
deploy gate share. A stale or missing catalog reads as "nothing is
exploited" (cve.kev fails safe toward uptime for *new* quarantines), which
is exactly what must not be trusted to *end* one that rests on it:

- under `balanced` and `relaxed`, KEV is the only thing that quarantines,
  so every quarantine rests on it;
- under any posture, a quarantine taken for a CVE the cached catalog lists
  rests on it.

A `strict` or `paranoid` quarantine taken for a CVE the catalog does not
list was judged on severity, which a stale catalog does not hide; it lifts
as before. (Its re-scan still cannot see KEV overrides of lower-severity
findings while the catalog is stale; neither can the scan of any project
that is running, so keeping it down would buy nothing they do not have.)
"""
from __future__ import annotations

from datetime import date

from boxmunge.cve.kev import KEV_MAX_AGE_DAYS, KevCatalog
from boxmunge.cve.policy_types import Posture

_KEV_ONLY = frozenset({Posture.BALANCED, Posture.RELAXED})


def stale_kev_lift_refusal(posture: Posture, quarantined_cve: str | None,
                           kev: KevCatalog, today: date) -> str | None:
    """Why a quarantine of a project under ``posture``, recorded for
    ``quarantined_cve``, may not be lifted on ``kev`` today, or None.

    The reason names the cause and the command that fixes it."""
    if not kev.is_stale(today):
        return None
    if posture not in _KEV_ONLY and quarantined_cve not in kev.cve_ids:
        return None
    if kev.fetched_at is None:
        state = "there is no CISA KEV catalog on this box"
    else:
        state = (f"the CISA KEV catalog is stale (last fetched "
                 f"{kev.fetched_at.date().isoformat()}; the limit is {KEV_MAX_AGE_DAYS} days)")
    return (f"this quarantine rests on CISA's list of exploited CVEs, and {state}. A "
            f"stale catalog reads as \"nothing is exploited\", so it cannot show the "
            f"cause is gone. Refresh it with `boxmunge security scan` (it fetches the "
            f"catalog first; if the fetch fails, its KEV alert and `boxmunge log "
            f"--component cve-scan` name why), then retry.")
