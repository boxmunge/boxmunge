# SPDX-License-Identifier: Apache-2.0
"""May a quarantine be lifted on this CISA KEV catalog?

A clear re-scan only means something if the exploitation signal behind it
can be trusted. A stale catalog reads as "nothing is exploited"
(cve.kev fails safe toward uptime for *new* quarantines), so the routes that
end a quarantine judge the catalog first, the same way:

- **fresh**: the lift goes ahead;
- **stale, but a catalog is cached**: judged against the cached IDs. If
  they list the quarantine's own CVE, or any CVE the scan found in the
  images, the lift is refused. Otherwise it goes ahead, and the lift alert
  (priority 1) names the gap: CVEs CISA added since the catalog was fetched
  could not be checked;
- **no usable catalog** (never fetched, or the cache is unreadable): refused
  under every posture, since nothing at all can be checked.

`security resume <project> --accept-stale-kev` is the audited way past a
refusal, for an operator who has judged the risk (security_resume). Every
refusal names it, and the ways to get fresh data first.

The scan's automatic lift is unattended, so it takes only the fresh case
(security_enforce.clears_quarantine). Staging lifts nothing, so the deploy
gate judges the catalog only for production (quarantine_gate).
"""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date

from boxmunge.cve.kev import KevCatalog
from boxmunge.cve.policy import ProjectDecision

ACCEPT_FLAG = "--accept-stale-kev"


@dataclass(frozen=True)
class KevLiftCheck:
    """``stale`` is why the catalog cannot be trusted (None: fresh).
    ``refusal`` is why the lift must not go ahead (None: it may), and ``gap``
    what a lift that goes ahead on a stale catalog could not check."""

    stale: str | None = None
    refusal: str | None = None
    gap: str | None = None


def fresh_data_advice() -> str:
    """How to get a fresh catalog, for every refusal."""
    return ("Get a fresh catalog: `boxmunge security scan` fetches it from each source in "
            "`kev.sources` in boxmunge.yml (by default CISA's feed, then CISA's GitHub "
            "mirror cisagov/kev-data); if no source answers from this box, add one it can "
            "reach to `kev.sources`")


def accept_advice(project: str) -> str:
    return (f"Or, having judged the risk, lift it anyway: `boxmunge security resume "
            f"{project} {ACCEPT_FLAG}` (logged and alerted)")


def check_kev_for_lift(quarantined_cve: str, decisions: Sequence[ProjectDecision],
                       kev: KevCatalog, today: date) -> KevLiftCheck:
    """Judge ``kev`` for lifting a quarantine recorded for ``quarantined_cve``
    whose re-scan produced ``decisions``."""
    stale = kev.stale_reason(today)
    if stale is None:
        return KevLiftCheck()
    if kev.unreadable is not None or kev.fetched_at is None:
        return KevLiftCheck(stale, refusal=(
            f"there is no usable CISA KEV catalog ({stale}), so boxmunge cannot tell "
            f"whether {quarantined_cve} or anything in the images is actively exploited"))
    in_images = {f.finding.cve_id for d in decisions for f in d.findings} & kev.cve_ids
    listed = []
    if quarantined_cve in kev.cve_ids:
        still = ", still in the images" if quarantined_cve in in_images else ""
        listed.append(f"{quarantined_cve} (the quarantine's CVE{still})")
    listed += [f"{cve} (in the images)" for cve in sorted(in_images - {quarantined_cve})]
    if listed:
        return KevLiftCheck(stale, refusal=(
            f"the CISA KEV catalog is stale ({stale}), and the cached copy lists "
            f"{', '.join(listed)} as actively exploited; a stale catalog cannot show that "
            f"has changed"))
    fetched = kev.fetched_at.date().isoformat()
    return KevLiftCheck(stale, gap=(
        f"the CISA KEV catalog is stale ({stale}). Neither the quarantine's CVE nor any CVE "
        f"in the images is on the cached copy, but CVEs CISA added since it was fetched "
        f"({fetched}) could not be checked"))
