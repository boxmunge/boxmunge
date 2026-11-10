# SPDX-License-Identifier: Apache-2.0
"""May a quarantine be lifted on this CISA KEV catalog?

A clear re-scan only means something if the exploitation signal behind it
can be trusted. A stale catalog reads as "nothing is exploited"
(cve.kev fails safe toward uptime for *new* quarantines), so the routes that
end a quarantine judge the catalog first, the same way:

- **fresh**: the lift goes ahead;
- **stale, but a catalog is cached**: the CVEs the re-scan found in the
  images are judged against the cached IDs. If any is listed (the
  quarantine's own CVE on unchanged images, say), the lift is refused. A
  fix whose images no longer contain it goes ahead, and the lift alert
  (priority 1) names the gap: CVEs CISA added since the catalog was fetched
  could not be checked;
- **no usable catalog** (never fetched, or the cache is unreadable): refused
  under every posture, since nothing at all can be checked.

`security resume <project> --accept-stale-kev` is the audited way past the
no-usable-catalog refusal, for an operator who has judged the risk
(security_resume); `prod-deploy <project> --accept-stale-kev` is the same
for the release a deploy ships (commands/kev_acceptance). Neither ever
overrides a stale catalog that lists a CVE still in the images: a fresh
catalog could not lift that either, and a release without the CVE already
gets through. Every refusal names the exits that work from where the
operator is.

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
from boxmunge.redeploy_hint import redeploy_either

ACCEPT_FLAG = "--accept-stale-kev"


@dataclass(frozen=True)
class KevLiftCheck:
    """``stale`` is why the catalog cannot be trusted (None: fresh).
    ``refusal`` is why the lift must not go ahead (None: it may);
    ``acceptable`` whether `--accept-stale-kev` may override it (only when
    there is no usable catalog). ``gap`` is what a lift that goes ahead on
    a stale catalog could not check."""

    stale: str | None = None
    refusal: str | None = None
    acceptable: bool = False
    gap: str | None = None


def fresh_data_advice() -> str:
    """How to get a fresh catalog, for every refusal."""
    return ("Get a fresh catalog: `boxmunge security scan` fetches it from each source in "
            "`kev.sources` in boxmunge.yml (by default CISA's feed, then CISA's GitHub "
            "mirror cisagov/kev-data); if no source answers from this box, add one it can "
            "reach to `kev.sources`, for example an https copy of the feed you host")


def resume_exits(project: str, check: KevLiftCheck) -> list[str]:
    """What gets a project ``security resume`` refused out of quarantine."""
    exits = [f"{fresh_data_advice()}, then retry."]
    if check.acceptable:
        exits.append(f"Or, having judged the risk, lift it anyway: `boxmunge security resume "
                     f"{project} {ACCEPT_FLAG}` (logged and alerted). It brings the images "
                     f"the project runs now back online.")
    else:
        exits.append(f"Or deploy a release without those CVEs: upload it and run "
                     f"`prod-deploy {project}`, or rebuild the installed release on fixed "
                     f"base images with `{redeploy_either(project)}` (its images are "
                     f"scanned first). {ACCEPT_FLAG} does not apply: a fresh catalog would "
                     f"refuse this lift too.")
    return exits


def check_kev_for_lift(quarantined_cve: str, decisions: Sequence[ProjectDecision],
                       kev: KevCatalog, today: date) -> KevLiftCheck:
    """Judge ``kev`` for lifting a quarantine recorded for ``quarantined_cve``
    whose re-scan produced ``decisions``."""
    stale = kev.stale_reason(today)
    if stale is None:
        return KevLiftCheck()
    if kev.unreadable is not None or kev.fetched_at is None:
        return KevLiftCheck(stale, acceptable=True, refusal=(
            f"there is no usable CISA KEV catalog ({stale}), so boxmunge cannot tell "
            f"whether {quarantined_cve} or anything in the images is actively exploited"))
    in_images = {f.finding.cve_id for d in decisions for f in d.findings} & kev.cve_ids
    if in_images:
        listed = [f"{cve} (the quarantine's CVE)" if cve == quarantined_cve else cve
                  for cve in sorted(in_images)]
        return KevLiftCheck(stale, refusal=(
            f"the CISA KEV catalog is stale ({stale}), and the cached copy lists "
            f"{', '.join(listed)}, still in the images, as actively exploited; a stale "
            f"catalog cannot show that has changed"))
    fetched = kev.fetched_at.date().isoformat()
    return KevLiftCheck(stale, gap=(
        f"the CISA KEV catalog is stale ({stale}). No CVE in the images is on the cached "
        f"copy, but CVEs CISA added since it was fetched ({fetched}) could not be checked"))
