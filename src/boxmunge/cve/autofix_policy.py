# SPDX-License-Identifier: Apache-2.0
"""Autofix decisions: how soon a finding is patched, and whether its site is
dark while that happens.

Pure functions over a policy disposition (see policy.py): no I/O. They encode
the per-posture rules of the CVE autofix flowcharts. A finding is on the
patch path when its package is an OS package (``os-pkgs``) with a fixed
version; whether the image can actually be patched (apk or apt, and the
project's ``security.autofix``) is the caller's to check, as is
``dangerously_disable_quarantine``, which turns "dark" into running at risk.
"""
from __future__ import annotations

from datetime import timedelta
from enum import Enum

from boxmunge.cve.policy_types import Disposition, FindingDisposition, Posture
from boxmunge.cve.scanner import PkgClass

# An urgent patch attempt has this long from its own start (not from the
# detection: a project waiting its turn in the queue keeps its current state).
AUTOFIX_URGENT_BUDGET = timedelta(minutes=30)
# An urgent patch that has not started this long after its detection is
# stuck (the autofix unit does not start, or the project stays busy): the
# scan stops holding its quarantine back, alerts, and health warns.
AUTOFIX_QUEUE_MAX_WAIT = timedelta(hours=2)
# A nightly patch attempt (commands.autofix_nightly) has as long, from its
# own start: projects are patched one after another in the window.
AUTOFIX_NIGHTLY_BUDGET = timedelta(minutes=30)
# No nightly patch starts later in container-update's run than this, less
# its budget and a margin: the maintenance unit's limit covers the scan too.
NIGHTLY_AUTOFIX_WINDOW = timedelta(hours=3)

# A finding the policy takes down (or, opted out, runs at risk) for: a
# not-listed one with these and its patch gate is strict's overdue fix
# (cve.fix_grace), or paranoid's gate.
_DARK = frozenset({Disposition.QUARANTINE, Disposition.STILL_RUNNING_AT_RISK})

# A full-KEV finding at or above this CVSS score (or with none) is patched
# dark under balanced. The score is the highest any source gives.
CVSS_DOWNTIME_THRESHOLD = 9.0


class AutofixUrgency(Enum):
    URGENT = "urgent"    # patched now: known exploited, or paranoid at its gate
    NIGHTLY = "nightly"  # patched in the nightly window
    NONE = "none"        # not patched


def on_patch_path(fd: FindingDisposition) -> bool:
    """A fixed version exists and the package is an OS package."""
    return fd.finding.fix_available and fd.finding.pkg_class is PkgClass.OS


def nightly_eligible(fd: FindingDisposition, posture: Posture) -> bool:
    """On the patch path, not known exploited, and without the fix it would
    meet the gate (balanced's under relaxed), not suppressed: the policy
    records that as ``fix_meets_patch_gate``. Paranoid never waits for the window: a
    fixable finding at its gate is patched at once (``urgency``)."""
    return (posture is not Posture.PARANOID and on_patch_path(fd)
            and not fd.exploited_by and fd.fix_meets_patch_gate
            and fd.disposition is Disposition.IGNORED_FIXED)


def urgency(fd: FindingDisposition, posture: Posture) -> AutofixUrgency:
    """URGENT for a full-KEV finding on the patch path (no suppression applies
    to one), any listed one under paranoid, a VulnCheck-only one the policy
    does not suppress, a paranoid finding at its gate, and one strict's fix
    deadline took down (cve.fix_grace: it keeps its patch gate); NIGHTLY
    when ``nightly_eligible``; else NONE."""
    if not on_patch_path(fd):
        return AutofixUrgency.NONE
    # Paranoid takes every listing through the KEV override, where no
    # suppression applies, as it does for a full-KEV finding anywhere.
    if fd.full_kev or (fd.exploited_by and posture is Posture.PARANOID):
        return AutofixUrgency.URGENT
    if fd.exploited_by:  # VulnCheck only: the policy records the suppression
        return AutofixUrgency.URGENT if fd.fix_meets_patch_gate else AutofixUrgency.NONE
    if fd.fix_meets_patch_gate and (posture is Posture.PARANOID or fd.disposition in _DARK):
        return AutofixUrgency.URGENT
    if nightly_eligible(fd, posture):
        return AutofixUrgency.NIGHTLY
    return AutofixUrgency.NONE


def downtime_while_patching(fd: FindingDisposition, posture: Posture) -> bool:
    """Whether the site is dark while this finding is patched (table A).

    Full KEV: relaxed never; balanced at CVSS 9 or above, or unrated; strict
    and paranoid always. VulnCheck only: paranoid only. Not listed: a
    paranoid finding at its gate, and one strict's fix deadline took down;
    every other one is patched with the site up.
    Raises ValueError for a finding off the patch path: nothing is patched."""
    if not on_patch_path(fd):
        raise ValueError(
            f"{fd.finding.cve_id} in {fd.finding.package} is not on the patch path "
            f"(fix available: {fd.finding.fix_available}, "
            f"package class: {fd.finding.pkg_class.value})")
    if fd.full_kev:
        if posture is Posture.RELAXED:
            return False
        if posture is Posture.BALANCED:
            score = fd.finding.downtime_score()
            return score is None or score >= CVSS_DOWNTIME_THRESHOLD
        return True
    if fd.exploited_by:
        return posture is Posture.PARANOID
    return fd.fix_meets_patch_gate and (posture is Posture.PARANOID or fd.disposition in _DARK)
