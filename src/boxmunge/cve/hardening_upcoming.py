# SPDX-License-Identifier: Apache-2.0
"""Flagging a finding the stricter hardening penalty lifts to the gate from 0.12.

Split from policy.py (the decision engine). Pure: two dispositions in, one out.
"""
from __future__ import annotations

from dataclasses import replace

from boxmunge.cve.hardening import UpcomingHardening
from boxmunge.cve.policy_explain import explain_hardening_upcoming
from boxmunge.cve.policy_types import Disposition, FindingDisposition


def _meets_gate(d: FindingDisposition) -> bool:
    """Quarantined (paranoid), alerted as awaiting a fix (strict), or, fixable,
    at the gate that alerts and patches it."""
    return d.disposition in (Disposition.QUARANTINE, Disposition.AWAITING_FIX) or (
        d.fix_would_quarantine)


def flag_upcoming(
    now: FindingDisposition, then: FindingDisposition, upcoming: UpcomingHardening,
) -> FindingDisposition:
    """``now`` under today's penalty, ``then`` under the 0.12 one."""
    if _meets_gate(now) or not _meets_gate(then):
        return now
    return replace(
        now, hardening_would_quarantine=True,
        explanation=explain_hardening_upcoming(
            upcoming.services, then.hardening_penalty - now.hardening_penalty,
            then.explanation, quarantines=then.disposition is Disposition.QUARANTINE))
