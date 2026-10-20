# SPDX-License-Identifier: Apache-2.0
"""Flagging a finding the stricter hardening penalty will quarantine from 0.12.

Split from policy.py (the decision engine). Pure: two dispositions in, one out.
"""
from __future__ import annotations

from dataclasses import replace

from boxmunge.cve.hardening import UpcomingHardening
from boxmunge.cve.policy_explain import explain_hardening_upcoming
from boxmunge.cve.policy_types import Disposition, FindingDisposition


def flag_upcoming(
    now: FindingDisposition, then: FindingDisposition, upcoming: UpcomingHardening,
) -> FindingDisposition:
    """``now`` under today's penalty, ``then`` under the 0.12 one."""
    if now.disposition == Disposition.QUARANTINE or then.disposition != Disposition.QUARANTINE:
        return now
    return replace(
        now, hardening_would_quarantine=True,
        explanation=explain_hardening_upcoming(
            upcoming.services, then.hardening_penalty - now.hardening_penalty,
            then.explanation))
