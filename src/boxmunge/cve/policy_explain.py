# SPDX-License-Identifier: Apache-2.0
"""Operator-facing explanation strings for CVE policy dispositions.

Extracted from policy.py to keep the decision engine under the LoC budget.
Pure functions: value in, string out. No I/O, no decisions. Takes plain
label strings (not the Posture enum) so it imports nothing from policy.py.
"""
from __future__ import annotations

from boxmunge.cve.scanner import AttackVector, Severity


def explain_av_filter(
    attack_vector: AttackVector | None, posture_label: str,
) -> str:
    """Explanation for the v0.7.1 Attack Vector gate firing.

    Operator-facing prose: tell the reader why a non-trivial CVE got
    routed to informational, and how to opt back into the old behavior.
    """
    if attack_vector is None:
        return (
            "Attack vector unspecified in scanner data — defaulting to "
            f"informational under {posture_label} posture. Set posture: "
            "paranoid to quarantine on unspecified-AV findings."
        )
    av_label = attack_vector.value
    return (
        f"AV:{av_label[0]} ({av_label} attack vector) — not reachable from "
        f"network surface; informational under {posture_label} posture. To "
        "quarantine on local-AV findings, set posture: paranoid."
    )


def explain_threshold(
    base: Severity,
    effective: Severity,
    penalty: int,
    posture_label: str,
    threshold_label: str,
    *,
    over_threshold: bool,
    dangerously_disabled: bool,
) -> str:
    """One-line explanation for posture-threshold dispositions."""
    if base == effective:
        head = f"{base.value}, no upstream fix"
    else:
        head = (
            f"{base.value} → effective {effective.value} "
            f"(hardening penalty: +{penalty}), no upstream fix"
        )

    if over_threshold and dangerously_disabled:
        return (
            f"{head}. Meets {posture_label} threshold ({threshold_label}) — would "
            f"quarantine but dangerously_disable_quarantine: true. Read-only "
            f"rootfs is the remaining defense."
        )
    if over_threshold:
        return (
            f"{head}. Meets {posture_label} threshold ({threshold_label}) — "
            f"quarantine."
        )
    return (
        f"{head}. Below {posture_label} threshold ({threshold_label}) — "
        f"informational."
    )
