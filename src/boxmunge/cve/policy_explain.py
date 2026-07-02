# SPDX-License-Identifier: Apache-2.0
"""Operator-facing explanation strings for CVE policy dispositions.

Extracted from policy.py to keep the decision engine under the LoC budget.
Pure functions: value in, string out. No I/O, no decisions. Takes plain
label strings (not the Posture enum) so it imports nothing from policy.py.
"""
from __future__ import annotations

from boxmunge.cve.scanner import AttackVector, Severity, VulnStatus


def explain_relaxed_kev_only() -> str:
    """Explanation for a non-KEV finding held informational under relaxed."""
    return (
        "relaxed posture: only actively-exploited (CISA KEV) findings "
        "quarantine; everything else is informational regardless of distro "
        "severity. Raise the posture to balanced or strict for "
        "distro-severity-based quarantine."
    )


def explain_kev_quarantine(cve_id: str) -> str:
    """Explanation for a KEV-override quarantine (actively exploited)."""
    return (
        f"{cve_id} is on the CISA Known Exploited Vulnerabilities (KEV) "
        "catalog — actively exploited in the wild; quarantined regardless "
        "of posture, distro status, attack vector, or severity threshold."
    )


def explain_distro_deprioritized(
    status: VulnStatus, distro_sev: Severity | None,
) -> str:
    """Explanation for a distro-deprioritized status routed to informational."""
    sev = distro_sev.value if distro_sev is not None else "unrated"
    return (
        f"Distro status: {status.value} (distro severity: {sev}) — the "
        "distribution does not treat this as an actionable, urgent fix. "
        "Informational; site stays up. Set posture: paranoid to quarantine "
        "on it anyway."
    )


def explain_no_distro_verdict(finding_sev: Severity) -> str:
    """Explanation for a finding with no OS-distro severity (only NVD/GHSA)."""
    return (
        f"No distro verdict (only upstream feeds rate this {finding_sev.value}). "
        "Below paranoid posture, quarantine requires the distribution's own "
        "assessment or CISA KEV membership. Informational."
    )


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
