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


def explain_kev_quarantine(
    cve_id: str, overridden_until: str | None = None, fixed_version: str | None = None,
) -> str:
    """Explanation for a KEV-override quarantine (actively exploited).

    ``overridden_until`` is the expiry of a suppression the KEV listing
    overrode: suppressions never hide a KEV-listed CVE (audit B-07).
    ``fixed_version`` is set when a fix exists that the image is not running.
    """
    text = (
        f"{cve_id} is on the CISA Known Exploited Vulnerabilities (KEV) "
        "catalog — actively exploited in the wild; quarantined regardless "
        "of posture, distro status, attack vector, or severity threshold."
    )
    if fixed_version is not None:
        text += (
            f" A fix is available ({fixed_version}) but this image is not "
            "running it: rebuild the image and deploy it. The deploy scans "
            "its images before anything starts and lifts the quarantine once "
            "it is live."
        )
    if overridden_until is not None:
        text += (
            f" The suppression for it (until {overridden_until}) does not "
            "apply: a suppression never hides a KEV-listed CVE."
        )
    return text


def explain_kev_opted_out(cve_id: str, fixed_version: str | None) -> str:
    """Explanation for a KEV finding on a project with quarantine disabled."""
    text = (
        f"{cve_id} is on the CISA Known Exploited Vulnerabilities (KEV) "
        "catalog — actively exploited in the wild — but this project sets "
        "dangerously_disable_quarantine: true, so it keeps running."
    )
    if fixed_version is not None:
        text += (
            f" A fix is available ({fixed_version}) but this image is not "
            "running it: rebuild the image and redeploy."
        )
    return text + " Alerted on every scan while the finding is live."


def explain_kev_fix_not_running(cve_id: str, fixed_version: str | None) -> str:
    """Explanation for a fixable KEV finding under relaxed posture."""
    return (
        f"{cve_id} is on the CISA Known Exploited Vulnerabilities (KEV) "
        f"catalog — actively exploited in the wild — and a fix is available "
        f"({fixed_version}) that this image is not running. Under relaxed "
        "posture a fixable KEV finding does not quarantine; rebuild the image "
        "and redeploy now. Alerted on every scan until the fix is running."
    )


def explain_fix_available(
    fixed_version: str | None, *, would_quarantine: bool, posture_label: str,
) -> str:
    """Explanation for a non-KEV finding with an upstream fix."""
    text = (
        f"Fix available upstream ({fixed_version}) but not running in this "
        "image. A deploy does not pull a newer base image: bump the image tag "
        "or digest, change FROM, or set compose `build: {pull: true}`, then "
        "redeploy (CVE_POLICY.md, \"Shipping a fix the upstream image does not "
        "have yet\"); boxmunge does not rebuild images for you."
    )
    if would_quarantine:
        text += (
            f" Without the fix this finding meets the {posture_label} "
            "quarantine gate."
        )
    return text


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


def explain_irrelevant_runtime(
    package: str,
    ecosystem: str,
    runtimes: frozenset[str],
    posture_label: str,
) -> str:
    """Explanation for a finding de-escalated because the runtime is unused."""
    if runtimes:
        runs = ", ".join(sorted(runtimes))
        tail = f"this project's runtime is {runs}"
    else:
        tail = "this project runs no language runtime"
    return (
        f"{package} is a {ecosystem} runtime package; {tail} — not on any "
        f"execution path. Informational under {posture_label} posture."
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
    severity_sources: tuple[str, ...] = (),
) -> str:
    """One-line explanation for posture-threshold dispositions.

    `severity_sources` names where `base` came from when it is not simply the
    scanner's severity (paranoid's highest rating across sources).
    """
    rated = base.value
    if severity_sources:
        rated = f"{base.value} (highest rating, from {', '.join(severity_sources)})"
    if base == effective:
        head = f"{rated}, no upstream fix"
    else:
        head = (
            f"{rated} → effective {effective.value} "
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


HARDENING_UPCOMING_FIX = (
    "Add `read_only: true` to the service in compose.yml, declare it in the "
    "manifest so boxmunge hardens it, or accept the risk: suppress the CVE "
    "after review, or choose a lower `security.posture`."
)


def hardening_cause(services: tuple[str, ...]) -> str:
    """Which services carry the extra penalty, and why it counts."""
    named = ", ".join(services) if services else "the project's services"
    return (
        f"{named}: boxmunge does not harden it as the penalty assumes (a "
        f"compose-only service without `read_only: true`, or a manifest "
        f"`cap_add` / `no_new_privileges: false`)"
    )


def explain_hardening_upcoming(
    services: tuple[str, ...], penalty: int, threshold_detail: str,
) -> str:
    """Why a finding that does not quarantine today will from 0.12, and the fix.

    ``threshold_detail`` is the explanation the finding gets under the 0.12
    penalty. 0.11.0 only warns."""
    return (
        f"WARNING, not quarantined yet: the stricter hardening penalty would "
        f"quarantine this finding. From 0.12 that penalty applies. "
        f"{threshold_detail} The extra penalty (+{penalty}) comes from "
        f"{hardening_cause(services)}. {HARDENING_UPCOMING_FIX}"
    )
