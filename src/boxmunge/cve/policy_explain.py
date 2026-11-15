# SPDX-License-Identifier: Apache-2.0
"""Operator-facing explanation strings for CVE policy dispositions.

Extracted from policy.py to keep the decision engine under the LoC budget.
Pure functions: value in, string out. No I/O, no decisions. Takes plain
label strings (not the Posture enum) so it imports nothing from policy.py.
"""
from __future__ import annotations

from boxmunge.cve.scanner import AttackVector, Severity, VulnStatus


def explain_relaxed_kev_only(listed_by: str) -> str:
    """Explanation for a non-KEV finding held informational under relaxed.
    ``listed_by`` names a weaker listing (VulnCheck) the finding has, or is ""."""
    text = (
        "relaxed posture: only a finding on the CISA or EU KEV list "
        "quarantines; everything else is informational regardless of distro "
        "severity. Raise the posture to balanced or strict to be alerted on "
        "distro severity, or paranoid to quarantine on it."
    )
    if listed_by:
        text += (f" It is listed as exploited by {listed_by} only, which does "
                 "not quarantine under relaxed; it is alerted urgently.")
    return text


def explain_awaiting_fix(
    base: Severity, effective: Severity, penalty: int,
    posture_label: str, threshold_label: str, listed_by: str,
) -> str:
    """Explanation for a finding at an alert-only severity gate (balanced, strict).
    ``listed_by`` names a weaker listing (VulnCheck) the finding has, or is ""."""
    rated = base.value if base == effective else (
        f"{base.value} → effective {effective.value} (hardening penalty: +{penalty})")
    if listed_by:
        exploited = (
            f"It is listed as exploited by {listed_by} only, which does not "
            f"quarantine under {posture_label} posture (gate: {threshold_label}): "
            "the site stays up and you are alerted urgently. You will also be "
            "alerted when a fix lands (then rebuild and redeploy) or if CISA or "
            "the EU lists it (then it quarantines).")
    else:
        exploited = (
            "It is not known to be exploited (not on the CISA or EU KEV lists), "
            f"so under {posture_label} posture (gate: {threshold_label}) the site "
            "stays up and nothing needs doing now. You will be alerted when a fix "
            "lands (then rebuild and redeploy) or if it is listed as actively "
            "exploited (then it quarantines).")
    return (
        f"{rated}, network-reachable, and no fix exists yet. {exploited} "
        "`security.posture: paranoid` takes such findings down."
    )


def explain_kev_quarantine(
    cve_id: str, listed_by: str, overridden_until: str | None = None, fixed_version: str | None = None,
) -> str:
    """Explanation for a KEV-override quarantine (actively exploited).

    ``overridden_until`` is the expiry of a suppression the KEV listing
    overrode: suppressions never hide a KEV-listed CVE (audit B-07).
    ``fixed_version`` is set when a fix exists that the image is not running.
    """
    text = (
        f"{cve_id} is known exploited ({listed_by}) — "
        "actively exploited in the wild; quarantined regardless "
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


def explain_kev_opted_out(cve_id: str, fixed_version: str | None, listed_by: str) -> str:
    """Explanation for a KEV finding on a project with quarantine disabled."""
    text = (
        f"{cve_id} is known exploited ({listed_by}) — "
        "actively exploited in the wild — but this project sets "
        "dangerously_disable_quarantine: true, so it keeps running."
    )
    if fixed_version is not None:
        text += (
            f" A fix is available ({fixed_version}) but this image is not "
            "running it: rebuild the image and redeploy."
        )
    return text + " Alerted on every scan while the finding is live."


def explain_kev_fix_not_running(
    cve_id: str, fixed_version: str | None, listed_by: str,
) -> str:
    """Explanation for a fixable KEV finding under relaxed posture."""
    return (
        f"{cve_id} is known exploited ({listed_by}) — "
        f"actively exploited in the wild — and a fix is available "
        f"({fixed_version}) that this image is not running. Under relaxed "
        "posture a fixable KEV finding does not quarantine; rebuild the image "
        "and redeploy now. Alerted on every scan until the fix is running."
    )


_REBUILD_ADVICE = (
    "A `build:` service is rebuilt on its base image's current digest by its "
    "next stage and promote, or prod-deploy (--redeploy when nothing new was "
    "uploaded); otherwise bump the image tag or digest, or, for a package the "
    "Dockerfile installs, set compose `build: {no_cache: true}`, then redeploy "
    "(CVE_POLICY.md, \"Base images and the build cache\"); boxmunge does not "
    "rebuild images for you."
)


def explain_fix_available(
    fixed_version: str | None, *, meets_gate: bool, posture_label: str,
) -> str:
    """Explanation for a non-KEV finding with an upstream fix."""
    text = (
        f"Fix available upstream ({fixed_version}) but not running in this "
        f"image. {_REBUILD_ADVICE}"
    )
    if meets_gate:
        text += (
            f" It meets the {posture_label} alert gate: not known to be "
            "exploited, so the site stays up, but apply the fix."
        )
    return text


def explain_fix_quarantine(fixed_version: str | None, *, dangerously_disabled: bool) -> str:
    """Explanation for a fixable finding at paranoid's gate: it takes the
    downtime until the fix runs."""
    if dangerously_disabled:
        held = ("it would be quarantined until the fix runs, but "
                "dangerously_disable_quarantine: true, so it keeps running")
    else:
        held = "it is quarantined until the fixed image runs"
    return (
        f"Fix available upstream ({fixed_version}) but not running in this "
        f"image. It meets the paranoid quarantine gate, so {held}. "
        f"{_REBUILD_ADVICE}"
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
    "after review, or choose `security.posture: balanced`, which quarantines "
    "only on actively exploited (CISA KEV) CVEs."
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
    services: tuple[str, ...], penalty: int, threshold_detail: str, *, quarantines: bool,
) -> str:
    """Why a finding below the posture's gate today meets it from 0.12, and the fix.

    ``threshold_detail`` is the explanation the finding gets under the 0.12
    penalty; ``quarantines`` says whether that is a quarantine (paranoid) or
    the alert and patch gate (strict). 0.11 only warns, and only strict and
    paranoid are judged under it (the postures where the penalty can decide
    downtime)."""
    if quarantines:
        head = ("WARNING, not quarantined yet: the stricter hardening penalty would "
                "quarantine this finding. From 0.12 that penalty applies.")
    else:
        head = ("WARNING, not acted on yet: the stricter hardening penalty lifts this "
                "finding to the posture's gate. From 0.12 that penalty applies: it "
                "raises the threshold at which a finding is alerted and patched, and "
                "a fix that is not deployed can start the fix deadline.")
    return (
        f"{head} {threshold_detail} The extra penalty (+{penalty}) comes from "
        f"{hardening_cause(services)}. {HARDENING_UPCOMING_FIX}"
    )
