# SPDX-License-Identifier: Apache-2.0
"""Container hardening profile — extracted from compose, scored to a penalty.

Split out of policy.py: parsing Docker Compose structures is a different
responsibility from deciding CVE dispositions, and policy.py was at its
LoC budget. Pure functions and one frozen dataclass; no I/O, no decisions.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

_MAX_HARDENING_PENALTY = 2


@dataclass(frozen=True)
class HardeningProfile:
    """Compose-derived hardening posture for a project.

    Captures the user's deviations from the boxmunge overlay's hardened
    baseline, after the overlay has been merged. v0.8 overlay enforces
    read_only=true, no-new-privileges=true, tmpfs:['/tmp'], and an empty
    cap_add by default — fields here are True iff the *applied* config
    still meets that baseline (read_only and no_new_privileges) or False
    if user config overrode it (extra_caps_added, privileged, or an
    explicit read_only:false in user compose).
    """

    read_only: bool
    no_new_privileges: bool
    extra_caps_added: bool
    privileged: bool


def calculate_hardening_penalty(profile: HardeningProfile) -> int:
    """Sum of step-elevations from the hardened default, capped at +2.

    +1 each for read_only disabled, no_new_privileges disabled, extra
    cap_add. +2 outright for privileged (validators block this upstream;
    we still tolerate it gracefully so the engine is total).
    """
    if profile.privileged:
        return _MAX_HARDENING_PENALTY

    penalty = 0
    if not profile.read_only:
        penalty += 1
    if not profile.no_new_privileges:
        penalty += 1
    if profile.extra_caps_added:
        penalty += 1
    return min(penalty, _MAX_HARDENING_PENALTY)


def hardening_profile_from_compose(
    compose: dict[str, Any],
    *,
    services_with_overlay: set[str] | None = None,
) -> HardeningProfile:
    """Extract the project's effective hardening profile from a parsed compose.yml.

    The project-level profile is the worst-case (most weakened) across all
    services — if any single service has read_only=False, the project's
    effective hardening is read_only=False. This matches the operator's
    risk model: a single weakened service exposes the project's blast radius.

    Reads the user's compose.yml — i.e. pre-overlay-merge. Boxmunge's overlay
    enforces hardening by default; this function captures user *deviations*
    from that baseline.

    `services_with_overlay`: services where boxmunge's hardening overlay is
    active (every service whose effective profile is not "off"). For these
    services we treat `no-new-privileges` AND `read_only` as enforced by the
    overlay even if the user's compose doesn't declare them explicitly — the
    overlay sets both (v0.8 made read_only a default), and `compose_validate`
    rejects user attempts to flip no-new-privileges back via
    `no-new-privileges:false`. If the user declares `read_only: false`
    explicitly, that wins (the v0.8 overlay generator omits its own
    read_only fragment for that service), so it correctly weakens the
    profile here. If `None` (default), assume every service has the
    overlay applied — backward-compatible with callers that haven't been
    updated and matches the common case for new deployments.

    `cap_add` is always user-driven and judged on the literal compose
    declaration regardless of overlay.

    For each service:
      - read_only: True iff overlay applies AND user did NOT declare
        `read_only: false`, OR (no overlay) `read_only: true` is explicitly set
      - no_new_privileges: True iff overlay applies OR (`security_opt`
        contains "no-new-privileges:true" AND no entry contains
        "no-new-privileges:false")
      - extra_caps_added: True iff `cap_add` is non-empty
      - privileged: True iff `privileged: true`

    Project-level: AND across services for the True-required fields, OR for
    the True-bad fields. With zero services we vacuously return a fully-
    hardened profile — there's nothing to scan, so policy is moot.
    """
    services = compose.get("services") or {}
    if not isinstance(services, dict) or not services:
        return HardeningProfile(
            read_only=True,
            no_new_privileges=True,
            extra_caps_added=False,
            privileged=False,
        )

    # When None, default to "every service has overlay applied" — every named
    # service is in the assumed set.
    overlay_set: set[str] = (
        services_with_overlay
        if services_with_overlay is not None
        else set(services.keys())
    )

    project_read_only = True
    project_no_new_privileges = True
    project_extra_caps_added = False
    project_privileged = False

    for svc_name, svc in services.items():
        if not isinstance(svc, dict):
            continue

        # read_only — v0.8: overlay enforces read-only rootfs by default for
        # non-off services. The only thing that weakens this is an explicit
        # `read_only: false` in user compose (the overlay generator omits
        # its read_only fragment when the user declared anything for that
        # field, and Compose merge gives us the user's literal value).
        # For off-profile services (no overlay), only an explicit
        # `read_only: true` counts.
        if svc_name in overlay_set:
            svc_ro = svc.get("read_only") is not False
        else:
            svc_ro = svc.get("read_only") is True
        if not svc_ro:
            project_read_only = False

        # no_new_privileges — overlay enforces it for non-off services.
        # Otherwise, fall back to literal compose declaration.
        if svc_name in overlay_set:
            svc_nnp = True
        else:
            sec_opt = svc.get("security_opt") or []
            if not isinstance(sec_opt, list):
                sec_opt = []
            has_true = any(s == "no-new-privileges:true" for s in sec_opt)
            has_false = any(s == "no-new-privileges:false" for s in sec_opt)
            svc_nnp = has_true and not has_false
        if not svc_nnp:
            project_no_new_privileges = False

        # extra_caps_added — any non-empty cap_add list weakens. Overlay's
        # cap_drop is extended (not replaced) by user cap_add, so a user
        # cap_add really does relax the profile.
        cap_add = svc.get("cap_add") or []
        if isinstance(cap_add, list) and len(cap_add) > 0:
            project_extra_caps_added = True

        # privileged — any True weakens. Already rejected by compose_validate
        # on non-off services, but tolerated here for tests / off-profile.
        if svc.get("privileged") is True:
            project_privileged = True

    return HardeningProfile(
        read_only=project_read_only,
        no_new_privileges=project_no_new_privileges,
        extra_caps_added=project_extra_caps_added,
        privileged=project_privileged,
    )
