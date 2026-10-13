# SPDX-License-Identifier: Apache-2.0
"""User compose.yml validator — guards the silent-floor hardening claim.

A user-authored `compose.yml` is merged with boxmunge's generated
`compose.boxmunge.yml` overlay. This module parses compose.yml *before*
the overlay is generated and rejects anything that would defeat the
silent floor. The per-key rules live in `compose_service_rules` and the
mount rules in `compose_mounts`; this module orchestrates them and adds
the project-level cross-checks (CVE policy, overlay dedupe, writable).
Services explicitly opted out via `security.profile: off` get warnings
instead of rejection — every offender is surfaced so the operator sees
the full picture.
"""
from __future__ import annotations

from typing import Any

import yaml

from boxmunge.compose_mounts import has_named_volume
from boxmunge.compose_service_rules import service_findings
from boxmunge.log import log_warning
from boxmunge.paths import BoxPaths
from boxmunge.security_overlay import (
    PROFILE_DEFAULT,
    PROFILE_OFF,
    overlay_security_opt_for_profile,
)


class ComposeSecurityError(Exception):
    """Raised when a user compose.yml declares a key that defeats hardening."""


# ---------------------------------------------------------------------------
# v0.6.0 CVE-policy cross-validators
#
# These run after the per-service hostile-key pass, only when the relevant
# project-level CVE-policy field is set. Each helper returns a violation
# message for a single service or None — the caller decides whether to
# raise (non-off service) or warn (off service).
# ---------------------------------------------------------------------------

_DISABLE_QUARANTINE_MSG = (
    "service {svc}: dangerously_disable_quarantine: true requires\n"
    "read_only: true. Either drop dangerously_disable_quarantine from the\n"
    "manifest's security: block, or restore read-only rootfs on this\n"
    "service. Read-only rootfs is the only remaining post-exploit defense\n"
    "when CVE quarantine is disabled."
)

_STRICT_POSTURE_MSG = (
    "service {svc}: posture 'strict' requires read_only: true. Strict\n"
    "posture quarantines on Medium-severity CVEs; this requires defense in\n"
    "depth. Either lower posture to 'balanced'/'relaxed' or restore\n"
    "read-only rootfs on this service."
)


def _service_is_read_only(svc: dict[str, Any]) -> bool:
    """True iff the service explicitly declares `read_only: true`.

    Anything else (False, missing, None, truthy non-bool) violates — this
    is a deliberate boolean-identity check, not a truthiness test.
    """
    return svc.get("read_only") is True


def _check_disable_quarantine_requires_readonly(
    svc: dict[str, Any], svc_name: str
) -> str | None:
    if _service_is_read_only(svc):
        return None
    return _DISABLE_QUARANTINE_MSG.format(svc=svc_name)


def _check_strict_posture_requires_readonly(
    svc: dict[str, Any], svc_name: str
) -> str | None:
    if _service_is_read_only(svc):
        return None
    return _STRICT_POSTURE_MSG.format(svc=svc_name)


# ---------------------------------------------------------------------------
# Compose-merge dedupe (audit "Compose merge dedupe — Option C")
#
# Background: Docker Compose v2's multi-file merge promotes `security_opt`
# from override-overwrite to list-extend. If the user's compose.yml AND the
# boxmunge overlay both declare `["no-new-privileges:true"]`, the merged
# result has the entry twice — and Compose v2 explicitly rejects duplicate
# items in `security_opt`. The v0.6.3 hotfix addressed this with operator
# guidance ("don't redeclare it"); this validator adds defense-in-depth so
# the operator gets a clear actionable error before the docker-compose
# stack trace ever fires.
#
# Off-profile services skip this check: they are explicitly out of the
# overlay's coverage, so any security_opt entry in their compose.yml is
# theirs to manage alone.
# ---------------------------------------------------------------------------


_OVERLAY_DEDUPE_MSG = (
    'service {svc}: security_opt entry "{entry}" is redundant — the '
    "boxmunge default-profile overlay already sets it, and Docker Compose "
    "rejects duplicate list items at merge time. Remove this entry from "
    "your compose.yml; v0.6.2+ recognises the overlay's enforcement when "
    "calculating the CVE hardening penalty, so removing the duplicate has "
    "no effect on your project's security posture."
)


def _check_overlay_dedupe(
    services: dict[str, Any], off: set[str],
) -> tuple[str, str] | None:
    """Return (svc_name, redundant_entry) for the first overlap, or None.

    Compares each non-off service's user-declared security_opt against
    the overlay's emitted list. The default profile is the only profile
    that emits anything in v0.5/v0.6 — when other profiles ship, this
    helper widens to look up the effective profile per service.
    """
    overlay_opts = set(overlay_security_opt_for_profile(PROFILE_DEFAULT))
    if not overlay_opts:
        return None
    for svc_name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        if svc_name in off:
            continue
        user_opts = svc.get("security_opt")
        if not isinstance(user_opts, list):
            continue
        for entry in user_opts:
            if isinstance(entry, str) and entry in overlay_opts:
                return (svc_name, entry)
    return None



def _check_writable_conflict(
    services: dict[str, Any],
    manifest_services: dict[str, Any],
) -> None:
    """Enforce v0.9 three-state writable cutover.

    For each service in the user compose, classify via the manifest's
    writable: block:
      EXTERNAL — compose tmpfs/volumes OK, skip
      DEFAULT / MANAGED — compose tmpfs and named-volumes forbidden

    Bind mounts (./code, /absolute, ~) and boxmunge's own smoke-scripts
    mount don't count as writability declarations and pass through.

    Raises ComposeSecurityError on the first conflict with migration
    text pointing the operator at services.<svc>.writable.
    """
    # Lazy import keeps compose_validate independent of writable module
    # ordering. (writable.py has no deps on compose_validate.)
    from boxmunge.writable import WritableState, classify_state

    for svc_name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        manifest_svc = manifest_services.get(svc_name)
        if not isinstance(manifest_svc, dict):
            # Service exists in compose but not in manifest — that's a
            # separate concern (handled elsewhere). Skip writable check.
            continue
        state = classify_state(manifest_svc)
        if state is WritableState.EXTERNAL:
            continue

        has_tmpfs = isinstance(svc.get("tmpfs"), list) and len(svc["tmpfs"]) > 0
        has_named_vol = has_named_volume(svc.get("volumes"))

        if not has_tmpfs and not has_named_vol:
            continue

        kind = "tmpfs" if has_tmpfs else "volumes"
        if state is WritableState.MANAGED:
            raise ComposeSecurityError(
                f"services.{svc_name}: compose.yml declares {kind} but the "
                f"manifest declares services.{svc_name}.writable — that "
                f"surface is owned by boxmunge. Remove the compose-side "
                f"{kind} declaration, or restructure under "
                f"services.{svc_name}.writable.ephemeral / .persistent, "
                f"or set services.{svc_name}.writable.external: true to "
                f"manage writability in compose.yml directly."
            )
        # DEFAULT (no writable block in manifest)
        raise ComposeSecurityError(
            f"services.{svc_name}: compose.yml declares {kind} but the "
            f"manifest has no writable: block for this service. Boxmunge "
            f"owns this surface by default. Declare paths in "
            f"services.{svc_name}.writable.ephemeral (for tmpfs) or "
            f"services.{svc_name}.writable.persistent (for named volumes), "
            f"or set services.{svc_name}.writable.external: true to "
            f"manage writability in compose.yml directly."
        )


def _enforce_cve_rule(
    services: dict[str, Any],
    off: set[str],
    paths: BoxPaths,
    project_name: str | None,
    rule_label: str,
    check_fn,
) -> None:
    """Run a CVE-policy rule across all services.

    Off services log every offender; the first non-off offender raises.
    Off-service warnings are emitted before any raise (matches the existing
    multi-hit hostile-key pattern in the per-service pass).
    """
    pending_raise: tuple[str, str] | None = None
    for svc_name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        violation = check_fn(svc, svc_name)
        if violation is None:
            continue
        if svc_name in off:
            log_warning(
                "compose-validate",
                f"{rule_label} on service {svc_name} "
                f"(profile: off — allowed): read_only is not true",
                paths,
                project=project_name,
            )
            continue
        if pending_raise is None:
            pending_raise = (svc_name, violation)
    if pending_raise is not None:
        raise ComposeSecurityError(pending_raise[1])



# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def validate_user_compose(
    compose_path,
    paths: BoxPaths,
    off_services: set[str] | None = None,
    project_name: str | None = None,
    cve_policy: dict | None = None,
    manifest_services: dict | None = None,
) -> None:
    """Parse compose.yml and reject hostile keys.

    For services in `off_services` (those with `security.profile: off` in
    the manifest), hostile keys produce log_warning entries instead of
    raising. For multi-entry fields (cap_add, security_opt, volumes) every
    offender is logged.

    `project_name` is threaded into log_warning so structured logs can be
    filtered with `boxmunge log --project <name>` (audit E-NEW-2).

    `cve_policy` is the project-level security: block (or None / empty).
    Two project-level CVE-policy fields demand defense in depth:
      - `dangerously_disable_quarantine: true` requires `read_only: true`
        on every non-off service.
      - `posture: 'strict'` requires `read_only: true` on every non-off
        service.
    Off services log a warning instead of raising. Rule A (disable
    quarantine) runs before Rule B (strict posture) — first rejection wins.

    Raises ComposeSecurityError on the first hostile key in a non-off
    service, or if the file cannot be read/parsed.
    """
    off = off_services or set()
    base_dir = compose_path.parent

    try:
        raw = compose_path.read_text()
    except OSError as e:
        raise ComposeSecurityError(
            f"could not parse compose.yml: cannot read {compose_path}: {e}"
        ) from e

    try:
        doc = yaml.safe_load(raw)
    except yaml.YAMLError as e:
        raise ComposeSecurityError(f"could not parse compose.yml: {e}") from e

    if doc is None:
        return
    if not isinstance(doc, dict):
        raise ComposeSecurityError(
            f"could not parse compose.yml: top level must be a mapping, "
            f"got {type(doc).__name__}"
        )

    if "name" in doc:
        raise ComposeSecurityError(
            f"compose.yml sets a top-level name: {doc['name']!r}. boxmunge "
            f"names the compose project after the boxmunge project (and "
            f"'<project>-staging' for staging), so a name: line could point "
            f"commands at another project's containers and volumes. Remove "
            f"the top-level name: line."
        )

    services = doc.get("services") or {}
    if not isinstance(services, dict):
        raise ComposeSecurityError(
            f"could not parse compose.yml: 'services' must be a mapping, "
            f"got {type(services).__name__}"
        )

    # Compose-only services (not in the manifest) inherit the project-level
    # profile, exactly as the overlay generator resolves them.
    if isinstance(manifest_services, dict) and (cve_policy or {}).get("profile") == PROFILE_OFF:
        off = off | {name for name in services if name not in manifest_services}

    for svc_name, svc in services.items():
        if not isinstance(svc, dict):
            continue

        findings = service_findings(svc, base_dir, paths)
        if not findings:
            continue

        if svc_name in off:
            for f in findings:
                log_warning(
                    "compose-validate",
                    f"hostile compose key {f.key} on service {svc_name} "
                    f"(profile: off — allowed): {f.value}",
                    paths,
                    project=project_name,
                )
            continue

        first = findings[0]
        raise ComposeSecurityError(
            f"service {svc_name}: {first.key} = {first.value} {first.advice}"
        )

    # Compose-merge dedupe defense-in-depth. Reject any user-declared
    # security_opt entry that the boxmunge overlay would also emit for a
    # non-off service — Docker Compose v2 rejects duplicate list items
    # at merge time and the operator should see a clear actionable error
    # before the docker-compose stack trace fires. (v0.6.3 footgun;
    # Wave 3 / architecture audit Option C.)
    overlay_overlap = _check_overlay_dedupe(services, off)
    if overlay_overlap is not None:
        svc_name, entry = overlay_overlap
        raise ComposeSecurityError(
            _OVERLAY_DEDUPE_MSG.format(svc=svc_name, entry=entry)
        )

    # CVE-policy cross-validation. Rule A first, then Rule B — order is
    # part of the spec. Each rule is inert unless its triggering field is
    # set, so the common path (no CVE policy) is a single dict lookup.
    policy = cve_policy or {}
    if policy.get("dangerously_disable_quarantine") is True:
        _enforce_cve_rule(
            services, off, paths, project_name,
            rule_label="dangerously_disable_quarantine requires read_only",
            check_fn=_check_disable_quarantine_requires_readonly,
        )
    if policy.get("posture") == "strict":
        _enforce_cve_rule(
            services, off, paths, project_name,
            rule_label="posture 'strict' requires read_only",
            check_fn=_check_strict_posture_requires_readonly,
        )

    # v0.9: writable three-state conflict matrix. Skipped if the caller
    # didn't pass manifest_services (legacy callers + tests that focus on
    # other rules); active callers (deploy/stage/resume/upgrade) always
    # pass it post-v0.9.
    if manifest_services is not None and isinstance(manifest_services, dict):
        _check_writable_conflict(services, manifest_services)
