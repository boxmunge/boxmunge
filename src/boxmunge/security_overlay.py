# SPDX-License-Identifier: Apache-2.0
"""Per-service container hardening — profile resolver + compose overlay renderer.

Pure module: no I/O, no logging, no platform calls. Consumes a manifest dict,
emits a per-service compose fragment.
"""
from __future__ import annotations

from typing import Any

# Profile names. v0.5 ships `default` and `off`. Future tiers add `strict` and
# `paranoid`; their names are reserved now so a manifest setting them today
# fails validation rather than silently doing nothing.
PROFILE_DEFAULT = "default"
PROFILE_OFF = "off"
KNOWN_PROFILES: set[str] = {PROFILE_DEFAULT, PROFILE_OFF}
RESERVED_PROFILES: set[str] = {"strict", "paranoid"}

# v0.6.0 CVE policy: project-level posture controls quarantine severity
# threshold. Independent of `profile` — the two coexist freely. Default
# (when absent) is interpreted as "balanced" by downstream readers; we
# do NOT inject a default into the manifest dict during validation.
POSTURE_RELAXED = "relaxed"
POSTURE_BALANCED = "balanced"
POSTURE_STRICT = "strict"
KNOWN_POSTURES: set[str] = {POSTURE_RELAXED, POSTURE_BALANCED, POSTURE_STRICT}

# Default `cap_drop` list. Capabilities in this list are NOT in Docker's
# default deny set, but are dangerous and rarely needed by application code.
# See spec §"Default cap_drop list" for rationale per cap.
DEFAULT_CAP_DROP: list[str] = [
    "NET_ADMIN",
    "SYS_PTRACE",
    "SYS_MODULE",
    "SYS_RAWIO",
    "SYS_TIME",
    "SYS_BOOT",
    "MAC_ADMIN",
    "MAC_OVERRIDE",
    "MKNOD",
    "AUDIT_WRITE",
    "WAKE_ALARM",
    "BLOCK_SUSPEND",
    "LEASE",
    "NET_RAW",
]

# Whitelist of cap names accepted in user-supplied cap_drop / cap_add fields.
# Validation rejects anything outside this set.
VALID_CAP_NAMES: set[str] = {
    "AUDIT_CONTROL", "AUDIT_READ", "AUDIT_WRITE",
    "BLOCK_SUSPEND", "BPF",
    "CHOWN", "DAC_OVERRIDE", "DAC_READ_SEARCH",
    "FOWNER", "FSETID",
    "IPC_LOCK", "IPC_OWNER",
    "KILL", "LEASE", "LINUX_IMMUTABLE",
    "MAC_ADMIN", "MAC_OVERRIDE", "MKNOD",
    "NET_ADMIN", "NET_BIND_SERVICE", "NET_BROADCAST", "NET_RAW",
    "PERFMON",
    "SETFCAP", "SETGID", "SETPCAP", "SETUID",
    "SYS_ADMIN", "SYS_BOOT", "SYS_CHROOT", "SYS_MODULE",
    "SYS_NICE", "SYS_PACCT", "SYS_PTRACE", "SYS_RAWIO",
    "SYS_RESOURCE", "SYS_TIME", "SYS_TTY_CONFIG",
    "SYSLOG", "WAKE_ALARM",
}

DEFAULT_PIDS_LIMIT = 512


def _baseline_for_profile(profile: str) -> dict[str, Any]:
    """Return the unmodified baseline dict for a named profile."""
    if profile == PROFILE_DEFAULT:
        return {
            "security_opt": ["no-new-privileges:true"],
            "init": True,
            "pids_limit": DEFAULT_PIDS_LIMIT,
            "cap_drop": list(DEFAULT_CAP_DROP),
            "cap_add": [],
        }
    if profile == PROFILE_OFF:
        return {}
    raise ValueError(f"Unknown profile: {profile!r}")


_OVERRIDE_FIELDS = ("no_new_privileges", "init", "pids_limit", "cap_drop", "cap_add")


def _apply_overrides(baseline: dict[str, Any], overrides: dict[str, Any]) -> dict[str, Any]:
    """Apply individual field overrides on top of a baseline dict.

    Fail-safe semantics: omitting a field never disables a protection — the
    baseline value remains in effect. Disabling requires an explicit value
    (e.g. no_new_privileges: false).
    """
    result = dict(baseline)
    for field in _OVERRIDE_FIELDS:
        if field not in overrides:
            continue
        value = overrides[field]
        if field == "no_new_privileges":
            sec_opt = list(result.get("security_opt", []))
            sec_opt = [s for s in sec_opt if s != "no-new-privileges:true"]
            if value is True:
                sec_opt.append("no-new-privileges:true")
            if sec_opt:
                result["security_opt"] = sec_opt
            else:
                result.pop("security_opt", None)
        elif field == "init":
            result["init"] = bool(value)
        elif field == "pids_limit":
            if value == 0:
                result.pop("pids_limit", None)
            else:
                result["pids_limit"] = int(value)
        elif field == "cap_drop":
            result["cap_drop"] = list(value)
        elif field == "cap_add":
            result["cap_add"] = list(value)
    return result


def _subtract_cap_adds(result: dict[str, Any]) -> dict[str, Any]:
    """Remove any cap from cap_drop that also appears in cap_add."""
    cap_add = result.get("cap_add", [])
    if not cap_add:
        return result
    cap_drop = result.get("cap_drop", [])
    result["cap_drop"] = [c for c in cap_drop if c not in cap_add]
    return result


def resolve_security(
    project_security: dict[str, Any] | None,
    service_security: dict[str, Any] | None,
) -> dict[str, Any]:
    """Resolve effective security posture for a single service.

    Caller is responsible for schema validation BEFORE calling this function.
    """
    project_security = project_security or {}
    service_security = service_security or {}

    project_profile = project_security.get("profile", PROFILE_DEFAULT)
    if "profile" in service_security:
        baseline = _baseline_for_profile(service_security["profile"])
    else:
        baseline = _baseline_for_profile(project_profile)
        baseline = _apply_overrides(baseline, project_security)
    baseline = _apply_overrides(baseline, service_security)
    baseline = _subtract_cap_adds(baseline)
    return baseline


class SecurityValidationError(ValueError):
    """Raised when a security: block is malformed."""


def validate_security_block(
    block: dict[str, Any] | None, context: str
) -> None:
    """Validate a security: block. Raises SecurityValidationError on problems.

    `context` is "project" or a service name like "service:web", used in
    error messages so the operator can locate the offending block.
    """
    if block is None:
        return
    if not isinstance(block, dict):
        raise SecurityValidationError(
            f"{context}: security block must be a mapping, got {type(block).__name__}"
        )

    if "profile" in block:
        profile = block["profile"]
        # YAML 1.1 boolean trap: unquoted `off`/`on`/`yes`/`no` are parsed as
        # booleans by PyYAML, so `profile: off` becomes `profile: False`. We
        # surface a targeted error rather than the cryptic "Unknown profile
        # False" the generic branch would emit. (See audit finding #4.)
        if isinstance(profile, bool):
            raise SecurityValidationError(
                f"{context}: profile parsed as boolean {profile} -- quote it: "
                f"profile: \"off\". YAML 1.1 parses unquoted off/on/yes/no "
                f"as booleans."
            )
        if profile in RESERVED_PROFILES:
            raise SecurityValidationError(
                f"{context}: profile {profile!r} is reserved for a future "
                f"boxmunge release. Use {sorted(KNOWN_PROFILES)} for now."
            )
        if profile not in KNOWN_PROFILES:
            raise SecurityValidationError(
                f"{context}: Unknown profile {profile!r}. "
                f"Valid profiles: {sorted(KNOWN_PROFILES)}."
            )

    if block.get("profile") == PROFILE_OFF:
        reason = block.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            raise SecurityValidationError(
                f"{context}: profile 'off' requires a non-empty 'reason' "
                f"field documenting why the project/service is opting out "
                f"of container hardening. The reason will be reproduced in "
                f"deploy warnings and `boxmunge security` output."
            )

    for cap_field in ("cap_drop", "cap_add"):
        if cap_field not in block:
            continue
        caps = block[cap_field]
        if not isinstance(caps, list):
            raise SecurityValidationError(
                f"{context}: {cap_field} must be a list, got {type(caps).__name__}"
            )
        for cap in caps:
            if not isinstance(cap, str) or cap not in VALID_CAP_NAMES:
                raise SecurityValidationError(
                    f"{context}: Unknown capability {cap!r} in {cap_field}. "
                    f"Run `agent-help security` for the valid list."
                )

    if "pids_limit" in block:
        v = block["pids_limit"]
        if not isinstance(v, int) or isinstance(v, bool) or v < 0:
            raise SecurityValidationError(
                f"{context}: pids_limit must be a non-negative integer "
                f"(0 disables the limit), got {v!r}"
            )

    for bool_field in ("no_new_privileges", "init"):
        if bool_field in block and not isinstance(block[bool_field], bool):
            raise SecurityValidationError(
                f"{context}: {bool_field} must be true or false, "
                f"got {block[bool_field]!r}"
            )

    if "posture" in block:
        if context != "project":
            raise SecurityValidationError(
                f"{context}: 'posture' is only valid at the project level "
                f"(manifest top-level security: block), not per-service. "
                f"CVE posture applies to the whole project."
            )
        posture = block["posture"]
        # YAML 1.1 boolean trap: bool is a subtype of str-ish parsing failure
        # — bare `strict` is fine but check the type explicitly so we don't
        # accept `posture: true` etc.
        if not isinstance(posture, str) or isinstance(posture, bool):
            raise SecurityValidationError(
                f"{context}: posture must be a string, "
                f"got {type(posture).__name__}: {posture!r}"
            )
        if posture not in KNOWN_POSTURES:
            raise SecurityValidationError(
                f"{context}: Unknown posture {posture!r}. "
                f"Valid postures: {sorted(KNOWN_POSTURES)}."
            )

    if "dangerously_disable_quarantine" in block:
        if context != "project":
            raise SecurityValidationError(
                f"{context}: 'dangerously_disable_quarantine' is only valid "
                f"at the project level (manifest top-level security: block), "
                f"not per-service. CVE posture applies to the whole project."
            )
        v = block["dangerously_disable_quarantine"]
        # bool is a subtype of int, so check bool first to avoid 0/1 slipping
        # through as "boolean".
        if not isinstance(v, bool):
            raise SecurityValidationError(
                f"{context}: 'dangerously_disable_quarantine' must be a "
                f"boolean (true or false), got {type(v).__name__}: {v!r}"
            )


def _effective_profile(
    project_security: dict[str, Any] | None,
    service_security: dict[str, Any] | None,
) -> str:
    project_security = project_security or {}
    service_security = service_security or {}
    if "profile" in service_security:
        return service_security["profile"]
    return project_security.get("profile", PROFILE_DEFAULT)


def services_with_off_profile(manifest: dict[str, Any]) -> list[tuple[str, str]]:
    """Return [(service_name, reason)] for every service resolving to profile: off.

    Reason is taken from the service's own security block if it set
    profile: off there, otherwise from the project-level block.
    """
    project_sec = manifest.get("security") or {}
    if not isinstance(project_sec, dict):
        project_sec = {}
    services = manifest.get("services") or {}
    if not isinstance(services, dict):
        return []
    result: list[tuple[str, str]] = []
    for svc_name, svc in services.items():
        svc_sec = svc.get("security") if isinstance(svc, dict) else None
        if _effective_profile(project_sec, svc_sec) != PROFILE_OFF:
            continue
        # Reason precedence: service-level reason wins if service set off.
        if isinstance(svc_sec, dict) and svc_sec.get("profile") == PROFILE_OFF:
            reason = svc_sec.get("reason", "")
        else:
            reason = project_sec.get("reason", "")
        result.append((svc_name, reason))
    return result


def services_with_overrides(manifest: dict[str, Any]) -> list[tuple[str, list[str]]]:
    """Return [(service_name, [diff_descriptions])] for every service whose
    effective config differs from the default baseline AND is not `off`.

    Used for info-level visibility in health and check reports — surfaces
    deliberate per-flag relaxations like `cap_add: [NET_RAW]` so an operator
    or new team member can see at a glance which services have been tuned.

    Services on `profile: off` are NOT returned here — they are handled by
    `services_with_off_profile` at warning level.
    """
    project_sec = manifest.get("security") or {}
    if not isinstance(project_sec, dict):
        project_sec = {}
    services = manifest.get("services") or {}
    if not isinstance(services, dict):
        return []
    default_baseline = _baseline_for_profile(PROFILE_DEFAULT)
    result: list[tuple[str, list[str]]] = []

    for svc_name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        svc_sec = svc.get("security")
        if _effective_profile(project_sec, svc_sec) == PROFILE_OFF:
            continue
        resolved = resolve_security(project_sec, svc_sec)
        if resolved == default_baseline:
            continue
        diffs: list[str] = []
        # Compare each known field. Surface differences in deterministic order.
        for key in ("no_new_privileges", "init", "pids_limit", "cap_drop", "cap_add"):
            if key == "no_new_privileges":
                # Map back from security_opt presence.
                resolved_nnp = "no-new-privileges:true" in resolved.get("security_opt", [])
                default_nnp = "no-new-privileges:true" in default_baseline.get("security_opt", [])
                if resolved_nnp != default_nnp:
                    diffs.append(f"no_new_privileges={resolved_nnp}")
                continue
            if key == "cap_drop":
                if set(resolved.get(key, [])) != set(default_baseline.get(key, [])):
                    diffs.append(f"cap_drop={sorted(resolved.get(key, []))}")
                continue
            if resolved.get(key) != default_baseline.get(key):
                diffs.append(f"{key}={resolved.get(key, '(unset)')}")
        if diffs:
            result.append((svc_name, diffs))
    return result


def render_compose_security_fragment(resolved: dict[str, Any]) -> dict[str, Any]:
    """Convert the resolver output into the compose service fragment.

    Strips empty list/dict values so the rendered overlay stays clean.
    cap_add: [] is dropped (it's the default state); cap_drop: [] is dropped.
    """
    out: dict[str, Any] = {}
    if resolved.get("security_opt"):
        out["security_opt"] = list(resolved["security_opt"])
    if "init" in resolved:
        out["init"] = bool(resolved["init"])
    if "pids_limit" in resolved:
        out["pids_limit"] = int(resolved["pids_limit"])
    if resolved.get("cap_drop"):
        out["cap_drop"] = list(resolved["cap_drop"])
    if resolved.get("cap_add"):
        out["cap_add"] = list(resolved["cap_add"])
    return out


def format_off_warning(
    project: str, off_services: list[tuple[str, str]]
) -> str:
    """Format the deploy-time SECURITY OFF warning, or "" if none apply.

    The exact wording is part of the spec — the warning is meant to be
    repeatedly visible and to steer the operator toward per-flag overrides.
    """
    if not off_services:
        return ""
    lines = []
    for svc_name, reason in off_services:
        lines.append(
            f"[WARNING] SECURITY OFF — {project}/{svc_name} is deploying "
            f"without container hardening."
        )
        lines.append(
            f"          Reason recorded in manifest: {reason!r}"
        )
        lines.append(
            "          This service has no `no-new-privileges`, no fork-bomb "
            "protection, no\n          dropped capabilities. The container "
            "has the same privilege ceiling as\n          the Docker daemon "
            "allows by default — a single privilege-escalation\n          "
            "vulnerability inside the container becomes a privilege-escalation"
        )
        lines.append(
            "          vulnerability against the host's container runtime."
        )
        lines.append(
            "          If you need to relax a specific protection, prefer "
            "`cap_add: [...]`\n          or `pids_limit: <higher>` under the "
            "default profile rather than\n          turning security off "
            "entirely. See `agent-help security`."
        )
    return "\n".join(lines)
