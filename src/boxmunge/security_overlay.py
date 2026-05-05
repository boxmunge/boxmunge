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
