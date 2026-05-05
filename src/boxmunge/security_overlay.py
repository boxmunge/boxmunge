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


def resolve_security(
    project_security: dict[str, Any] | None,
    service_security: dict[str, Any] | None,
) -> dict[str, Any]:
    """Resolve effective security posture for a single service.

    Caller is responsible for schema validation BEFORE calling this function.
    See validate_security_block() for validation. resolve_security assumes
    inputs are well-formed.
    """
    project_security = project_security or {}
    service_security = service_security or {}

    project_profile = project_security.get("profile", PROFILE_DEFAULT)
    if "profile" in service_security:
        profile = service_security["profile"]
    else:
        profile = project_profile
    return _baseline_for_profile(profile)
