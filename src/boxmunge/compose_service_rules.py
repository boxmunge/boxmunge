# SPDX-License-Identifier: Apache-2.0
"""Per-service hostile-key rules for user compose files.

Compose's multi-file merge lets some user keys win over boxmunge's overlay
(privileged/pid/network_mode/userns_mode/ipc/cgroupns_mode overwrite;
cap_add/volumes/security_opt/devices/device_cgroup_rules extend). Each
rule here inspects one service mapping and reports the keys that would
defeat the default hardening. Values are normalised before comparison
(case, whitespace, `CAP_` prefixes, `=` versus `:` separators) and flags
that must be booleans are type-checked strictly, so a quoted `"true"`
cannot slip past a check written for `true`.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, NamedTuple

from boxmunge.capabilities import is_denied_cap
from boxmunge.compose_mounts import check_volumes
from boxmunge.paths import BoxPaths

HARDENING_ADVICE = (
    "defeats boxmunge hardening; remove it or set security.profile: off "
    "with reason"
)


class Finding(NamedTuple):
    """One offending key on one service. `advice` completes the sentence
    `service <svc>: <key> = <value> <advice>`."""
    key: str
    value: str
    advice: str = HARDENING_ADVICE


# Keys that Docker reads as booleans. A non-boolean value (for example the
# string "true") is rejected outright rather than interpreted.
_STRICT_BOOL_KEYS: tuple[str, ...] = ("privileged", "read_only", "init")

# Namespace keys: the value `host` shares the host's namespace, and
# `container:<name>` joins another container's (possibly another
# project's) namespace. Keys listed in _CONTAINER_JOIN_KEYS reject both.
_NAMESPACE_KEYS: tuple[str, ...] = (
    "pid", "ipc", "network_mode", "uts", "userns_mode", "cgroupns_mode",
)
_CONTAINER_JOIN_KEYS: frozenset[str] = frozenset({"pid", "ipc", "network_mode"})

_SECCOMP_DEFAULTS: frozenset[str] = frozenset({"runtime/default", "builtin"})


def _check_strict_bools(svc: dict[str, Any]) -> list[Finding]:
    hits: list[Finding] = []
    for key in _STRICT_BOOL_KEYS:
        if key not in svc:
            continue
        value = svc[key]
        if not isinstance(value, bool):
            hits.append(Finding(
                key, repr(value),
                "is not a boolean; write an unquoted true or false "
                "(boxmunge does not guess what a quoted value means)",
            ))
        elif key == "privileged" and value is True:
            hits.append(Finding("privileged", "true"))
    return hits


def _check_namespaces(svc: dict[str, Any]) -> list[Finding]:
    hits: list[Finding] = []
    for key in _NAMESPACE_KEYS:
        if key not in svc:
            continue
        raw = svc[key]
        if not isinstance(raw, str):
            hits.append(Finding(
                key, repr(raw), "must be a string; remove it or quote the value",
            ))
            continue
        value = raw.strip().lower()
        if value == "host":
            hits.append(Finding(key, raw))
        elif key in _CONTAINER_JOIN_KEYS and value.startswith("container:"):
            hits.append(Finding(
                key, raw,
                "joins another container's namespace, which may belong to "
                "another project; use service:<name> for a service in this "
                "compose file, or remove it",
            ))
    return hits


def _check_devices(svc: dict[str, Any]) -> list[Finding]:
    """Any `devices` or `device_cgroup_rules` entry grants host devices."""
    hits: list[Finding] = []
    for key in ("devices", "device_cgroup_rules"):
        entries = svc.get(key)
        if isinstance(entries, list) and entries:
            hits.append(Finding(key, str(entries[0])))
    return hits


def _check_cgroup_parent(svc: dict[str, Any]) -> list[Finding]:
    """Reject absolute or traversing cgroup_parent; flat names are allowed."""
    val = svc.get("cgroup_parent")
    if isinstance(val, str) and val and (val.startswith("/") or ".." in val):
        return [Finding("cgroup_parent", val)]
    return []


def _split_security_opt(entry: str) -> tuple[str, str | None]:
    """Split `key:value` or `key=value` (Docker accepts both)."""
    lowered = entry.strip().lower()
    cut = min((i for i in (lowered.find(":"), lowered.find("=")) if i >= 0),
              default=-1)
    if cut < 0:
        return lowered, None
    return lowered[:cut].strip(), lowered[cut + 1:].strip()


def _security_opt_problem(entry: str) -> str | None:
    """Return advice for a hostile security_opt entry, or None if benign."""
    lowered = entry.lower()
    key, value = _split_security_opt(entry)
    if "unconfined" in lowered:
        return HARDENING_ADVICE
    if key == "label" and value == "disable":
        return HARDENING_ADVICE
    if key == "no-new-privileges" and value == "false":
        return HARDENING_ADVICE
    if key == "seccomp" and value not in _SECCOMP_DEFAULTS:
        return (
            "replaces Docker's default seccomp profile with a custom one, "
            "which boxmunge cannot verify; remove it"
        )
    return None


def _check_security_opt(svc: dict[str, Any]) -> list[Finding]:
    sec_opt = svc.get("security_opt")
    if not isinstance(sec_opt, list):
        return []
    hits: list[Finding] = []
    for entry in sec_opt:
        if not isinstance(entry, str):
            continue
        advice = _security_opt_problem(entry)
        if advice is not None:
            hits.append(Finding("security_opt", entry, advice))
    return hits


def _check_cap_add(svc: dict[str, Any]) -> list[Finding]:
    cap_add = svc.get("cap_add")
    if not isinstance(cap_add, list):
        return []
    return [
        Finding("cap_add", cap)
        for cap in cap_add
        if isinstance(cap, str) and is_denied_cap(cap)
    ]


_RULES = (
    _check_strict_bools, _check_namespaces, _check_devices,
    _check_cgroup_parent, _check_security_opt, _check_cap_add,
)


def service_findings(
    svc: dict[str, Any], base_dir: Path, paths: BoxPaths,
) -> list[Finding]:
    """Return every hostile key on one service, in rule order."""
    findings: list[Finding] = []
    for rule in _RULES:
        findings.extend(rule(svc))
    findings.extend(
        Finding("volumes", entry, advice)
        for entry, advice in check_volumes(svc, base_dir, paths)
    )
    return findings
