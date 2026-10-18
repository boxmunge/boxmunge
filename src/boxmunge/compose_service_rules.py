# SPDX-License-Identifier: Apache-2.0
"""Per-service hostile-key rules for user compose files.

Compose's multi-file merge lets some user keys win over boxmunge's overlay
(privileged/pid/network_mode/userns_mode/ipc/cgroup overwrite;
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
    relaxable: bool = True  # False: refused under `profile: off` too


# Keys that Docker reads as booleans. A non-boolean value (for example the
# string "true") is rejected outright rather than interpreted.
_STRICT_BOOL_KEYS: tuple[str, ...] = ("privileged", "read_only", "init")

# Namespace keys: the value `host` shares the host's namespace. Joining
# another container's namespace (`container:<name>`, a network by name) is
# an isolation question, answered in compose_isolation. userns_mode is not
# here: namespace_refusals refuses it outright.
_NAMESPACE_KEYS: tuple[str, ...] = ("pid", "ipc", "network_mode", "uts", "cgroup")

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
        if raw.strip().lower() == "host":
            hits.append(Finding(key, raw))
    return hits


# A remapped daemon refuses these outright (privileged, host pid and host
# network fail at create; host ipc fails at runc's mqueue mount), so on a
# remapped box profile: off cannot relax them.
_HOST_ONLY_UNDER_REMAP: dict[str, str] = {
    "pid": "process", "network_mode": "network", "ipc": "IPC"}

_USERNS_ADVICE = (
    "is not allowed: every project runs in the daemon's user namespace, and "
    "leaving it (userns_mode: host) runs the service's root as real host root on "
    "a remapped box. Remove it (not relaxed by profile: off)")
_REMAP_ADVICE = (
    "cannot run on this box: its Docker daemon remaps user namespaces, which "
    "refuses {what}. Remove it (not relaxed by profile: off); a service that "
    "needs it cannot run on a remapped box")


def namespace_refusals(svc: dict[str, Any], *, remapped: bool) -> list[Finding]:
    """Findings profile: off does not relax: userns_mode with any value, and,
    on a remapped box, privileged and host pid, network_mode and ipc."""
    hits: list[Finding] = []
    if "userns_mode" in svc:
        hits.append(Finding("userns_mode", repr(svc["userns_mode"]), _USERNS_ADVICE))
    if not remapped:
        return hits
    if svc.get("privileged") is True:
        hits.append(Finding("privileged", "true", _REMAP_ADVICE.format(what="privileged mode")))
    for key, what in _HOST_ONLY_UNDER_REMAP.items():
        raw = svc.get(key)
        if isinstance(raw, str) and raw.strip().lower() == "host":
            hits.append(Finding(key, raw, _REMAP_ADVICE.format(
                what=f"sharing the host's {what} namespace")))
    return hits


def _check_devices(svc: dict[str, Any]) -> list[Finding]:
    """Any `devices`, `device_cgroup_rules`, `gpus` or reserved device
    grants host devices."""
    deploy = svc.get("deploy")
    resources = deploy.get("resources") if isinstance(deploy, dict) else None
    reservations = resources.get("reservations") if isinstance(resources, dict) else None
    candidates = {key: svc.get(key) for key in ("devices", "device_cgroup_rules", "gpus")}
    if isinstance(reservations, dict):
        candidates["deploy.resources.reservations.devices"] = reservations.get("devices")
    hits: list[Finding] = []
    for key, entries in candidates.items():
        if isinstance(entries, list) and entries:
            hits.append(Finding(key, str(entries[0])))
        elif isinstance(entries, str) and entries:
            hits.append(Finding(key, entries))
    return hits


_API_SOCKET_ADVICE = (
    "hands the container the Docker daemon's API, which can start privileged "
    "containers with any host path mounted; remove it (boxmunge runs the "
    "project's containers itself), or set security.profile: off with reason"
)

_PRIVILEGED_HOOK_ADVICE = (
    "runs the hook with full privileges, regaining every capability the "
    "hardening drops; remove privileged: (hooks run with the service's own "
    "privileges), or set security.profile: off with reason"
)


def _check_daemon_access(svc: dict[str, Any]) -> list[Finding]:
    """`use_api_socket` mounts the daemon socket without a volume entry."""
    value = svc.get("use_api_socket")
    if value is None or value is False:
        return []
    return [Finding("use_api_socket", repr(value), _API_SOCKET_ADVICE)]


def _hook_entries(svc: dict[str, Any]) -> list[tuple[str, Any]]:
    """Every lifecycle hook as (label, hook): post_start, pre_stop, and the
    `exec` hook of `develop.watch` sync+exec rules."""
    hooks: list[tuple[str, Any]] = []
    for key in ("post_start", "pre_stop"):
        entries = svc.get(key)
        if isinstance(entries, list):
            hooks += [(f"{key}[{i}]", hook) for i, hook in enumerate(entries)]
    develop = svc.get("develop")
    watch = develop.get("watch") if isinstance(develop, dict) else None
    if isinstance(watch, list):
        hooks += [
            (f"develop.watch[{i}].exec", rule.get("exec"))
            for i, rule in enumerate(watch)
            if isinstance(rule, dict) and "exec" in rule
        ]
    return hooks


def _check_hooks(svc: dict[str, Any]) -> list[Finding]:
    hits: list[Finding] = []
    for label, hook in _hook_entries(svc):
        value = hook.get("privileged") if isinstance(hook, dict) else None
        if value is not None and value is not False:
            hits.append(Finding(f"{label}.privileged", repr(value), _PRIVILEGED_HOOK_ADVICE))
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


def _check_build(svc: dict[str, Any]) -> list[Finding]:
    """Build steps run in their own container: keep it off the host network
    and unprivileged, like the service itself."""
    build = svc.get("build")
    if not isinstance(build, dict):
        return []
    hits: list[Finding] = []
    network = build.get("network")
    if isinstance(network, str) and network.strip().lower() == "host":
        hits.append(Finding(
            "build.network", network,
            "lets build steps reach services listening on the host; remove it",
        ))
    if build.get("privileged") is not None and build.get("privileged") is not False:
        hits.append(Finding("build.privileged", repr(build.get("privileged"))))
    if build.get("entitlements"):
        hits.append(Finding(
            "build.entitlements", repr(build["entitlements"]),
            "grants build steps privileges beyond an ordinary container "
            "(network.host, security.insecure); remove it, or set "
            "security.profile: off with reason",
        ))
    return hits


_RULES = (
    _check_strict_bools, _check_namespaces, _check_devices, _check_daemon_access,
    _check_hooks, _check_cgroup_parent, _check_security_opt, _check_cap_add,
    _check_build,
)


def service_findings(
    svc: dict[str, Any], base_dir: Path, paths: BoxPaths, roots: tuple[Path, ...],
) -> list[Finding]:
    """Return every hostile key on one service, in rule order."""
    findings: list[Finding] = []
    for rule in _RULES:
        findings.extend(rule(svc))
    findings.extend(
        Finding("volumes", entry, advice, relaxable)
        for entry, advice, relaxable in check_volumes(svc, base_dir, paths, roots)
    )
    return findings
