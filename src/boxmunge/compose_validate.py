# SPDX-License-Identifier: Apache-2.0
"""User compose.yml validator — guards the silent-floor hardening claim.

A user-authored `compose.yml` is merged with boxmunge's generated
`compose.boxmunge.yml` overlay. Compose's multi-file merge semantics let
certain user keys win over the overlay (privileged/pid/network_mode/
userns_mode/ipc/cgroupns_mode overwrite; cap_add/volumes/security_opt/
devices/device_cgroup_rules extend). This module parses compose.yml
*before* the overlay is generated and rejects any key that would defeat
the silent floor. Services explicitly opted out via `security.profile:
off` get warnings instead of rejection — every offender on multi-entry
fields is surfaced so the operator sees the full picture.
"""
from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any

import yaml

from boxmunge.log import log_warning
from boxmunge.paths import BoxPaths


class ComposeSecurityError(Exception):
    """Raised when a user compose.yml declares a key that defeats hardening."""


# ---------------------------------------------------------------------------
# Hostile-key inventory
# ---------------------------------------------------------------------------

# Caps with no legitimate "opt back in" — they unwind isolation so far that
# no normal app needs them. Caps in security_overlay.DEFAULT_CAP_DROP (e.g.
# NET_RAW for ping, NET_ADMIN for namespace-managing apps) are NOT in this
# set — adding them back via cap_add is the legitimate opt-back-in path.
_ALWAYS_HOSTILE_CAPS: set[str] = {
    "SYS_ADMIN", "DAC_READ_SEARCH", "BPF", "PERFMON", "SYS_RESOURCE",
}

# Substrings (case-insensitive) that indicate a hostile security_opt entry.
# `no-new-privileges:false` defeats the overlay's `:true` under list-merge.
_HOSTILE_SECURITY_OPT_SUBSTRINGS: tuple[str, ...] = (
    "unconfined", "label:disable", "no-new-privileges:false",
)

# Host paths that must never be exposed via bind-mount source. Matched with
# POSIX path-prefix semantics — descendants are also rejected.
#
# Both `/var/run/docker.sock` and `/run/docker.sock` are listed explicitly:
# on modern Debian/Ubuntu `/var/run` is a symlink to `/run`, so a hostile
# compose can mount the unsymlinked `/run/docker.sock` and bypass the
# `/var/run/docker.sock` rule (audit B-1). We do NOT list `/run` itself —
# that would reject every legitimate `/run/myapp` tmpfs mount.
_HOSTILE_VOLUME_SOURCES: tuple[str, ...] = (
    "/var/run/docker.sock", "/run/docker.sock",
    "/proc", "/sys", "/etc", "/dev", "/",
)


# ---------------------------------------------------------------------------
# Per-key validators
#
# Single-hit checks return `tuple[str, str] | None` — the (key, value) of the
# first offender. Multi-hit checks (cap_add, security_opt, volumes) return
# `list[tuple[str, str]]` — every offender, so off-service warnings surface
# the complete picture (audit I-NEW-3).
# ---------------------------------------------------------------------------

def _check_privileged(svc: dict[str, Any]) -> tuple[str, str] | None:
    if svc.get("privileged") is True:
        return ("privileged", "true")
    return None


def _scalar_host_match(svc: dict[str, Any], key: str) -> tuple[str, str] | None:
    val = svc.get(key)
    if isinstance(val, str) and val.lower() == "host":
        return (key, val)
    return None


def _check_pid(svc: dict[str, Any]) -> tuple[str, str] | None:
    pid = svc.get("pid")
    if not isinstance(pid, str):
        return None
    lowered = pid.lower()
    if lowered == "host" or lowered.startswith("container:"):
        return ("pid", pid)
    return None


def _check_userns_mode(svc: dict[str, Any]) -> tuple[str, str] | None:
    return _scalar_host_match(svc, "userns_mode")


def _check_network_mode(svc: dict[str, Any]) -> tuple[str, str] | None:
    return _scalar_host_match(svc, "network_mode")


def _check_ipc(svc: dict[str, Any]) -> tuple[str, str] | None:
    """`ipc: host` shares the host IPC namespace — escape vector."""
    return _scalar_host_match(svc, "ipc")


def _check_cgroupns_mode(svc: dict[str, Any]) -> tuple[str, str] | None:
    """`cgroupns_mode: host` shares the host cgroup namespace."""
    return _scalar_host_match(svc, "cgroupns_mode")


def _check_devices(svc: dict[str, Any]) -> tuple[str, str] | None:
    """Any non-empty `devices` list exposes host devices to the container."""
    devs = svc.get("devices")
    if isinstance(devs, list) and devs:
        return ("devices", str(devs[0]))
    return None


def _check_device_cgroup_rules(svc: dict[str, Any]) -> tuple[str, str] | None:
    """`device_cgroup_rules` (e.g. "c *:* rwm") grants device-class access."""
    rules = svc.get("device_cgroup_rules")
    if isinstance(rules, list) and rules:
        return ("device_cgroup_rules", str(rules[0]))
    return None


def _check_cgroup_parent(svc: dict[str, Any]) -> tuple[str, str] | None:
    """Reject cgroup_parent values that look like traversal or absolute
    placement. Flat names (e.g. "my-cgroup") are allowed.
    """
    val = svc.get("cgroup_parent")
    if not isinstance(val, str) or not val:
        return None
    if val.startswith("/") or ".." in val:
        return ("cgroup_parent", val)
    return None


def _check_security_opt(svc: dict[str, Any]) -> list[tuple[str, str]]:
    sec_opt = svc.get("security_opt")
    if not isinstance(sec_opt, list):
        return []
    hits: list[tuple[str, str]] = []
    for entry in sec_opt:
        if not isinstance(entry, str):
            continue
        lowered = entry.lower()
        if any(needle in lowered for needle in _HOSTILE_SECURITY_OPT_SUBSTRINGS):
            hits.append(("security_opt", entry))
    return hits


def _check_cap_add(svc: dict[str, Any]) -> list[tuple[str, str]]:
    cap_add = svc.get("cap_add")
    if not isinstance(cap_add, list):
        return []
    hits: list[tuple[str, str]] = []
    for cap in cap_add:
        if isinstance(cap, str) and cap.upper() in _ALWAYS_HOSTILE_CAPS:
            hits.append(("cap_add", cap))
    return hits


def _bind_source(entry: Any) -> str | None:
    """Extract the source side of a volume entry, or None if not a bind mount.

    Short syntax: "src:dst[:opts]" — source is everything before the first
    ':'. Long syntax: {"type": "bind", "source": "...", ...}. Anonymous
    volume targets ("/data") have no source — return None. Named volumes
    ("name:/dst") return the name; it won't match a hostile path.
    """
    if isinstance(entry, str):
        if ":" not in entry:
            return None
        return entry.split(":", 1)[0]
    if isinstance(entry, dict):
        if entry.get("type") != "bind":
            return None
        src = entry.get("source")
        return src if isinstance(src, str) else None
    return None


def _has_env_substitution(src: str) -> bool:
    """True if the source contains Compose env-var substitution.

    Compose substitutes `${VAR}` and `$VAR` from the project env at runtime
    — we cannot validate the resolved value statically. Reject up front;
    fail noisily, never fall back.
    """
    return "${" in src or src.startswith("$")


def _is_hostile_volume_source(src: str) -> bool:
    """POSIX path-prefix match against _HOSTILE_VOLUME_SOURCES.

    Matches if `src` equals or descends from any hostile entry. Relative
    paths and named-volume strings (no leading '/') never match.
    """
    if not src.startswith("/"):
        return False
    src_path = PurePosixPath(src)
    for hostile in _HOSTILE_VOLUME_SOURCES:
        # `/` is exact-match only — every absolute path is a descendant of
        # root, so prefix matching here would reject every legit bind mount.
        if hostile == "/":
            if src == "/":
                return True
            continue
        hostile_path = PurePosixPath(hostile)
        if src_path == hostile_path:
            return True
        try:
            src_path.relative_to(hostile_path)
            return True
        except ValueError:
            continue
    return False


def _check_volumes(svc: dict[str, Any]) -> list[tuple[str, str]]:
    """Return every hostile volume entry — env-substitution OR hostile prefix."""
    volumes = svc.get("volumes")
    if not isinstance(volumes, list):
        return []
    hits: list[tuple[str, str]] = []
    for entry in volumes:
        src = _bind_source(entry)
        if src is None:
            continue
        if _has_env_substitution(src):
            hits.append((
                "volumes",
                f"{entry} (env-var substitution in volumes: source not "
                f"supported — write the host path literally for "
                f"hardening verification)",
            ))
            continue
        if _is_hostile_volume_source(src):
            hits.append(("volumes", str(entry)))
    return hits


_SINGLE_CHECKS = (
    _check_privileged, _check_pid, _check_userns_mode, _check_network_mode,
    _check_ipc, _check_cgroupns_mode, _check_devices,
    _check_device_cgroup_rules, _check_cgroup_parent,
)
_MULTI_CHECKS = (_check_security_opt, _check_cap_add, _check_volumes)


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

    services = doc.get("services") or {}
    if not isinstance(services, dict):
        raise ComposeSecurityError(
            f"could not parse compose.yml: 'services' must be a mapping, "
            f"got {type(services).__name__}"
        )

    for svc_name, svc in services.items():
        if not isinstance(svc, dict):
            continue

        findings: list[tuple[str, str]] = []
        for check in _SINGLE_CHECKS:
            hit = check(svc)
            if hit is not None:
                findings.append(hit)
        for multi in _MULTI_CHECKS:
            findings.extend(multi(svc))

        if not findings:
            continue

        if svc_name in off:
            for key, value in findings:
                log_warning(
                    "compose-validate",
                    f"hostile compose key {key} on service {svc_name} "
                    f"(profile: off — allowed): {value}",
                    paths,
                    project=project_name,
                )
            continue

        key, value = findings[0]
        raise ComposeSecurityError(
            f"service {svc_name}: {key} = {value} defeats boxmunge "
            f"hardening; remove it or set security.profile: off "
            f"with reason"
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
