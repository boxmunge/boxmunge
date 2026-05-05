# SPDX-License-Identifier: Apache-2.0
"""User compose.yml validator — guards the silent-floor hardening claim.

A user-authored `compose.yml` is merged with boxmunge's generated
`compose.boxmunge.yml` overlay. Docker Compose's multi-file merge semantics
let certain user keys win over the overlay (`privileged`, `pid`,
`network_mode`, `userns_mode` overwrite; `cap_add` and `volumes` and
`security_opt` extend), so a user `compose.yml` that declares
`privileged: true` or `cap_add: [SYS_ADMIN]` defeats the boxmunge baseline.

This module parses the compose.yml *before* the overlay is generated and
rejects any key that would defeat the silent floor. Services explicitly
opted out via `security.profile: off` get a warning instead of a rejection
— the operator already accepted the risk for those.

Pure-ish module: file I/O is read-only on the compose path; `log_warning`
is the only side-effect, and only fires for opted-out services.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from boxmunge.log import log_warning


class ComposeSecurityError(Exception):
    """Raised when a user compose.yml declares a key that defeats boxmunge hardening."""


# ---------------------------------------------------------------------------
# Hostile-key inventory
# ---------------------------------------------------------------------------

# Caps that we always reject in user `cap_add`, even though the boxmunge
# baseline does not drop them (`cap_add` is the legitimate opt-back-in
# mechanism for caps in DEFAULT_CAP_DROP, e.g. NET_RAW for ping/traceroute).
# This list captures caps where there is no legitimate "opt back in" — they
# unwind container isolation so far that no normal app should need them.
_ALWAYS_HOSTILE_CAPS: set[str] = {
    "SYS_ADMIN",
    "DAC_READ_SEARCH",
    "BPF",
    "PERFMON",
    "SYS_RESOURCE",
}

# Substrings (case-insensitive) that indicate a hostile security_opt entry.
_HOSTILE_SECURITY_OPT_SUBSTRINGS: tuple[str, ...] = (
    "unconfined",
    "label:disable",
)

# Host paths that must never be exposed to a container by a user compose.
# Match against the source side of any bind mount (short or long syntax).
_HOSTILE_VOLUME_SOURCES: set[str] = {
    "/var/run/docker.sock",
    "/proc",
    "/sys",
    "/",
    "/etc",
    "/dev",
}


def _hostile_caps() -> set[str]:
    """Effective hostile-cap set — the always-hostile names.

    Note: caps in security_overlay.DEFAULT_CAP_DROP are NOT considered hostile
    when they appear in `cap_add`. Adding them back is the legitimate
    opt-back-in mechanism (e.g. NET_RAW for ping/traceroute, NET_ADMIN for
    apps that manage their own network namespace).
    """
    return set(_ALWAYS_HOSTILE_CAPS)


# ---------------------------------------------------------------------------
# Per-key validators — each returns (key, value) on first hit, or None.
# `key` and `value` are stringified for the error message.
# ---------------------------------------------------------------------------

def _check_privileged(svc: dict[str, Any]) -> tuple[str, str] | None:
    if svc.get("privileged") is True:
        return ("privileged", "true")
    return None


def _check_pid(svc: dict[str, Any]) -> tuple[str, str] | None:
    pid = svc.get("pid")
    if pid is None:
        return None
    if not isinstance(pid, str):
        return None
    if pid == "host" or pid.startswith("container:"):
        return ("pid", pid)
    return None


def _check_userns_mode(svc: dict[str, Any]) -> tuple[str, str] | None:
    if svc.get("userns_mode") == "host":
        return ("userns_mode", "host")
    return None


def _check_network_mode(svc: dict[str, Any]) -> tuple[str, str] | None:
    if svc.get("network_mode") == "host":
        return ("network_mode", "host")
    return None


def _check_security_opt(svc: dict[str, Any]) -> tuple[str, str] | None:
    sec_opt = svc.get("security_opt")
    if not isinstance(sec_opt, list):
        return None
    for entry in sec_opt:
        if not isinstance(entry, str):
            continue
        lowered = entry.lower()
        for needle in _HOSTILE_SECURITY_OPT_SUBSTRINGS:
            if needle in lowered:
                return ("security_opt", entry)
    return None


def _check_cap_add(svc: dict[str, Any]) -> tuple[str, str] | None:
    cap_add = svc.get("cap_add")
    if not isinstance(cap_add, list):
        return None
    hostile = _hostile_caps()
    for cap in cap_add:
        if not isinstance(cap, str):
            continue
        if cap.upper() in hostile:
            return ("cap_add", cap)
    return None


def _bind_source(entry: Any) -> str | None:
    """Extract the source side of a volume entry, or None if not a bind mount.

    Short syntax: "src:dst[:opts]" — `src` is everything before the first ':'
    (Windows-style absolute paths with drive letters are not a target here;
    boxmunge runs on Linux).

    Long syntax: {"type": "bind", "source": "...", ...}.

    Named volumes ("volname:/dst") are not bind mounts — we still return the
    bare name so the caller can compare it; named-volume names will not match
    any entry in _HOSTILE_VOLUME_SOURCES (they don't start with '/').
    """
    if isinstance(entry, str):
        if ":" not in entry:
            # Anonymous volume like "/data" used as a target only — no source.
            return None
        return entry.split(":", 1)[0]
    if isinstance(entry, dict):
        # Long syntax. Only bind mounts expose a host path.
        if entry.get("type") != "bind":
            return None
        src = entry.get("source")
        return src if isinstance(src, str) else None
    return None


def _check_volumes(svc: dict[str, Any]) -> tuple[str, str] | None:
    volumes = svc.get("volumes")
    if not isinstance(volumes, list):
        return None
    for entry in volumes:
        src = _bind_source(entry)
        if src is None:
            continue
        if src in _HOSTILE_VOLUME_SOURCES:
            return ("volumes", str(entry))
    return None


# Order matters only for which key is reported first when multiple are
# hostile on the same service. Keep deterministic for stable error messages.
_CHECKS = (
    _check_privileged,
    _check_pid,
    _check_userns_mode,
    _check_network_mode,
    _check_security_opt,
    _check_cap_add,
    _check_volumes,
)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def validate_user_compose(
    compose_path: Path,
    off_services: set[str] | None = None,
) -> None:
    """Parse compose.yml and reject hostile keys.

    For services in `off_services` (those that resolve to profile: off in
    the manifest), hostile keys produce log_warning entries instead of
    raising — the operator already opted out of the hardening.

    Raises ComposeSecurityError on the first hostile key in a non-off service,
    or if the file cannot be read/parsed.
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
        raise ComposeSecurityError(
            f"could not parse compose.yml: {e}"
        ) from e

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
        for check in _CHECKS:
            hit = check(svc)
            if hit is None:
                continue
            key, value = hit
            if svc_name in off:
                log_warning(
                    "compose-validate",
                    f"hostile compose key {key} on service {svc_name} "
                    f"(profile: off — allowed)",
                )
                # Continue scanning this service so the operator sees ALL
                # warnings for an opted-out service, not just the first.
                continue
            raise ComposeSecurityError(
                f"service {svc_name}: {key} = {value} defeats boxmunge "
                f"hardening; remove it or set security.profile: off "
                f"with reason"
            )
