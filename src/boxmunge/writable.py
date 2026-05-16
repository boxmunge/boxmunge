# SPDX-License-Identifier: Apache-2.0
"""Per-service writable-path abstraction.

Pure module: no I/O, no logging. Owns schema validation, state
classification, and translation of manifest writable blocks into
compose tmpfs/volumes fragments.

Each service is classified into one of three states:

  DEFAULT       - no writable block; runs with v0.8 baseline (read_only
                  rootfs + tmpfs:/tmp)
  MANAGED       - writable.ephemeral and/or writable.persistent declared;
                  boxmunge owns translation to compose tmpfs/volumes
  EXTERNAL      - writable.external: true; boxmunge emits no tmpfs/volume
                  entries for this service, operator owns compose-side
                  writability entirely

The three states are mutually exclusive. Validation enforces that.
"""
from __future__ import annotations

import re
from enum import Enum
from typing import Any


class WritableState(Enum):
    DEFAULT = "default"
    MANAGED = "manifest-managed"
    EXTERNAL = "externally-managed"


# Persistent mount paths that almost always indicate operator error.
# Mounting a named volume here would shadow critical OS state.
RESERVED_ROOTS: frozenset[str] = frozenset({
    "/", "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64",
    "/boot", "/proc", "/sys", "/dev",
})

# Ephemeral-class paths (tmpfs territory) that don't belong on persistent
# volumes — the data would never survive in a useful way.
_EPHEMERAL_ONLY_PATHS: frozenset[str] = frozenset({
    "/tmp", "/var/run", "/run",
})

NAME_PATTERN = r"^[a-z0-9][a-z0-9-]{0,30}$"
_NAME_RE = re.compile(NAME_PATTERN)

_MAX_PATH_LEN = 256
_KNOWN_KEYS: frozenset[str] = frozenset({"ephemeral", "persistent", "external"})


class WritableValidationError(ValueError):
    """Raised when a writable: block is malformed."""


def classify_state(svc: Any) -> WritableState:
    """Return the writable state for a service block.

    Caller is responsible for prior schema validation. Garbage in →
    DEFAULT out (no exception) — this function is consulted from
    multiple non-validating call sites (overlay generator, log
    hint formatter) and they must not crash on a malformed service.
    """
    if not isinstance(svc, dict):
        return WritableState.DEFAULT
    block = svc.get("writable")
    if not isinstance(block, dict):
        return WritableState.DEFAULT
    if block.get("external") is True:
        return WritableState.EXTERNAL
    if block.get("ephemeral") or block.get("persistent"):
        return WritableState.MANAGED
    return WritableState.DEFAULT


def describe_state(svc: Any) -> tuple[WritableState, str]:
    """Return (state, human-readable description) for a service block.

    Used by `boxmunge security` to surface writable state per service.
    The description is short — meant for one line in tabular output.

    Examples:
        DEFAULT  -> "default (read-only rootfs, /tmp tmpfs)"
        MANAGED  -> "manifest-managed (1 ephemeral, 1 persistent)"
        EXTERNAL -> "externally-managed (operator owns)"
    """
    state = classify_state(svc)
    if state is WritableState.DEFAULT:
        return state, "default (read-only rootfs, /tmp tmpfs)"
    if state is WritableState.EXTERNAL:
        return state, "externally-managed (operator owns)"
    # MANAGED — count entries.
    block = (svc or {}).get("writable") or {}
    eph_count = len(block.get("ephemeral") or [])
    per_count = len(block.get("persistent") or [])
    parts: list[str] = []
    if eph_count:
        parts.append(f"{eph_count} ephemeral")
    if per_count:
        parts.append(f"{per_count} persistent")
    return state, f"manifest-managed ({', '.join(parts) or 'no entries'})"


def writable_json(svc: Any) -> dict[str, Any]:
    """Return the JSON-shape representation of a service's writable
    state for `boxmunge security --json` consumers.

    Always returns a mapping with `state` set; `ephemeral` and
    `persistent` lists are included when populated; `external` flag
    is included when true.
    """
    state = classify_state(svc)
    out: dict[str, Any] = {"state": state.value}
    if not isinstance(svc, dict):
        return out
    block = svc.get("writable")
    if not isinstance(block, dict):
        return out
    if state is WritableState.EXTERNAL:
        out["external"] = True
        return out
    eph = block.get("ephemeral")
    if isinstance(eph, list) and eph:
        out["ephemeral"] = list(eph)
    per = block.get("persistent")
    if isinstance(per, list) and per:
        out["persistent"] = [
            {"name": e.get("name"), "mount": e.get("mount")}
            for e in per
            if isinstance(e, dict)
        ]
    return out


def _validate_path(path: Any, context: str) -> str:
    """Validate a single container path. Returns the path on success.

    `context` flows into the error message so the operator can locate
    the offending entry.
    """
    if not isinstance(path, str):
        raise WritableValidationError(
            f"{context}: path must be a string, got {type(path).__name__}"
        )
    if not path.startswith("/"):
        raise WritableValidationError(
            f"{context}: path {path!r} must be absolute (start with '/')"
        )
    if ".." in path.split("/"):
        raise WritableValidationError(
            f"{context}: path {path!r} contains '..'"
        )
    if len(path) > _MAX_PATH_LEN:
        raise WritableValidationError(
            f"{context}: path {path!r} too long (max {_MAX_PATH_LEN} chars)"
        )
    return path


def _validate_ephemeral(entries: Any, service_name: str) -> list[str]:
    if not isinstance(entries, list):
        raise WritableValidationError(
            f"services.{service_name}.writable.ephemeral must be a list, "
            f"got {type(entries).__name__}"
        )
    seen: set[str] = set()
    out: list[str] = []
    for i, entry in enumerate(entries):
        path = _validate_path(
            entry, f"services.{service_name}.writable.ephemeral[{i}]"
        )
        if path in seen:
            raise WritableValidationError(
                f"services.{service_name}.writable.ephemeral: duplicate "
                f"path {path!r}"
            )
        seen.add(path)
        out.append(path)
    return out


def _validate_persistent_entry(
    entry: Any, index: int, service_name: str
) -> tuple[str, str]:
    """Validate one persistent entry; return (name, mount)."""
    ctx = f"services.{service_name}.writable.persistent[{index}]"
    if not isinstance(entry, dict):
        raise WritableValidationError(
            f"{ctx} must be a mapping with 'name' and 'mount', "
            f"got {type(entry).__name__}"
        )
    if "name" not in entry:
        raise WritableValidationError(f"{ctx} is missing required field 'name'")
    if "mount" not in entry:
        raise WritableValidationError(f"{ctx} is missing required field 'mount'")
    name = entry["name"]
    if not isinstance(name, str) or not _NAME_RE.match(name):
        raise WritableValidationError(
            f"{ctx}: name {name!r} must match {NAME_PATTERN} "
            f"(lowercase alphanumeric with hyphens, 1-31 chars, "
            f"starting with letter or digit)"
        )
    mount = _validate_path(entry["mount"], f"{ctx}.mount")
    if mount.endswith("/") and mount != "/":
        raise WritableValidationError(
            f"{ctx}: mount {mount!r} must not have a trailing slash"
        )
    if mount in RESERVED_ROOTS:
        raise WritableValidationError(
            f"{ctx}: mount {mount!r} is a reserved root — mounting a "
            f"persistent volume here would shadow critical OS state. "
            f"Use a subdirectory like /app/data instead."
        )
    if mount in _EPHEMERAL_ONLY_PATHS:
        raise WritableValidationError(
            f"{ctx}: mount {mount!r} is an ephemeral path — did you mean "
            f"to declare it under writable.ephemeral?"
        )
    unknown = set(entry.keys()) - {"name", "mount"}
    if unknown:
        raise WritableValidationError(
            f"{ctx} has unknown key(s): {sorted(unknown)}. "
            f"Allowed: name, mount."
        )
    return name, mount


def _validate_persistent(entries: Any, service_name: str) -> list[tuple[str, str]]:
    if not isinstance(entries, list):
        raise WritableValidationError(
            f"services.{service_name}.writable.persistent must be a list, "
            f"got {type(entries).__name__}"
        )
    seen_names: set[str] = set()
    seen_mounts: set[str] = set()
    out: list[tuple[str, str]] = []
    for i, entry in enumerate(entries):
        name, mount = _validate_persistent_entry(entry, i, service_name)
        if name in seen_names:
            raise WritableValidationError(
                f"services.{service_name}.writable.persistent: name "
                f"{name!r} is not unique within this service"
            )
        if mount in seen_mounts:
            raise WritableValidationError(
                f"services.{service_name}.writable.persistent: mount "
                f"{mount!r} is not unique within this service"
            )
        seen_names.add(name)
        seen_mounts.add(mount)
        out.append((name, mount))
    return out


def _check_nesting(
    ephemeral: list[str], persistent: list[tuple[str, str]], service_name: str
) -> None:
    """Reject persistent mounts nested under any ephemeral path.

    At runtime the tmpfs mounts before the named volume, so a persistent
    mount nested under an ephemeral path would be silently shadowed —
    data lost on every restart. We catch this at validation time rather
    than letting the operator discover it the hard way.
    """
    for name, mount in persistent:
        for eph in ephemeral:
            if mount == eph:
                # Caught earlier as overlap, but defend in depth.
                continue
            prefix = eph if eph.endswith("/") else eph + "/"
            if mount.startswith(prefix):
                raise WritableValidationError(
                    f"services.{service_name}.writable: persistent mount "
                    f"{mount!r} (name={name!r}) is nested under ephemeral "
                    f"path {eph!r}. The tmpfs would shadow the volume at "
                    f"runtime. Pick non-overlapping paths."
                )


def validate_writable_block(block: Any, service_name: str) -> None:
    """Validate one service's writable: block.

    Accepts None (block absent) and {} (block present but empty) as
    valid — both classify as DEFAULT. Raises WritableValidationError
    on any structural problem.
    """
    if block is None:
        return
    if not isinstance(block, dict):
        raise WritableValidationError(
            f"services.{service_name}.writable must be a mapping, "
            f"got {type(block).__name__}"
        )

    unknown = set(block.keys()) - _KNOWN_KEYS
    if unknown:
        raise WritableValidationError(
            f"services.{service_name}.writable: unknown key(s) "
            f"{sorted(unknown)}. Allowed: {sorted(_KNOWN_KEYS)}."
        )

    has_external = "external" in block
    has_ephemeral = "ephemeral" in block
    has_persistent = "persistent" in block

    if has_external:
        external = block["external"]
        if not isinstance(external, bool):
            raise WritableValidationError(
                f"services.{service_name}.writable.external must be a "
                f"boolean (true), got {type(external).__name__}: {external!r}"
            )
        if external is False:
            raise WritableValidationError(
                f"services.{service_name}.writable.external: do not "
                f"declare false — omit the field instead. The field "
                f"exists only as an explicit opt-in for "
                f"externally-managed writability."
            )
        if has_ephemeral or has_persistent:
            raise WritableValidationError(
                f"services.{service_name}.writable: 'external: true' is "
                f"mutually exclusive with 'ephemeral' and 'persistent'. "
                f"Pick one: declare paths in manifest (ephemeral/persistent) "
                f"OR delegate to compose.yml (external: true)."
            )
        return  # external-only block is fully validated

    ephemeral = _validate_ephemeral(block["ephemeral"], service_name) if has_ephemeral else []
    persistent = _validate_persistent(block["persistent"], service_name) if has_persistent else []

    persistent_mounts = {m for _, m in persistent}
    for eph in ephemeral:
        if eph in persistent_mounts:
            raise WritableValidationError(
                f"services.{service_name}.writable: path {eph!r} declared "
                f"as both ephemeral and persistent. Pick one."
            )

    _check_nesting(ephemeral, persistent, service_name)
