# SPDX-License-Identifier: Apache-2.0
"""Volume and bind-mount rules for user compose files.

Bind-mount sources are compared only after normalisation: `~` is
expanded, relative paths are joined to the directory holding compose.yml,
`..` and repeated slashes are collapsed, and symlinks are resolved. A
source is rejected when it is a denied host path, lies inside one, or is
a parent of one (mounting `/run` exposes `/run/docker.sock` just as
surely as mounting the socket itself). Any other source must stay inside
the project directory, so one project cannot mount another's files.
"""
from __future__ import annotations

import os
import posixpath
import re
from pathlib import Path
from typing import Any, Iterable

from boxmunge.paths import BoxPaths

# Host paths that must never be reachable through a bind mount. Both
# spellings of the runtime directory are listed because `/var/run` is a
# symlink to `/run` on Debian, and the validating host may not be the
# one that resolves it.
_SYSTEM_DENIED_PATHS: tuple[str, ...] = (
    "/var/run/docker.sock", "/run/docker.sock",
    "/var/run/containerd", "/run/containerd",
    "/var/lib/docker", "/var/lib/containerd",
    "/proc", "/sys", "/dev", "/etc", "/boot",
    "/root", "/home",
    "/usr", "/bin", "/sbin", "/lib", "/lib64",
)

_ENV_SUBSTITUTION_RE = re.compile(r"\$\w|\$\{")

# Long-syntax mount types whose source is checked (bind) or is not a host
# path. `npipe` and `cluster` name host or cluster resources by other means.
_MOUNT_TYPES: frozenset[str] = frozenset({"bind", "volume", "tmpfs", "image"})

# Smoke-test mount source injected by the overlay generator: each environment
# mounts its own release's scripts (production's project dir, staging's slot).
# Must be ignored when classifying user-compose volume entries.
SMOKE_SOURCE = "./boxmunge-scripts"
_SMOKE_MOUNT_SOURCES: frozenset[str] = frozenset({SMOKE_SOURCE})


def _is_path_like(src: str) -> bool:
    """Compose treats a short-syntax source as a host path when it starts
    with `.`, `/`, or `~`; anything else names a volume."""
    return src.startswith((".", "/", "~"))


def volume_source(entry: Any) -> str | None:
    """Return the host-side source of a volume entry, or None if it has none.

    Short syntax `src:dst[:opts]` yields `src` (a path or a volume name);
    an anonymous volume (`/data`) has no source. Long syntax yields
    `source` for `type: bind` only.
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


def is_bind_entry(entry: Any) -> bool:
    """True if the volume entry is a bind mount (not a named/anonymous volume)."""
    if isinstance(entry, dict):
        return entry.get("type") == "bind"
    src = volume_source(entry)
    return src is not None and _is_path_like(src)


def has_env_substitution(src: str) -> bool:
    """True if the source contains Compose variable substitution anywhere
    (`$VAR` or `${VAR}`), which cannot be verified statically."""
    return bool(_ENV_SUBSTITUTION_RE.search(src))


def _normalise(path: str) -> str:
    norm = posixpath.normpath(path)
    # POSIX normpath keeps exactly two leading slashes; the kernel does not.
    if norm.startswith("//"):
        norm = "/" + norm.lstrip("/")
    return norm


def host_path_forms(src: str, base_dir: Path) -> tuple[str, str]:
    """Return (normalised, symlink-resolved) absolute forms of a bind source."""
    if src.startswith("~"):
        expanded = os.path.expanduser(src)
    elif src.startswith("/"):
        expanded = src
    else:
        expanded = os.path.join(str(base_dir), src)
    norm = _normalise(expanded)
    return norm, _normalise(os.path.realpath(norm))


def _within(path: str, root: str) -> bool:
    """True if `path` equals `root` or lies below it."""
    if root == "/":
        return True
    return path == root or path.startswith(root + "/")


def _both_spellings(path: str) -> set[str]:
    return {_normalise(path), _normalise(os.path.realpath(path))}


def denied_host_path(src: str, base_dir: Path, paths: BoxPaths) -> str | None:
    """Return the denied path a bind source exposes, or None if it is allowed.

    The boxmunge root is denied except for paths strictly inside
    `projects/`; cross-project confinement is a separate rule.
    """
    candidates = set(host_path_forms(src, base_dir))
    system = {form: raw for raw in _SYSTEM_DENIED_PATHS for form in _both_spellings(raw)}
    root_forms = _both_spellings(str(paths.root))
    project_forms = _both_spellings(str(paths.projects))

    for cand in sorted(candidates):
        for form, raw in system.items():
            if _within(cand, form) or _within(form, cand):
                return raw
        for root in root_forms:
            if _within(root, cand):
                return str(paths.root)
            if _within(cand, root) and not any(
                cand.startswith(p + "/") for p in project_forms
            ):
                return str(paths.root)
    return None


def outside_roots(src: str, base_dir: Path, roots: Iterable[Path]) -> bool:
    """True unless a host path, both as written and with symlinks resolved,
    lies inside one of the allowed roots."""
    root_forms = {form for root in roots for form in _both_spellings(str(root))}
    return not all(
        any(_within(cand, root) for root in root_forms)
        for cand in host_path_forms(src, base_dir)
    )


def check_volumes(
    svc: dict[str, Any], base_dir: Path, paths: BoxPaths, roots: Iterable[Path],
) -> list[tuple[str, str, bool]]:
    """Return every hostile volume entry of one service as (entry, advice,
    relaxable). A bind source outside `roots` is never relaxable, not even
    by `profile: off`: every start refuses it (compose_guard's bind walk).

    `roots` are the directories bind mounts may use: the project directory
    (and the directory holding the compose file, when it is validated
    before being copied into place).
    """
    roots = tuple(roots)
    volumes = svc.get("volumes")
    if not isinstance(volumes, list):
        return []
    hits: list[tuple[str, str, bool]] = []
    for entry in volumes:
        if isinstance(entry, dict) and entry.get("type") not in _MOUNT_TYPES:
            hits.append((
                str(entry),
                f"uses mount type {entry.get('type')!r}, whose source boxmunge "
                f"cannot check; use bind (inside the project), volume, tmpfs "
                f"or image",
                True,
            ))
            continue
        src = volume_source(entry)
        if src is None:
            continue
        if has_env_substitution(src):
            hits.append((
                str(entry),
                "uses env-var substitution in volumes: source, which is not "
                "supported — write the host path literally for hardening "
                "verification",
                True,
            ))
            continue
        if not is_bind_entry(entry):
            continue
        denied = denied_host_path(src, base_dir, paths)
        if denied is not None:
            norm, _ = host_path_forms(src, base_dir)
            hits.append((
                str(entry),
                f"exposes a protected host path (source resolves to {norm}, "
                f"which is, contains, or lies inside {denied}); bind-mount a "
                f"directory inside the project instead",
                False,
            ))
        elif outside_roots(src, base_dir, roots):
            norm, _ = host_path_forms(src, base_dir)
            hits.append((
                str(entry),
                f"is outside the project directory (source resolves to "
                f"{norm}); bind mounts may only use paths inside the project "
                f"directory, such as ./data. Move the data there",
                False,
            ))
    return hits


def has_named_volume(volumes: Any) -> bool:
    """True if the volumes list declares a writable volume: a named or
    anonymous volume, not a bind mount and not the smoke-scripts mount."""
    if not isinstance(volumes, list):
        return False
    for entry in volumes:
        if isinstance(entry, str):
            if ":" not in entry:
                # Anonymous volume target — counts as a writable volume.
                return True
            src = entry.split(":", 1)[0]
            if src in _SMOKE_MOUNT_SOURCES or _is_path_like(src):
                continue
            return True
        if isinstance(entry, dict) and entry.get("type", "volume") == "volume":
            return True
    return False
