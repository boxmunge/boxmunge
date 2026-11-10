# SPDX-License-Identifier: Apache-2.0
"""The files a compose file makes Compose read, and whether they stay inside
the project.

`docker compose config` cannot show where it read things from: `env_file`
and `label_file` contents are inlined and `extends`/`include` are merged
away. So those references are checked on the literal files, following
every include and extends file they lead to.

`include:` is confined to a subset whose path resolution is simple and
checked against Compose (v5.1.3): an entry is a path or a list of paths
(`path:`), naming existing files inside the project, at most two levels
deep (compose.yml -> included -> included). An included file's relative
paths (env_file, label_file, extends file, nested include) resolve, as
Compose resolves them, against the directory of its entry's FIRST path,
not the file's own directory. Everything else is refused: an entry's
`project_directory` (Compose moves the base when it is missing or a file,
and resolves it from the wrong directory below depth two), its `env_file`
(resolved from the wrong directory at depth three), and deeper nesting.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from boxmunge.compose_mounts import has_env_substitution, host_path_forms, outside_roots

MAX_INCLUDE_DEPTH = 2
ALLOWED_INCLUDES = (
    "boxmunge allows an include entry only as a path or a list of paths "
    "(`- parts/db.yml` or `- path: [a.yml, b.yml]`) naming files inside the "
    "project, nested at most two levels (compose.yml -> included -> included); "
    "project_directory and env_file on an include entry are refused.")
# What Compose fetches instead of reading a local file: URLs (oci://,
# https://, git://), scp-style git remotes (user@host:repo) and bare
# hosted-git paths.
_REMOTE = re.compile(r"://|^[\w.-]+@[\w.-]+:|^(github\.com|gitlab\.com|bitbucket\.org)/")


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def env_file_paths(value: Any) -> list[Any]:
    """env_file is a string, a list of strings, or a list of {path: ...}."""
    return [e.get("path") if isinstance(e, dict) else e for e in as_list(value)]


def include_entries(doc: dict[str, Any]) -> list[tuple[list[Any], list[str]]]:
    """(compose paths, keys other than `path`) per include entry."""
    entries = []
    for item in as_list(doc.get("include")):
        if isinstance(item, dict):
            entries.append((as_list(item.get("path")), sorted(str(k) for k in item if k != "path")))
        else:
            entries.append(([item], []))
    return entries


def entry_base(compose_paths: list[Any], base: Path) -> Path | None:
    """The directory Compose resolves an included file's relative paths
    against: the directory of its entry's FIRST path, relative to the
    including file's ``base``. For `path: [a/x.yml, b/y.yml]`, y.yml's
    `env_file: e.env` is a/e.env. None when the first path is not a
    literal local path (the walk reports it)."""
    first = next(iter(compose_paths), None)
    if (not isinstance(first, str) or not first or has_env_substitution(first)
            or _REMOTE.search(first)):
        return None
    return Path(host_path_forms(first, base)[0]).parent


class _ReferenceWalk:
    """Follow include/extends files from one compose file, checking every
    host path they name stays inside the project, and noting every file
    Compose reads: compose, include, extends and env files."""

    def __init__(self, roots: tuple[Path, ...]) -> None:
        self.roots = roots
        self.problems: list[str] = []
        self.files: list[Path] = []
        self.documents: dict[Path, dict[str, Any]] = {}  # each compose file, parsed once
        self.project_files: list[Path] = []  # the top file and its includes
        # (file, service) -> the (file, service) it extends
        self.extends: dict[tuple[Path, str], tuple[Path, str]] = {}
        self._seen: set[tuple[str, str, int]] = set()

    def _confined(self, what: str, ref: Any, base: Path, *, read: bool = True) -> bool:
        if not isinstance(ref, str) or not ref:
            self.problems.append(f"{what} {ref!r} must be a file path")
            return False
        if _REMOTE.search(ref):
            self.problems.append(
                f"{what} {ref!r} is remote (Compose would fetch it). Copy the file "
                f"into the project instead."
            )
            return False
        if has_env_substitution(ref):
            self.problems.append(
                f"{what} {ref!r} uses variable substitution, which cannot be "
                f"checked. Write the path literally."
            )
            return False
        if outside_roots(ref, base, self.roots):
            norm, _ = host_path_forms(ref, base)
            self.problems.append(
                f"{what} {ref!r} resolves to {norm}, outside the project "
                f"directory. Keep every compose, extends, include, env_file and "
                f"label_file path inside the project."
            )
            return False
        if read:
            self.files.append(Path(host_path_forms(ref, base)[0]))
        return True

    def _target(self, what: str, ref: Any, base: Path) -> Path | None:
        """A compose file an include or extends names: confined, and an
        existing regular file (a missing one is not left to Compose, which
        may read it as a remote)."""
        if not self._confined(what, ref, base):
            return None
        target = Path(host_path_forms(ref, base)[0])
        if not target.is_file():
            self.problems.append(
                f"{what} {ref!r} is not a file in the project ({target} does not "
                f"exist or is not a regular file). Name a compose file the release carries."
            )
            return None
        return target

    def _include(self, name: str, compose_paths: list[Any], extra: list[str], base: Path,
                 depth: int) -> None:
        what = f"{name}: include"
        if extra:
            self.problems.append(f"{what} entry sets {', '.join(extra)}. {ALLOWED_INCLUDES}")
            return
        if depth >= MAX_INCLUDE_DEPTH:
            self.problems.append(
                f"{what} {compose_paths!r} nests includes deeper than "
                f"{MAX_INCLUDE_DEPTH} levels. {ALLOWED_INCLUDES}")
            return
        if not compose_paths:
            self.problems.append(f"{what} entry names no path. {ALLOWED_INCLUDES}")
            return
        targets = [self._target(what, ref, base) for ref in compose_paths]
        new_base = entry_base(compose_paths, base)
        if new_base is None or None in targets:
            return  # reported above
        # Compose loads the included project's `.env` from its base, so that
        # file steers interpolation of the included model.
        self.files.append(new_base / ".env")
        for target in targets:
            self.visit(target, new_base, depth + 1)

    def _parsed(self, path: Path) -> Any:
        if path not in self.documents:
            try:
                doc = yaml.safe_load(path.read_text())
            except yaml.YAMLError as e:
                self.problems.append(f"{path.name}: cannot parse: {e}")
                return None
            self.documents[path] = doc if isinstance(doc, dict) else {}
        return self.documents[path]

    def visit(self, path: Path, base: Path | None = None, depth: int = 0, *,
              extended: bool = False) -> None:
        """``base`` resolves the file's relative paths: its own directory for
        the top file and an extends file, the include entry's base for an
        included one (entry_base). ``depth`` counts includes from the top
        file; an extends file keeps its referrer's. The same file reached
        with another base or depth is walked again. ``extended``: reached
        only through `extends`, so its services are not the project's."""
        base = base or path.parent
        if not extended and path not in self.project_files:
            self.project_files.append(path)
        key = (str(path.resolve()), str(base), depth)
        if key in self._seen:
            return
        self._seen.add(key)
        self.files.append(path)
        doc = self._parsed(path)
        if not doc:
            return
        for compose_paths, extra in include_entries(doc):
            self._include(path.name, compose_paths, extra, base, depth)
        services = doc.get("services") or {}
        if not isinstance(services, dict):
            return
        for svc_name, svc in services.items():
            if not isinstance(svc, dict):
                continue
            what = f"{path.name}: service {svc_name}"
            extends = svc.get("extends")
            ext_file = extends.get("file") if isinstance(extends, dict) else None
            target = None if ext_file is None else self._target(
                f"{what}: extends file", ext_file, base)
            if target is not None:
                # Compose resolves an extended file's paths from its own directory.
                self.visit(target, None, depth, extended=True)
            parent = extends.get("service") if isinstance(extends, dict) else extends
            if isinstance(parent, str) and (ext_file is None or target is not None):
                self.extends[(path, svc_name)] = (target or path, parent)
            for ref in env_file_paths(svc.get("env_file")):
                self._confined(f"{what}: env_file", ref, base)
            # label_file is read by the daemon, as root, like env_file.
            for ref in as_list(svc.get("label_file")):
                self._confined(f"{what}: label_file", ref, base)


def walk_references(
    compose_path: Path, roots: tuple[Path, ...], *, base: Path | None = None,
) -> tuple[list[str], list[Path]]:
    """Return (every include/extends/env_file/label_file reference that
    leaves the project or the include subset, every file the compose file
    makes Compose read). ``base`` is the project directory Compose resolves
    the file from, when that is not the file's own directory."""
    walk = _ReferenceWalk(roots)
    walk.visit(compose_path, base)
    return walk.problems, walk.files


@dataclass(frozen=True)
class ComposeSources:
    """The compose files Compose reads for a project, as the walk parsed
    them: ``documents`` holds every one (top file, includes, extends files),
    ``project_files`` those whose services the project has (the top file
    and its includes), ``extends`` each service's `extends` parent."""
    documents: dict[Path, dict[str, Any]]
    project_files: list[Path]
    extends: dict[tuple[Path, str], tuple[Path, str]]

    def services(self, path: Path) -> dict[str, Any]:
        services = self.documents[path].get("services")
        return services if isinstance(services, dict) else {}


def compose_sources(compose_path: Path, roots: tuple[Path, ...]) -> ComposeSources:
    """The compose files ``compose_path`` makes Compose read, each parsed
    once, as walk_references follows them. Raises ValueError for references
    the walk refuses (validation has refused them already, so this is a
    broken assumption)."""
    walk = _ReferenceWalk(roots)
    walk.visit(compose_path)
    if walk.problems:
        raise ValueError(f"{compose_path}: {walk.problems[0]}")
    return ComposeSources(walk.documents, walk.project_files, walk.extends)
