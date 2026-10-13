# SPDX-License-Identifier: Apache-2.0
"""Resolve a user compose file the way Docker Compose will run it.

The literal compose.yml is not what runs: Compose interpolates `${VAR}`
from the bundled `.env` and the environment, merges `extends:` and
`include:` files, and normalises short syntax. Validating only the
literal file let all of those smuggle in values the validator never saw.
So the validator and the overlay generator work on the output of
`docker compose -p <project> config`, which is exactly the model Compose
will start.

What `config` output cannot show is where it read things from: `env_file`
contents are inlined and `extends`/`include` are merged away. Those file
references are checked on the literal files instead, following every
include and extends file they lead to.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from boxmunge import docker
from boxmunge.compose_mounts import has_env_substitution, host_path_forms, outside_roots


class ComposeResolveError(Exception):
    """Raised when a compose file cannot be resolved by Docker Compose."""


def resolve_compose_config(compose_path: Path, project_name: str) -> dict[str, Any]:
    """Return the fully resolved compose model for one compose file."""
    try:
        out = docker.compose_config(
            compose_path.parent, [compose_path.name], project_name=project_name,
        )
    except docker.DockerError as e:
        raise ComposeResolveError(
            f"`docker compose config` could not resolve {compose_path.name}: {e}"
        ) from e
    try:
        doc = json.loads(out)
    except json.JSONDecodeError as e:
        raise ComposeResolveError(
            f"`docker compose config` returned output that is not JSON: {e}"
        ) from e
    if not isinstance(doc, dict):
        raise ComposeResolveError(
            f"`docker compose config` returned {type(doc).__name__}, not a mapping"
        )
    return doc


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _env_file_paths(value: Any) -> list[Any]:
    """env_file is a string, a list of strings, or a list of {path: ...}."""
    return [e.get("path") if isinstance(e, dict) else e for e in _as_list(value)]


def _include_entries(doc: dict[str, Any]) -> list[tuple[list[Any], list[Any], Any]]:
    """Return (compose paths, env files, project_directory) per include entry."""
    entries = []
    for item in _as_list(doc.get("include")):
        if isinstance(item, dict):
            entries.append((
                _as_list(item.get("path")), _env_file_paths(item.get("env_file")),
                item.get("project_directory"),
            ))
        else:
            entries.append(([item], [], None))
    return entries


class _ReferenceWalk:
    """Follow include/extends files from one compose file, checking every
    host path they name stays inside the project."""

    def __init__(self, roots: tuple[Path, ...]) -> None:
        self.roots = roots
        self.problems: list[str] = []
        self._seen: set[str] = set()

    def _confined(self, what: str, ref: Any, base: Path) -> bool:
        if not isinstance(ref, str) or not ref:
            self.problems.append(f"{what} {ref!r} must be a file path")
            return False
        if "://" in ref or ref.startswith("git@"):
            self.problems.append(
                f"{what} {ref!r} is remote. Copy the file into the project instead."
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
                f"directory. Keep every compose, extends, include and env_file "
                f"path inside the project."
            )
            return False
        return True

    def visit(self, path: Path) -> None:
        key = str(path.resolve())
        if key in self._seen or not path.is_file():
            return  # Compose itself reports a missing file.
        self._seen.add(key)
        try:
            doc = yaml.safe_load(path.read_text())
        except yaml.YAMLError as e:
            self.problems.append(f"{path.name}: cannot parse: {e}")
            return
        if not isinstance(doc, dict):
            return
        base = path.parent
        for compose_paths, env_files, project_dir in _include_entries(doc):
            for ref in compose_paths:
                if self._confined(f"{path.name}: include", ref, base):
                    self.visit(Path(host_path_forms(ref, base)[0]))
            for ref in env_files:
                self._confined(f"{path.name}: include env_file", ref, base)
            if project_dir is not None:
                self._confined(f"{path.name}: include project_directory", project_dir, base)
        services = doc.get("services") or {}
        if not isinstance(services, dict):
            return
        for svc_name, svc in services.items():
            if not isinstance(svc, dict):
                continue
            extends = svc.get("extends")
            ext_file = extends.get("file") if isinstance(extends, dict) else None
            if ext_file is not None and self._confined(
                f"{path.name}: service {svc_name}: extends file", ext_file, base,
            ):
                self.visit(Path(host_path_forms(ext_file, base)[0]))
            for ref in _env_file_paths(svc.get("env_file")):
                self._confined(f"{path.name}: service {svc_name}: env_file", ref, base)


def reference_problems(compose_path: Path, roots: tuple[Path, ...]) -> list[str]:
    """Return every include/extends/env_file reference that leaves the project."""
    walk = _ReferenceWalk(roots)
    walk.visit(compose_path)
    return walk.problems
