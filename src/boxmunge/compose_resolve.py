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
and `label_file` contents are inlined and `extends`/`include` are merged
away. Those file references are checked on the literal files instead,
following every include and extends file they lead to.
"""
from __future__ import annotations

import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import yaml

from boxmunge import docker
from boxmunge.compose_mounts import has_env_substitution, host_path_forms, outside_roots


class ComposeResolveError(Exception):
    """Raised when a compose file cannot be resolved by Docker Compose."""


@contextmanager
def _missing_env_files_present(compose_path: Path, base: Path | None = None) -> Iterator[None]:
    """Make absent in-project service env files exist while Compose resolves.

    A bundle is validated in an extraction directory, where on-box files such
    as secrets.env do not exist, and some Compose versions refuse to resolve
    a model whose env_file is missing, even with --no-env-resolution. Each
    missing env file that stays inside ``base`` (the directory Compose
    resolves relative paths against, by default the compose file's) is
    created empty for the duration of the call and removed afterwards.
    Validation never reads their values. A placeholder that somehow
    survived could not reach a live project: installing a release that
    carries secrets.env is refused.
    """
    created: list[Path] = []
    base = base or compose_path.parent
    try:
        doc = yaml.safe_load(compose_path.read_text())
    except (OSError, yaml.YAMLError):
        doc = None  # Compose reports the real problem when it resolves.
    services = doc.get("services") if isinstance(doc, dict) else None
    try:
        for svc in (services.values() if isinstance(services, dict) else []):
            if not isinstance(svc, dict):
                continue
            for ref in _env_file_paths(svc.get("env_file")):
                if (not isinstance(ref, str) or not ref or has_env_substitution(ref)
                        or outside_roots(ref, base, (base,))):
                    continue  # the reference walk reports these
                target = Path(host_path_forms(ref, base)[0])
                if not target.exists() and not target.is_symlink():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    # O_EXCL|O_NOFOLLOW: a link planted after the check above
                    # fails here instead of making root create its target.
                    os.close(os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                     | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644))
                    created.append(target)
        yield
    finally:
        for path in created:
            path.unlink(missing_ok=True)


def _parse_config(out: str) -> dict[str, Any]:
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


def _literal_service_names(path: Path, root: Path, seen: set[Path]) -> set[str]:
    """Service names a compose file and the files it includes declare."""
    if path in seen or not path.is_file():
        return set()
    seen.add(path)
    try:
        doc = yaml.safe_load(path.read_text())
    except yaml.YAMLError:
        return set()  # Compose reports the real problem when it resolves.
    if not isinstance(doc, dict):
        return set()
    services = doc.get("services")
    names = set(services) if isinstance(services, dict) else set()
    for name in names:
        if not isinstance(name, str):
            raise ComposeResolveError(
                f"{path.name}: service name {name!r} is not text to boxmunge's "
                f"YAML reader, which (YAML 1.1) reads unquoted on/off/yes/no as "
                f"booleans and bare digits as numbers, while Compose reads the "
                f"name as text. Quote the service name (for example 'on':) or "
                f"rename the service."
            )
    for compose_paths, _env, _dir in _include_entries(doc):
        for ref in compose_paths:
            if isinstance(ref, str) and not outside_roots(ref, path.parent, (root,)):
                names |= _literal_service_names(
                    Path(host_path_forms(ref, path.parent)[0]), root, seen)
    return names


# ---------------------------------------------------------------------------
# What the user wrote for `read_only`, which `config` loses.
#
# `config --format json` keeps `read_only: true` and DROPS `read_only: false`
# (it omits fields at their zero value), so the model cannot tell "opted out
# of the read-only rootfs" from "said nothing" and the overlay would force a
# read-only root onto a service that asked for a writable one. The user's
# intent is read from their compose.yml as written and put back.
#
# A service defined only through `extends:` / `include:` has no `read_only`
# key in this file; that counts as "not declared", so a `read_only: false`
# inherited from the extended/included file is still lost. Declare it on the
# service itself.
# ---------------------------------------------------------------------------


def declared_read_only(compose_path: Path) -> dict[str, bool]:
    """{service: value} for every service this file gives a `read_only` key.

    Raises ComposeResolveError when the file cannot be parsed or a value is
    not a literal boolean. An interpolated (`${X}`) or quoted value is
    refused rather than guessed at: what it means depends on the
    environment, and the opt-out must be unambiguous.
    """
    try:
        doc = yaml.safe_load(compose_path.read_text())
    except (OSError, yaml.YAMLError) as e:
        raise ComposeResolveError(f"cannot read {compose_path.name} as written: {e}") from e
    if not isinstance(doc, dict):
        raise ComposeResolveError(f"{compose_path.name}: top level must be a mapping")
    services = doc.get("services") or {}
    if not isinstance(services, dict):
        raise ComposeResolveError(f"{compose_path.name}: 'services' must be a mapping")
    declared: dict[str, bool] = {}
    for name, svc in services.items():
        if not isinstance(svc, dict) or "read_only" not in svc:
            continue
        value = svc["read_only"]
        if not isinstance(value, bool):
            raise ComposeResolveError(
                f"{compose_path.name}: service {name!r} has read_only: {value!r}, "
                f"which is not a boolean. Write an unquoted true or false "
                f"(boxmunge does not guess what an interpolated or quoted "
                f"value means)."
            )
        declared[str(name)] = value
    return declared


def restore_read_only_false(model: dict[str, Any], compose_path: Path) -> None:
    """Put each `read_only: false` the file declares back into the resolved
    model, in place. The user's literal value wins over the model."""
    services = model.get("services")
    if not isinstance(services, dict):
        return
    for name, value in declared_read_only(compose_path).items():
        svc = services.get(name)
        if value is False and isinstance(svc, dict):
            svc["read_only"] = False


def resolve_compose_config(compose_path: Path, project_name: str, *,
                           project_directory: Path | None = None) -> dict[str, Any]:
    """Return the fully resolved compose model for one compose file, with
    every profile: validation and the overlay cover profiled services too.
    ``project_directory`` resolves a compose file kept beside the release
    it describes (staging's base, in the slot).

    `read_only: false` is restored from the literal file (see above).

    Fails closed: a service the literal files declare (with their includes)
    but the model lacks would go unchecked and unhardened, for example on a
    Compose that ignored `--profile '*'`."""
    cwd = project_directory or compose_path.parent
    files = [str(compose_path)] if project_directory else [compose_path.name]
    extra = {"project_directory": project_directory} if project_directory else {}
    try:
        with _missing_env_files_present(compose_path, cwd):
            out = docker.compose_config(cwd, files, project_name=project_name,
                                        all_profiles=True, **extra)
    except docker.DockerError as e:
        raise ComposeResolveError(
            f"`docker compose config` could not resolve {compose_path.name}: {e}"
        ) from e
    model = _parse_config(out)
    resolved = model.get("services")
    missing = _literal_service_names(compose_path, compose_path.parent, set()) - {
        str(name) for name in (resolved if isinstance(resolved, dict) else ())}
    if missing:
        raise ComposeResolveError(
            f"`docker compose config` left out service(s) {', '.join(sorted(missing))}, "
            f"which {compose_path.name} declares, so they cannot be checked or "
            f"hardened. Upgrade Docker Compose (it must resolve every profile), "
            f"or remove the services."
        )
    restore_read_only_false(model, compose_path)
    return model


def resolve_deployed_config(
    project_dir: Path, compose_files: list[str], project_name: str,
    *, all_profiles: bool = False, project_directory: Path | None = None,
    env_file: Path | None = None, user_compose: Path | None = None,
) -> dict[str, Any]:
    """Return the merged model a deployed project runs with.

    Resolves every compose file the project is deployed with, from its
    directory, the way `up` does. Unlike a bundle under validation, a
    deployed project has its on-box env files, so nothing is stood in for:
    a missing one is the same error `up` would hit. ``project_directory``
    and ``env_file`` are passed to Compose (see docker.compose_config).
    ``user_compose``: the user's own compose.yml when the model is built from
    it alone; its `read_only: false` is restored (the model drops it). Not for
    a model that merges boxmunge's overlay, which owns the merged value.
    """
    elsewhere = {k: v for k, v in (("project_directory", project_directory),
                                   ("env_file", env_file)) if v is not None}
    try:
        out = docker.compose_config(
            project_dir, compose_files, project_name=project_name,
            all_profiles=all_profiles, **elsewhere,
        )
    except docker.DockerError as e:
        raise ComposeResolveError(
            f"`docker compose config` could not resolve {', '.join(compose_files)}: {e}"
        ) from e
    model = _parse_config(out)
    if user_compose is not None:
        restore_read_only_false(model, user_compose)
    return model


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
    host path they name stays inside the project, and noting every file
    Compose reads: compose, include, extends and env files."""

    def __init__(self, roots: tuple[Path, ...]) -> None:
        self.roots = roots
        self.problems: list[str] = []
        self.files: list[Path] = []
        self._seen: set[str] = set()

    def _confined(self, what: str, ref: Any, base: Path, *, read: bool = True) -> bool:
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
                f"directory. Keep every compose, extends, include, env_file and "
                f"label_file path inside the project."
            )
            return False
        if read:
            self.files.append(Path(host_path_forms(ref, base)[0]))
        return True

    def visit(self, path: Path, base: Path | None = None) -> None:
        """``base`` resolves the file's relative paths (default: its directory)."""
        key = str(path.resolve())
        if key in self._seen or not path.is_file():
            return  # Compose itself reports a missing file.
        self._seen.add(key)
        self.files.append(path)
        try:
            doc = yaml.safe_load(path.read_text())
        except yaml.YAMLError as e:
            self.problems.append(f"{path.name}: cannot parse: {e}")
            return
        if not isinstance(doc, dict):
            return
        base = base or path.parent
        for compose_paths, env_files, project_dir in _include_entries(doc):
            for ref in compose_paths:
                if self._confined(f"{path.name}: include", ref, base):
                    self.visit(Path(host_path_forms(ref, base)[0]))
            for ref in env_files:
                self._confined(f"{path.name}: include env_file", ref, base)
            if project_dir is not None and self._confined(
                f"{path.name}: include project_directory", project_dir, base, read=False,
            ):
                # Compose loads `.env` from an include's project_directory,
                # so that file steers interpolation of the included model.
                self.files.append(Path(host_path_forms(project_dir, base)[0]) / ".env")
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
            # label_file is read by the daemon, as root, like env_file.
            for ref in _as_list(svc.get("label_file")):
                self._confined(f"{path.name}: service {svc_name}: label_file", ref, base)


def walk_references(
    compose_path: Path, roots: tuple[Path, ...], *, base: Path | None = None,
) -> tuple[list[str], list[Path]]:
    """Return (every include/extends/env_file/label_file reference that
    leaves the project, every file the compose file makes Compose read).
    ``base`` is the project directory Compose resolves the file from, when
    that is not the file's own directory."""
    walk = _ReferenceWalk(roots)
    walk.visit(compose_path, base)
    return walk.problems, walk.files
