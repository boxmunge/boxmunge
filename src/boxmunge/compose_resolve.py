# SPDX-License-Identifier: Apache-2.0
"""Resolve a user compose file the way Docker Compose will run it.

The literal compose.yml is not what runs: Compose interpolates `${VAR}`
from the bundled `.env` and the environment, merges `extends:` and
`include:` files, and normalises short syntax. Validating only the
literal file let all of those smuggle in values the validator never saw.
So the validator and the overlay generator work on the output of
`docker compose -p <project> config`, which is exactly the model Compose
will start.

What `config` output cannot show is where it read things from: those
references are checked on the literal files (boxmunge.compose_references),
and the env files the model names are checked here too.
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
from boxmunge.compose_references import entry_base, env_file_paths, include_entries
from boxmunge.fs_nofollow import open_dir_beneath


class ComposeResolveError(Exception):
    """Raised when a compose file cannot be resolved by Docker Compose."""


@contextmanager
def _missing_env_files_present(compose_path: Path, base: Path | None = None) -> Iterator[None]:
    """Make absent in-project service env files exist while Compose resolves.

    A bundle is validated in an extraction directory, where on-box files such
    as secrets.env do not exist, and Compose versions older than the one
    this was last probed on (5.1.3 resolves without them) refuse a model
    whose env_file is missing, even with --no-env-resolution: CI's did. Each
    missing env file that stays inside ``base`` (the directory Compose
    resolves relative paths against, by default the compose file's), in a
    directory that already exists with no link on the way from ``base``, is
    created empty for the duration of the call and removed afterwards. No
    directory is ever made: root resolves at every start check, in a tree
    deploy can write.
    Validation never reads their values. A placeholder that somehow
    survived could not reach a live project: installing a release that
    carries secrets.env is refused.
    """
    created: list[tuple[int, str]] = []
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
            for ref in env_file_paths(svc.get("env_file")):
                try:
                    skip = (not isinstance(ref, str) or not ref or has_env_substitution(ref)
                            or outside_roots(ref, base, (base,)))
                except (OSError, ValueError):
                    skip = True  # not a usable name (a NUL, say)
                if skip:
                    continue  # the reference walk reports these
                placeholder = _placeholder(base, Path(host_path_forms(ref, base)[0]))
                if placeholder is not None:
                    created.append(placeholder)
        yield
    finally:
        for dir_fd, name in created:
            try:
                os.unlink(name, dir_fd=dir_fd)
            except FileNotFoundError:
                pass
            finally:
                os.close(dir_fd)


def _placeholder(base: Path, target: Path) -> tuple[int, str] | None:
    """Create ``target`` (a path under ``base``) empty if it is missing and
    every directory from ``base`` to it exists and is not a link; return
    (directory fd, name) to remove it by, or None. The directories are
    walked one component at a time with O_NOFOLLOW (fs_nofollow), so a link
    swapped in at any depth after the outside_roots check makes root
    create nothing; the file itself is created O_EXCL|O_NOFOLLOW."""
    rel = Path(os.path.relpath(target, base)).parts
    try:
        dir_fd = open_dir_beneath(base, rel[:-1])
    except (OSError, ValueError):
        return None  # missing, a link, a NUL, or not under base: Compose reports it
    try:
        os.close(os.open(rel[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                         | os.O_CLOEXEC, 0o644, dir_fd=dir_fd))
    except OSError:
        os.close(dir_fd)
        return None  # already there (or a link to anything): left as it is
    return dir_fd, rel[-1]


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


def _literal_service_names(path: Path, root: Path, seen: set[tuple[Path, Path]],
                           base: Path | None = None) -> set[str]:
    """Service names a compose file and the files it includes declare.
    ``base`` resolves the file's relative paths (see compose_references.entry_base)."""
    base = base or path.parent
    if (path, base) in seen or not path.is_file():
        return set()
    seen.add((path, base))
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
    for compose_paths, _extra in include_entries(doc):
        new_base = entry_base(compose_paths, base)
        for ref in compose_paths if new_base is not None else []:
            if isinstance(ref, str) and not outside_roots(ref, base, (root,)):
                names |= _literal_service_names(
                    Path(host_path_forms(ref, base)[0]), root, seen, new_base)
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
    missing = _literal_service_names(compose_path, cwd, set(), cwd) - {
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


def model_env_files(model: dict[str, Any], base_dir: Path) -> list[Path]:
    """Every service env file the resolved model makes Compose read. Compose
    emits them absolute; a relative one means relative to ``base_dir``, the
    directory Compose resolved from."""
    services = model.get("services")
    return [Path(host_path_forms(ref, base_dir)[0])
            for svc in (services.values() if isinstance(services, dict) else [])
            if isinstance(svc, dict)
            for ref in env_file_paths(svc.get("env_file")) if isinstance(ref, str) and ref]


def model_env_file_problems(model: dict[str, Any], base_dir: Path, roots: tuple[Path, ...],
                            project_name: str) -> list[str]:
    """Every env file of the resolved model that lies outside ``roots``.

    The literal walk is the first line (it reports the file that wrote the
    reference); this checks what Compose itself concluded, so a resolution
    rule the walk does not mirror cannot let another project's or the
    host's file through. `label_file` cannot be checked here: `config`
    inlines its contents into `labels` and drops the path."""
    services = model.get("services")
    problems = []
    for name, svc in (services.items() if isinstance(services, dict) else []):
        refs = env_file_paths(svc.get("env_file")) if isinstance(svc, dict) else []
        problems += [
            f"service {name}: env_file {ref!r} in the model Compose resolved lies "
            f"outside the project directory. Keep every env_file path inside the "
            f"project, then upload the fixed release and deploy it: prod-deploy "
            f"{project_name}."
            for ref in refs
            if not isinstance(ref, str) or not ref or outside_roots(ref, base_dir, roots)]
    return problems
