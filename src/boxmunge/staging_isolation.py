# SPDX-License-Identifier: Apache-2.0
"""Prove that staging and production share no Docker resource.

Both environments run on one daemon beside one project directory. Staging
is safe only if nothing either one names reaches the other: no volume,
network, network alias, container name or built image tag, and no bind
mount source (equal, or one inside the other). Every model is resolved by
`docker compose config` from the files the environment really runs with:
production from its project dir and overlay; staging from the slot
(staged_release.staging_target); and, before a stage or a production
install, production as it would run with the candidate. Any overlap
refuses the stage, or the install, before anything changes.

The shared ``boxmunge-proxy`` network itself is deliberately common to
every project; the explicit aliases on it are not.
"""
from __future__ import annotations

import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from boxmunge.bind_mounts import project_relative
from boxmunge.compose import generate_compose_override, load_user_compose, production_env_files
from boxmunge.compose_build import is_local_ref
from boxmunge.compose_mounts import is_bind_entry, volume_source
from boxmunge.compose_resolve import ComposeResolveError, resolve_deployed_config
from boxmunge.docker import staging_compose_project
from boxmunge.staged_release import ComposeTarget, has_slot, staging_target

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


class StagingIsolationError(ValueError):
    """Staging would share a resource with production."""


@dataclass(frozen=True)
class Identities:
    volumes: set[str] = field(default_factory=set)
    networks: set[str] = field(default_factory=set)
    aliases: set[str] = field(default_factory=set)       # "<network>/<alias>"
    containers: set[str] = field(default_factory=set)
    images: set[str] = field(default_factory=set)        # every image a service runs
    built: set[str] = field(default_factory=set)         # the tags `build` writes
    binds: dict[str, str] = field(default_factory=dict)  # host path -> what mounts it


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _replicas(svc: dict[str, Any]) -> int:
    count = _mapping(svc.get("deploy")).get("replicas", svc.get("scale", 1))
    return max(1, count) if isinstance(count, int) else 1


def _bind_target(entry: Any) -> str:
    if isinstance(entry, dict):
        return str(entry.get("target"))
    return entry.split(":")[1] if entry.count(":") else entry


def _host_paths(source: str, project_dir: Path) -> set[str]:
    path = os.path.normpath(os.path.join(project_dir, os.path.expanduser(source)))
    return {path, os.path.realpath(path)}


def identities(model: dict[str, Any], project: str, project_dir: Path) -> Identities:
    """Every resource name and host path a resolved compose model claims."""
    ids = Identities()
    networks = _mapping(model.get("networks"))
    for key, decl in _mapping(model.get("volumes")).items():
        ids.volumes.add(_mapping(decl).get("name") or f"{project}_{key}")
    for key, decl in networks.items():
        if not _mapping(decl).get("external"):
            ids.networks.add(_mapping(decl).get("name") or f"{project}_{key}")
    for name, svc in _mapping(model.get("services")).items():
        if not isinstance(svc, dict):
            continue
        explicit = svc.get("container_name")
        ids.containers.update([explicit] if explicit else
                              [f"{project}-{name}-{i}" for i in range(1, _replicas(svc) + 1)])
        image = svc.get("image") or f"{project}-{name}"
        ids.images.add(image)
        if svc.get("build") is not None:
            ids.built.add(image)
        for net, cfg in _mapping(svc.get("networks")).items():
            decl = _mapping(networks.get(net))
            if decl.get("external"):
                net_name = decl.get("name") or net
                ids.aliases.update(f"{net_name}/{a}" for a in _mapping(cfg).get("aliases") or [])
        for entry in svc.get("volumes") or []:
            if is_bind_entry(entry):
                for path in _host_paths(volume_source(entry), project_dir):
                    ids.binds[path] = f"{name}:{_bind_target(entry)}"
    for section in ("configs", "secrets"):
        for key, decl in _mapping(model.get(section)).items():
            if isinstance(_mapping(decl).get("file"), str):
                for path in _host_paths(decl["file"], project_dir):
                    ids.binds[path] = f"{section[:-1]} {key}"
    return ids


def _nested(a: str, b: str) -> bool:
    return a == b or a.startswith(b.rstrip("/") + "/") or b.startswith(a.rstrip("/") + "/")


def overlaps(prod: Identities, staging: Identities) -> list[str]:
    """Each resource both environments would use, described."""
    found = [f"{kind} {name}" for kind, a, b in (
        ("volume", prod.volumes, staging.volumes),
        ("network", prod.networks, staging.networks),
        ("network alias", prod.aliases, staging.aliases),
        ("container name", prod.containers, staging.containers),
    ) for name in sorted(a & b)]
    # A build replaces the tag it writes, whoever else runs that image.
    found += [f"image {name} (staging builds it; production runs it)"
              for name in sorted(staging.built & prod.images)]
    found += [f"image {name} (production builds it; staging would run it)"
              for name in sorted(prod.built & staging.images - staging.built)]
    seen: set[tuple[str, str]] = set()
    for p_path, p_use in sorted(prod.binds.items()):
        for s_path, s_use in sorted(staging.binds.items()):
            if _nested(p_path, s_path) and (p_use, s_use) not in seen:
                seen.add((p_use, s_use))
                found.append(f"bind mount {s_path} (production {p_use} mounts "
                             f"{p_path}; staging {s_use})")
    return found


def whole_project_mounts(ids: Identities, project_dir: Path, environment: str) -> list[str]:
    whole = {os.path.normpath(project_dir), os.path.realpath(project_dir)}
    return [f"{environment} {use} mounts the whole project directory ({path}), which "
            f"staging and production cannot each have a copy of. Mount the "
            f"subdirectories the service needs instead."
            for path, use in sorted(ids.binds.items()) if path in whole]


def _read_only(entry: Any) -> bool:
    if isinstance(entry, dict):
        return entry.get("read_only") is True
    parts = entry.split(":")
    return len(parts) > 2 and "ro" in parts[2].split(",")


def _build_inputs(build: Any) -> Iterator[tuple[str, str]]:
    """(what, host path) of each local input of a resolved build: Compose has
    made the context and additional contexts absolute; a relative dockerfile
    is resolved against the context."""
    if not isinstance(build, dict):
        return
    context = build.get("context")
    local = isinstance(context, str) and is_local_ref(context)
    if local:
        yield "context", context
    dockerfile = build.get("dockerfile")
    if isinstance(dockerfile, str) and (os.path.isabs(dockerfile) or local):
        yield "dockerfile", os.path.join(context if local else "", dockerfile)
    contexts = build.get("additional_contexts")
    if isinstance(contexts, list):
        contexts = dict(str(e).partition("=")[::2] for e in contexts)
    for name, ref in _mapping(contexts).items():
        if isinstance(ref, str) and is_local_ref(ref, additional=True):
            yield f"additional_contexts.{name}", ref


def _build_problems(name: str, build: Any, project_dir: Path, roots: set[str]) -> list[str]:
    """Staging builds only from the staged release: a build input elsewhere
    in the project dir (named by interpolation, say, which the base rewrite
    cannot see) would build production's files, or its data."""
    problems = []
    for what, ref in _build_inputs(build):
        path = os.path.normpath(ref)
        forms = dict.fromkeys((path, os.path.realpath(path)))
        if any(project_relative(form, project_dir, literal=True) is not None
               and not any(form == r or form.startswith(r + os.sep) for r in roots)
               for form in forms):
            problems.append(f"staging service {name} build {what} reads {path}, which is "
                            f"production's; build from the staged release (a path "
                            f"relative to the release)")
    return problems


def separation_problems(model: dict[str, Any], project_dir: Path, release: Path) -> list[str]:
    """I3: staging mounts nothing of production's except its -staging copies
    (read-write) and the slot's release (read-only), and builds only from
    the slot's release."""
    roots = {os.path.normpath(release), os.path.realpath(release)}

    def check(src: str, ro: bool, what: str) -> list[str]:
        path = os.path.normpath(os.path.join(release, os.path.expanduser(src)))
        if any(path == r or path.startswith(r + os.sep) for r in roots):
            return [] if ro else [f"staging {what} mounts the staged release ({path}) "
                                  f"read-write; mount release code read-only"]
        rel = project_relative(path, project_dir)
        if rel is None or rel.split(os.sep, 1)[0].endswith("-staging"):
            return []
        return [f"staging {what} mounts {path}, which is production's"]

    problems: list[str] = []
    for name, svc in _mapping(model.get("services")).items():
        for entry in (svc.get("volumes") or []) if isinstance(svc, dict) else []:
            if is_bind_entry(entry):
                problems += check(volume_source(entry), _read_only(entry), f"service {name}")
        if isinstance(svc, dict):
            problems += _build_problems(name, svc.get("build"), project_dir, roots)
    for section in ("configs", "secrets"):
        for key, decl in _mapping(model.get(section)).items():
            if isinstance(_mapping(decl).get("file"), str):
                problems += check(decl["file"], True, f"{section[:-1]} {key}")
    return problems


@contextmanager
def resolving() -> Iterator[None]:
    """A model that cannot be resolved cannot be proved apart: refuse."""
    try:
        yield
    except ComposeResolveError as e:
        raise StagingIsolationError(f"cannot resolve the environments to compare: {e}") from e


def production_model(paths: BoxPaths, project: str) -> dict[str, Any] | None:
    """The model production runs with, from its project dir; None when it
    was never deployed."""
    project_dir = paths.project_dir(project)
    if not (project_dir / "manifest.yml").exists():
        return None
    overlay = paths.project_compose_override(project)
    if not overlay.exists():
        raise StagingIsolationError(
            f"production of '{project}' has no {overlay.name}, so what it runs cannot be "
            f"checked against staging. Redeploy production first.")
    return resolve_deployed_config(project_dir, ["compose.yml", overlay.name], project,
                                   all_profiles=True)


def staging_model(target: ComposeTarget) -> dict[str, Any]:
    return resolve_deployed_config(target.cwd, target.files, target.project_name,
                                   all_profiles=True, project_directory=target.project_directory,
                                   env_file=target.env_file)


def _without_read_files(compose: Path, dest: Path) -> Path:
    """``compose`` without its services' env and label files. They are
    release code the project dir lacks until the install, which Compose
    2.35 refuses to resolve even with --no-env-resolution, and they name no
    resource the comparison looks at. Every relative path in it resolves
    against --project-directory, wherever the copy lies."""
    doc = yaml.safe_load(compose.read_text())
    for svc in _mapping(_mapping(doc).get("services")).values():
        if isinstance(svc, dict):
            svc.pop("env_file", None)
            svc.pop("label_file", None)
    dest.write_text(yaml.safe_dump(doc, default_flow_style=False, sort_keys=False))
    return dest


def _refuse_other_files(compose: Path) -> None:
    """The candidate is resolved with production's project dir as its
    --project-directory, so an include: or extends: file: would be read
    from production's current files, not the candidate's: the proof would
    compare the wrong model. Refused rather than proved wrongly."""
    doc = _mapping(yaml.safe_load(compose.read_text()))
    services = _mapping(doc.get("services")).values()
    if "include" in doc or any(isinstance(svc, dict) and isinstance(svc.get("extends"), dict)
                               and "file" in svc["extends"] for svc in services):
        raise StagingIsolationError(
            "a release whose compose.yml uses include: or extends: file: cannot be "
            "checked against staging while a release is staged. Unstage first, or "
            "remove include/extends (move those services into compose.yml)")


def candidate_model(paths: BoxPaths, project: str, tree: Path, manifest: dict[str, Any],
                    scratch: Path) -> dict[str, Any]:
    """What production would run once ``tree`` is installed in the project
    dir: its compose.yml and the overlay it would get, resolved there."""
    _refuse_other_files(tree / "compose.yml")
    overlay = scratch / "compose.boxmunge.candidate.yml"
    overlay.write_text(generate_compose_override(
        manifest, env_files=production_env_files(paths, project) or None,
        user_compose=load_user_compose(tree / "compose.yml", project)))
    compose = _without_read_files(tree / "compose.yml", scratch / "compose.candidate.yml")
    env = tree / ".env"
    project_dir = paths.project_dir(project)
    return resolve_deployed_config(
        project_dir, [str(compose), str(overlay)], project, all_profiles=True,
        project_directory=project_dir, env_file=env if env.is_file() else Path(os.devnull))


def check_isolation(paths: BoxPaths, project: str, staging: dict[str, Any],
                    productions: list[tuple[str, dict[str, Any]]]) -> None:
    """Refuse a staging model that shares anything with any of the labelled
    production models. Raises StagingIsolationError naming each problem."""
    project_dir = paths.project_dir(project)
    staging_ids = identities(staging, staging_compose_project(project), project_dir)
    problems = whole_project_mounts(staging_ids, project_dir, "staging")
    for label, model in productions:
        prod_ids = identities(model, project, project_dir)
        problems += whole_project_mounts(prod_ids, project_dir, label)
        shared = overlaps(prod_ids, staging_ids)
        if shared:
            problems.append(f"staging would share these with {label}:\n    - "
                            + "\n    - ".join(shared))
    if problems:
        raise StagingIsolationError(
            "staging cannot be kept apart from production:\n  - " + "\n  - ".join(problems))


def check_install_isolation(paths: BoxPaths, project: str, tree: Path,
                            manifest: dict[str, Any]) -> None:
    """D8: a production install while a release is staged must share nothing
    with the slot's staging. Raises StagingIsolationError. The scratch lies
    in .releases/ as ``.isolation-*``: a kill leaves it for
    staged_release.sweep_debris, which deploy and rollback run under the lock."""
    if not has_slot(paths, project):
        return
    releases = paths.project_releases(project)
    with resolving():
        with tempfile.TemporaryDirectory(dir=releases, prefix=".isolation-") as scratch:
            candidate = candidate_model(paths, project, tree, manifest, Path(scratch))
        staging = staging_model(staging_target(paths, project))
    check_isolation(paths, project, staging, [("production after this install", candidate)])
