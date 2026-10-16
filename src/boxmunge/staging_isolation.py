# SPDX-License-Identifier: Apache-2.0
"""Prove that staging and production share no Docker resource.

Both environments run on one daemon from one project directory. Staging is
safe only if nothing either one names reaches the other: no volume,
network, network alias, container name or built image tag, and no bind
mount source (equal, or one inside the other). Both models are resolved by
`docker compose config` from the files each environment really runs with:
production from its own release (the kept one during a stage) and its
generated overlay, staging from the generated staging files. Any overlap
refuses the stage before staging touches anything.

The shared ``boxmunge-proxy`` network itself is deliberately common to
every project; the explicit aliases on it are not.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from boxmunge.compose_mounts import is_bind_entry, volume_source
from boxmunge.compose_resolve import ComposeResolveError, resolve_deployed_config
from boxmunge.docker import staging_compose_project
from boxmunge.release_staging import has_prestage, prestage_ref, production_release_root
from boxmunge.staging_compose import STAGING_FILES

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


def mount_problems(ids: Identities, project_dir: Path, box_state: set[str],
                   environment: str) -> list[str]:
    """Mounts `stage` cannot keep apart: the whole project directory, and
    (for production) release code, which installing the staged release
    replaces: every entry but ``box_state``.
    """
    whole = {os.path.normpath(project_dir), os.path.realpath(project_dir)}
    problems: list[str] = []
    for path, use in sorted(ids.binds.items()):
        if path in whole:
            problems.append(
                f"{environment} {use} mounts the whole project directory ({path}), "
                f"which staging and production cannot each have a copy of. Mount "
                f"the subdirectories the service needs instead.")
            continue
        rel = next((os.path.relpath(path, base) for base in whole
                    if path.startswith(base + os.sep)), None)
        if environment == "production" and rel and rel.split(os.sep, 1)[0] not in box_state:
            problems.append(
                f"production {use} mounts {path} from the project directory, which "
                f"`stage` replaces with the staged release: production's "
                f"compose.boxmunge.yml was generated by an older boxmunge. An "
                f"upgrade regenerates it, or redeploy production's current "
                f"release; then stage again.")
    return list(dict.fromkeys(problems))


def production_model(paths: BoxPaths, project: str) -> dict[str, Any] | None:
    """The model production runs with; None when it was never deployed."""
    if has_prestage(paths, project) and prestage_ref(paths, project) is None:
        return None
    project_dir = paths.project_dir(project)
    overlay = paths.project_compose_override(project)
    if not (project_dir / "manifest.yml").exists() and not has_prestage(paths, project):
        return None
    if not overlay.exists():
        raise StagingIsolationError(
            f"production of '{project}' has no {overlay.name}, so what it runs "
            f"cannot be checked against staging. Redeploy production first.")
    release_root = production_release_root(paths, project)
    return resolve_deployed_config(
        project_dir, [str(release_root / "compose.yml"), overlay.name], project,
        all_profiles=True, project_directory=project_dir, env_file=_env_file(release_root))


def _env_file(release_root: Path) -> Path:
    env = release_root / ".env"
    return env if env.exists() else Path(os.devnull)


def staging_model(paths: BoxPaths, project: str, staging_dir: Path | None = None) -> dict:
    """Staging's model from its generated files in ``staging_dir`` (default
    the project dir; a candidate's are written beside it before install)."""
    project_dir = paths.project_dir(project)
    staging_dir = staging_dir or project_dir
    return resolve_deployed_config(
        project_dir, [str(staging_dir / f) for f in STAGING_FILES],
        staging_compose_project(project), all_profiles=True,
        project_directory=project_dir, env_file=_env_file(staging_dir))


def check_isolation(paths: BoxPaths, project: str, box_state: set[str],
                    staging_dir: Path | None = None) -> tuple[dict | None, dict]:
    """Resolve both environments and refuse anything `stage` cannot keep apart.

    ``box_state`` names the project entries that stay as they are once the
    staged release is installed. Returns (production model or None, staging model) for the
    data copy. Raises StagingIsolationError naming each problem found.
    """
    try:
        prod = production_model(paths, project)
        staging = staging_model(paths, project, staging_dir)
    except ComposeResolveError as e:
        raise StagingIsolationError(f"cannot resolve the environments to compare: {e}") from e
    project_dir = paths.project_dir(project)
    staging_ids = identities(staging, staging_compose_project(project), project_dir)
    problems = mount_problems(staging_ids, project_dir, box_state, "staging")
    if prod is not None:
        prod_ids = identities(prod, project, project_dir)
        problems = mount_problems(prod_ids, project_dir, box_state, "production") + problems
        shared = overlaps(prod_ids, staging_ids)
        if shared:
            problems.append("staging would share these with production:\n    - "
                            + "\n    - ".join(shared))
    if problems:
        raise StagingIsolationError(
            "staging cannot be kept apart from production:\n  - " + "\n  - ".join(problems))
    return prod, staging
