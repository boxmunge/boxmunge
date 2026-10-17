# SPDX-License-Identifier: Apache-2.0
"""Storage a release needs before its first start.

- A missing read-write bind source for a numeric non-root service, or any
  one on a remapped box (where container root cannot write a deploy-owned
  directory), is made through the helper and given to the service's user.
  One inside a directory a container of the project mounts read-write is
  refused: that container could swap part of its path for a link. Its
  parents are made as deploy and walked free of links (bind_sources). On
  an unremapped box the helper makes it with only the project dir mounted,
  reached inside (data_helper.mkdir_under); on a remapped one, where
  container root cannot write the deploy-owned parent, the daemon makes it.
  Otherwise the start check's deploy-owned creation stands.
- A named volume this deploy creates, at a path the image does not have, is
  created here with Compose's labels and its empty root given to the
  service's user once: no image directory is copied into it, so no later
  create undoes that (deploy_checks proved an image-owned one matches).
"""
from __future__ import annotations

import os
from pathlib import Path

from boxmunge.bind_sources import BindSourceError, project_rel, source_kind
from boxmunge.commands.deploy_checks import service_mounts, volume_name, writable_by_a_container
from boxmunge.data_helper import (
    compose_volume_labels, mkdir_under, run_helper, volume, volume_labels,
)
from boxmunge.docker_containers import image_facts
from boxmunge.docker_run import run as _run
from boxmunge.image_probe import probe_dir
from boxmunge.paths import BoxPaths
from boxmunge.release_target import ReleaseTarget, resolved_services
from boxmunge.run_as import read_users
from boxmunge.userns.offset import remap_offset

# Characters that `-v src:dst` would read as its own syntax.
_V_SYNTAX = (":", ",")


def _bind_source(target: ReleaseTarget, paths: BoxPaths, source: str,
                 ids: tuple[int, int] | None, offset: int) -> None:
    if os.path.lexists(source):
        return
    project_dir = paths.project_dir(target.project)
    holder = writable_by_a_container(target.project, source, below=False)
    if holder is not None:
        raise BindSourceError(
            f"bind source {source} lies inside {holder}, which a container of "
            f"{target.project} mounts read-write, so it could swap part of the path for a "
            f"link before the source is made. Mount it outside that directory, or stop "
            f"mounting {holder} read-write")
    rel = project_rel(source, project_dir)
    parent = os.path.dirname(rel)
    if parent:
        source_kind(project_dir, parent, create=True)
    label = f"{target.compose_project}-storage"
    print(f"  Creating {source} for the service's user...")
    if not offset:
        mkdir_under(label, project_dir, Path(rel), ids)
        return
    # Container root cannot write a deploy-owned parent on a remapped box,
    # so the daemon makes the source. Its parents were just walked free of
    # links as deploy, and no container can write them (checked above).
    if any(c in source for c in _V_SYNTAX):
        raise BindSourceError(f"bind source {source} contains ':' or ',', which the "
                              f"helper's -v mount would misread; rename it")
    script = f"chown {ids[0]}:{ids[1]} /x" if ids else "true"
    run_helper(label, ["-v", f"{source}:/x"], script)


def _fresh_volume(target: ReleaseTarget, model: dict, key: str, image: str, path: str,
                  ids: tuple[int, int]) -> None:
    decl = (model.get("volumes") or {}).get(key)
    if isinstance(decl, dict) and decl.get("external"):
        return  # the operator's own volume: never created or chowned here
    name = volume_name(model, target.compose_project, key)
    if volume_labels(name) is not None:
        return  # not created by this deploy: never re-chowned
    if probe_dir(image_facts(image).image_id, path) is not None:
        return  # the image owns it; deploy_checks proved the owner matches
    _run(["docker", "volume", "create",
          *compose_volume_labels(target.compose_project, key), name], capture=True)
    run_helper(f"{target.compose_project}-storage", volume(name, "/x"),
               f"chown {ids[0]}:{ids[1]} /x")


def prepare_storage(paths: BoxPaths, target: ReleaseTarget) -> None:
    """Raises DockerError (HelperError), BindSourceError or RunAsError."""
    users = read_users(paths, target.project, staging=target.staging)
    model, services = resolved_services(target)
    offset = remap_offset(paths)
    for name, svc in sorted(services.items()):
        ids = users[name].owner_ids() if name in users else None
        for m in service_mounts(svc):
            if m.kind == "bind" and not m.read_only and m.source and (offset or ids):
                _bind_source(target, paths, m.source, ids, offset)
            elif m.kind == "volume" and m.source and ids:
                _fresh_volume(target, model, m.source, str(svc.get("image")), m.target,
                              ids)
