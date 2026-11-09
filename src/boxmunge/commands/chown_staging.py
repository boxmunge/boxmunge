# SPDX-License-Identifier: Apache-2.0
"""data chown's part for staging: staging's own copies of a service's data.

Staging keeps its own copy of production's data between stages (a bind
under `<entry>-staging`, a named volume of the `<project>-staging` compose
project; staging_compose). Once a service runs as a new user, its next
stage runs it as that user too, over those copies, so `data chown` gives
them to the new user as well (staging_copies says which entries are
staging's). Staging must have no container of the service: one would run
its old user over the copy, as it is created, or come back on its own
after a reboot. `unstage` removes them, and keeps the copies.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from boxmunge.bind_sources import project_rel, source_kind
from boxmunge.bundle import STAGING_SUFFIX
from boxmunge.commands.deploy_checks import writable_by_a_container
from boxmunge.data_helper import COMPOSE_VOLUME_LABEL, chown_under, run_helper, volume, volume_labels
from boxmunge.docker import COMPOSE_PROJECT_LABEL, staging_compose_project
from boxmunge.docker_containers import project_containers
from boxmunge.paths import BoxPaths
from boxmunge.staging_copies import is_staging_copy, production_view, slot_made


class StagingChownRefused(Exception):
    """Staging's copies cannot be given to the new user as things are."""


@dataclass(frozen=True)
class StagingCopy:
    kind: str           # "bind" (path relative to the project dir) or "volume" (its name)
    where: str


def staging_copies(paths: BoxPaths, project: str, service: str,
                   mounts: list) -> list[StagingCopy]:
    """Staging's existing copies of `mounts` (production's persistent mounts
    of `service`). Raises StagingChownRefused while staging has a container
    of `service` and there is a copy to re-own."""
    project_dir = paths.project_dir(project)
    staging = staging_compose_project(project)
    dirs = production_view(project_dir)
    made = slot_made(paths, project)
    found: list[StagingCopy] = []
    for m in mounts:
        if m.kind == "bind":
            top, _, rest = project_rel(str(m.source), project_dir).partition("/")
            copy = f"{top}{STAGING_SUFFIX}"
            if not is_staging_copy(copy, dirs, made):
                continue
            rel = f"{copy}/{rest}" if rest else copy
            if os.path.lexists(project_dir / rel):
                found.append(StagingCopy("bind", rel))
            continue
        name = f"{staging}_{m.source}"
        labels = volume_labels(name)
        if labels is None:
            continue
        if (labels.get(COMPOSE_PROJECT_LABEL), labels.get(COMPOSE_VOLUME_LABEL)) != \
                (staging, str(m.source)):
            raise StagingChownRefused(
                f"volume {name} is not labelled as staging's {m.source!r}; it was not "
                f"changed. Inspect it, and remove it if it is a leftover")
        found.append(StagingCopy("volume", name))
    held = sorted(c.name for c in project_containers(staging)
                  if c.service == service and not c.oneoff)
    if found and held:
        raise StagingChownRefused(
            f"staging has containers of {service} ({', '.join(held)}), which would run "
            f"its old user over staging's copy of its data. Run `boxmunge unstage "
            f"{project}` (it keeps the copies), then run data chown again")
    return found


def chown_staging_copies(paths: BoxPaths, project: str, copies: list[StagingCopy],
                         ids: tuple[int, int]) -> list[str]:
    """Give each copy to `ids`, reached as production's binds are (no link
    on the way, only the project dir mounted). Returns what was changed."""
    project_dir = paths.project_dir(project)
    done = []
    for c in copies:
        print(f"  Giving staging's copy {c.where} to {ids[0]}:{ids[1]}...")
        if c.kind == "bind":
            holder = writable_by_a_container(project, str(project_dir / c.where), below=True)
            if holder is not None:
                raise StagingChownRefused(
                    f"staging's copy {c.where} lies inside {holder}, which a container of "
                    f"{project} mounts read-write; give {holder} itself to "
                    f"{ids[0]}:{ids[1]}, or stop mounting it read-write")
            source_kind(project_dir, c.where, create=False)
            chown_under(f"{project}-chown", project_dir, Path(c.where), ids)
        else:
            run_helper(f"{project}-chown", volume(c.where, "/x"),
                       f"chown -R -h {ids[0]}:{ids[1]} /x")
        done.append(c.where)
    return done
