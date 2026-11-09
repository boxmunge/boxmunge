# SPDX-License-Identifier: Apache-2.0
"""Staging's fresh copies of production's data belong to the users that run them.

The data copy (staging_data) keeps production's owners. A staged release
that runs a service as another user (the change a `data chown` would make
for production) would start over data it cannot write. Staging's copy is
staging's own and was just made from production, so it is given to the
user the staged release decided for the service that writes it, as part of
the copy: staging tests the new user without production's data changing
hands first. A store several services write as different users is left as
it is (the stage's owner check names it); so is one only root or a named
user writes.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING

from boxmunge.commands.deploy_checks import persistent, service_mounts
from boxmunge.data_helper import chown_under, run_helper, volume
from boxmunge.staging_placeholders import copy_label

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths
    from boxmunge.run_as import ServiceUser
    from boxmunge.staging_copy_plan import CopyPlan, Store


def _writers(dest: Store, services: dict[str, dict]) -> set[str]:
    """The services that mount `dest` (or a path in or around it) read-write."""
    found = set()
    for name, svc in services.items():
        for m in persistent(service_mounts(svc)):
            if dest.kind == "volume" and m.kind == "volume" and str(m.source) == dest.key:
                found.add(name)
            elif dest.kind == "bind" and m.kind == "bind":
                a, b = os.path.normpath(str(m.source)), os.path.normpath(dest.ref)
                if a == b or a.startswith(b + "/") or b.startswith(a + "/"):
                    found.add(name)
    return found


def give_copies(paths: BoxPaths, project: str, plan: CopyPlan, services: dict[str, dict],
                users: dict[str, ServiceUser]) -> None:
    """Give each store the copy filled to the user of the service that
    writes it (`services`: staging's resolved model; `users`: the staged
    release's decision)."""
    project_dir = paths.project_dir(project)
    for _src, dest in plan.pairs:
        owners = {users[s].owner_ids() for s in _writers(dest, services) if s in users}
        if len(owners) != 1 or None in owners:
            continue
        ids = owners.pop()
        print(f"  Giving staging's copy {dest.label} to {ids[0]}:{ids[1]}, who runs it...")
        if dest.kind == "volume":
            run_helper(copy_label(project), volume(dest.ref, "/x"),
                       f"chown -R -h {ids[0]}:{ids[1]} /x")
        else:
            chown_under(copy_label(project), project_dir,
                        Path(os.path.relpath(dest.ref, project_dir)), ids)
