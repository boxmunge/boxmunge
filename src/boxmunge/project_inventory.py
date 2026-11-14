# SPDX-License-Identifier: Apache-2.0
"""Which projects exist, and whether each has been deployed.

One classification every fleet operation shares. A project is:

- AWAITING: registered or created, never deployed (no manifest, no record of
  a deployment). Nothing to scan, back up or watch.
- DEPLOYED: its manifest is there (a link counts, even a dangling one: whether
  it reads is for the per-project boundary to report).
- DAMAGED: no manifest, yet deploy, scan or health state shows it was
  deployed. It still has data and maybe containers, so it is never skipped:
  fleet operations visit it, report it, and finish with a failing result.
"""

from __future__ import annotations

import os
from enum import Enum
from typing import TYPE_CHECKING

from boxmunge.paths import InvalidProjectName

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


class Inventory(Enum):
    AWAITING = "awaiting first deploy"
    DEPLOYED = "deployed"
    DAMAGED = "damaged"


def classify(name: str, paths: BoxPaths) -> Inventory:
    """The project's inventory state. A name with no directory is AWAITING
    here: a removal that did not finish is project_registry.unfinished_removals."""
    project_dir = paths.projects / name
    if not project_dir.is_dir():
        return Inventory.AWAITING
    if os.path.lexists(project_dir / "manifest.yml"):
        return Inventory.DEPLOYED
    try:
        evidence = (paths.project_deploy_state(name), paths.project_scan_state(name),
                    paths.project_health_state(name))
    except InvalidProjectName:
        return Inventory.AWAITING   # no state can be kept under such a name
    return Inventory.DAMAGED if any(os.path.lexists(f) for f in evidence) else Inventory.AWAITING


def known_deployed(names, paths: BoxPaths) -> list[str]:
    """Those of `names` that are deployed or damaged, sorted."""
    return sorted(n for n in names if classify(n, paths) is not Inventory.AWAITING)


def damaged_among(names, paths: BoxPaths) -> list[str]:
    return sorted(n for n in names if classify(n, paths) is Inventory.DAMAGED)


def project_dir_names(paths: BoxPaths) -> list[str]:
    """Every directory under projects/ that is deployed or damaged, sorted;
    empty when there is no projects directory."""
    if not paths.projects.exists():
        return []
    return known_deployed((d.name for d in paths.projects.iterdir() if d.is_dir()), paths)


def damaged_detail(name: str) -> str:
    return (f"deployed before, but its manifest.yml is missing (or links to nothing); "
            f"redeploy it (`boxmunge prod-deploy {name}`), or restore the manifest from a backup")
