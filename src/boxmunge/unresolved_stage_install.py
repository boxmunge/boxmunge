# SPDX-License-Identifier: Apache-2.0
"""install.sh's check for an unresolved stage (boxmunge.unresolved_stage), for
an install run by hand. An upgrade asks in its dry run
(refuse_unresolved_stages); `sudo bash install.sh` never runs one.

bootstrap/unresolved-stage.sh runs main() from the bundle's src/ before the
package is installed, on the host's python3 with no site-packages. So this
module and everything it imports use the standard library only. Read-only.
Delete it, with the script and unresolved_stage.py, once the upgrade floor is
0.11.7.
"""
from __future__ import annotations

import os
from pathlib import Path

from boxmunge import unresolved_stage
from boxmunge.paths import BoxPaths, InvalidProjectName, validate_project_name
from boxmunge.version import read_installed_version

# main()'s status for a refusal. Any other non-zero status (a traceback exits
# 1) is a check that could not run, which the script reports as an error.
REFUSED = 10


def project_names(paths: BoxPaths) -> list[str]:
    """The projects an upgrade checks (upgrade_steps._project_dirs): each
    directory with a manifest.yml and a name boxmunge addresses."""
    if not paths.projects.exists():
        return []
    names = []
    for project_dir in sorted(paths.projects.iterdir()):
        if not (project_dir.is_dir() and os.path.lexists(project_dir / "manifest.yml")):
            continue
        try:
            validate_project_name(project_dir.name)
        except InvalidProjectName:  # the upgrade reports it and carries on without it
            continue
        names.append(project_dir.name)
    return names


def main(root: str) -> int:
    """Print why this release must not be installed over the box at `root` and
    return REFUSED, or return 0."""
    paths = BoxPaths(root=Path(root))
    refusal = unresolved_stage.refusal(paths, project_names(paths), read_installed_version(paths),
                                       retry="run the install again")
    if refusal is None:
        return 0
    print(refusal)
    return REFUSED
