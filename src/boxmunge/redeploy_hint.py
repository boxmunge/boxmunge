# SPDX-License-Identifier: Apache-2.0
"""The command that deploys a project's installed release again.

Remedies that say "deploy it again" must name a command prod-deploy
accepts from that state. A bare `prod-deploy <project>` is not one for a
bundle project whose inbox is empty (commands/deploy_no_bundle): it
needs --redeploy. A git project's bare prod-deploy deploys whatever its
ref names now, so the installed commit is named with --ref.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from boxmunge.state import read_state

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


def redeploy_command(paths: BoxPaths, project: str) -> str:
    """`prod-deploy ...` that deploys `project`'s installed release again."""
    if not (paths.project_dir(project) / "repo").exists():
        return f"prod-deploy {project} --redeploy"
    installed = read_state(paths.project_deploy_state(project)).get("current_ref")
    if not isinstance(installed, str) or not installed:
        return f"prod-deploy {project}"  # never deployed: its ref is what there is
    return f"prod-deploy {project} --ref {installed}"


def redeploy_either(project: str) -> str:
    """Both forms, for a message written where the project's kind is not
    known (no BoxPaths at hand)."""
    return (f"prod-deploy {project} --redeploy (a git project: prod-deploy {project} "
            f"--ref <its deployed commit>)")
