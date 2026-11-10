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


def _is_git(paths: BoxPaths, project: str) -> bool:
    return (paths.project_dir(project) / "repo").exists()


def redeploy_command(paths: BoxPaths, project: str) -> str:
    """`prod-deploy ...` that deploys `project`'s installed release again."""
    if not _is_git(paths, project):
        return f"prod-deploy {project} --redeploy"
    installed = read_state(paths.project_deploy_state(project)).get("current_ref")
    if not isinstance(installed, str) or not installed:
        return f"prod-deploy {project}"  # never deployed: its ref is what there is
    return f"prod-deploy {project} --ref {installed}"


def deploy_ways(paths: BoxPaths, project: str) -> str:
    """Both deploys that start `project` from where it stands, quoted: its
    installed release again, or a new one (an upload's bundle, or the
    newest commit on a git project's ref)."""
    again = redeploy_command(paths, project)
    new = f"prod-deploy {project}"
    if again == new:
        return f"`{new}`"
    what = "for the newest commit on its ref" if _is_git(paths, project) else "after an upload"
    return f"`{again}`, or `{new}` {what}"


def deploy_from_pause(paths: BoxPaths, project: str) -> str:
    """The redeploy of a paused project, quoted: a deploy is refused while
    it is paused until `resume --no-start` hands the pause to it."""
    return (f"`boxmunge resume {project} --no-start`, then "
            f"`boxmunge {redeploy_command(paths, project)}`")


def redeploy_either(project: str) -> str:
    """Both forms, for a message written where the project's kind is not
    known (no BoxPaths at hand)."""
    return (f"prod-deploy {project} --redeploy (a git project: prod-deploy {project} "
            f"--ref <its deployed commit>)")
