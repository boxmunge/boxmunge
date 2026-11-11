# SPDX-License-Identifier: Apache-2.0
"""The TUI's project actions, run with their output captured so a failure
can be shown as the command said it (no Textual here, so it is testable)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from boxmunge.commands.deploy_no_bundle import REFUSAL
from boxmunge.paths import BoxPaths

_SHOWN_LINES = 8

# What each action does, shown in the confirmation modal before it runs.
PROMPTS: dict[str, str] = {
    "deploy": "Deploy {project}: install the newest uploaded bundle and restart "
              "the project on it.",
    "redeploy": "Redeploy {project}: re-run the installed release, recreating "
                "its containers.",
    "backup": "Back up {project}: take a data snapshot now.",
    "rollback": "Roll back {project}: replace the running release with the "
                "previous one and, if it has one, restore the data snapshot "
                "paired with it, discarding data written since.",
}


@dataclass(frozen=True)
class Outcome:
    ok: bool
    message: str
    offer_redeploy: bool = False  # a deploy refused for want of a new bundle


def _handlers(project: str, paths: BoxPaths) -> dict[str, Callable[[], int]]:
    from boxmunge.commands.backup_cmd import run_backup
    from boxmunge.commands.deploy import run_deploy
    from boxmunge.commands.rollback import run_rollback
    return {
        "deploy": lambda: run_deploy(project, paths),
        "redeploy": lambda: run_deploy(project, paths, redeploy=True),
        "backup": lambda: run_backup(project, paths),
        "rollback": lambda: run_rollback(project, paths, yes=True),
    }


def run_action(action: str, project: str, paths: BoxPaths) -> Outcome:
    """Run `action` for `project`. A failure's message is the command's
    output from its first ERROR line (its last lines if it printed none)."""
    from boxmunge.mcp_tools import capture_tool_call
    handler = _handlers(project, paths).get(action)
    if handler is None:
        raise ValueError(f"unknown TUI action {action!r}")
    result = capture_tool_call(handler)
    if result["success"]:
        return Outcome(True, f"{action} completed for {project}")
    lines = result["messages"]
    first = next((i for i, line in enumerate(lines) if line.startswith("ERROR")), None)
    shown = lines[first:first + _SHOWN_LINES] if first is not None else lines[-_SHOWN_LINES:]
    refused = action == "deploy" and any(line.startswith(REFUSAL) for line in lines)
    text = "\n".join([f"{action} failed for {project}", *shown])
    if refused:
        text += "\nPress D to redeploy the installed release."
    return Outcome(False, text, offer_redeploy=refused)
