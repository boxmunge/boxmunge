# SPDX-License-Identifier: Apache-2.0
"""prod-deploy of a bundle project with no new bundle in the inbox.

A stage takes the bundle it stages out of the inbox, as a deploy does. A
prod-deploy run after it used to fall back to redeploying the release
already installed, and said so in one line that read like success. Now it
is refused, naming what the operator most likely meant: promote the staged
release, upload the bundle again, or redeploy the installed release on
purpose (--redeploy).
"""
from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from boxmunge.data_dirs import ReleaseStateError
from boxmunge.release import live_ref
from boxmunge.staged_release import SlotError, load_slot

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


def redeploy_problem(project: str, *, is_new: bool, git: bool, ref: str | None) -> str | None:
    """Why `prod-deploy <project> --redeploy` cannot run as asked, or None."""
    if is_new:
        return (f"--redeploy deploys the release already installed, and '{project}' has "
                f"none yet. Upload its first bundle, then run 'prod-deploy {project}'.")
    if git:
        return (f"'{project}' is a git project: prod-deploy deploys the commit its ref "
                f"names and has no inbox bundle to miss. Run 'prod-deploy {project}' "
                f"(add --ref <ref> for another commit).")
    if ref:
        return (f"--redeploy deploys the installed release again, and --ref names an inbox "
                f"bundle to deploy instead. Run 'prod-deploy {project} --ref {ref}' or "
                f"'prod-deploy {project} --redeploy'.")
    return None


def _staged_hint(project: str, paths: BoxPaths) -> str | None:
    try:
        slot = load_slot(paths, project)
    except SlotError as e:
        return f"The staged release's record cannot be read: {e}."
    if slot is None or slot.state != "ready":
        return None
    return (f"{slot.ref} is staged (a stage takes its bundle out of the inbox): run "
            f"'promote {project}' to put it live.")


def refuse_no_new_bundle(project: str, paths: BoxPaths) -> int:
    """Refuse a prod-deploy that has no new bundle to deploy. Returns 1."""
    lines = [f"ERROR: No new bundle for '{project}' in the inbox, so prod-deploy has "
             f"nothing new to deploy. Nothing was changed."]
    hint = _staged_hint(project, paths)
    if hint:
        lines.append(f"  {hint}")
    lines.append(f"  To deploy a new release, upload its bundle and run "
                 f"'prod-deploy {project}' again.")
    try:
        installed = live_ref(paths, project)
    except ReleaseStateError as e:
        lines.append(f"  The installed release cannot be read either: {e}")
    else:
        lines.append(f"  To deploy the installed release ({installed}) again, rebuilding its "
                     f"images, run 'prod-deploy {project} --redeploy'.")
    print("\n".join(lines), file=sys.stderr)
    return 1
