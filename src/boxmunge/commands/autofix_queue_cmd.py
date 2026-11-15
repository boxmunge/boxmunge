# SPDX-License-Identifier: Apache-2.0
"""`boxmunge security autofix-queue`, and how the scans hand their urgent
patches to it.

The urgent autofix queue (commands.autofix_urgent) runs in its own oneshot
unit, boxmunge-autofix.service (root, 6h timeout, no timer): a patch can
take long, and inside the KEV watch (1h) or the nightly maintenance unit it
would hold up the fleet lock and the container update. A caller running as
root (the fleet scan, the KEV watch, a supervisor's single-project scan)
queues its patches, then starts the unit without waiting; systemd never
runs two at once, and starting it while it runs is a no-op, so the command
goes round the queue again while it holds projects this run has not tried
yet: each project at most once per run (one left queued, busy or failed,
waits for the next start). A
caller that is not root (a deploy-shell `security scan <project>`) cannot
start units, and runs its own project's patch itself.
"""
from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Collection
from datetime import datetime, timezone

from boxmunge.commands.autofix_urgent import run_urgent_queue
from boxmunge.cve.autofix_record import journaled_projects, queued_projects
from boxmunge.cve.autofix_run import AutofixOutcome
from boxmunge.log import log_error, log_operation
from boxmunge.paths import BoxPaths, InvalidProjectName
from boxmunge.project_alerts import alert_once
from boxmunge.state import StateError

AUTOFIX_UNIT = "boxmunge-autofix.service"
_COMPONENT = "autofix"


def _is_root() -> bool:
    return os.geteuid() == 0


def _pending(paths: BoxPaths) -> set[str]:
    """The names with a queued patch or a journal; a queue that cannot be
    listed counts as pending, so the unit runs and reports it."""
    try:
        return set(queued_projects(paths)) | set(journaled_projects(paths))
    except StateError:
        return {"(unlistable)"}


def start_autofix_unit(paths: BoxPaths) -> None:
    """Start the autofix unit when anything is queued; never waits. A start
    that fails is logged and printed, and alerted at most once a day for
    each project waiting on it: the queue stays, and the next caller starts
    it again."""
    pending = _pending(paths)
    if not pending:
        return
    try:
        result = subprocess.run(["systemctl", "start", "--no-block", AUTOFIX_UNIT],
                                capture_output=True, text=True, check=False, timeout=30)
        failure = None if result.returncode == 0 else (
            f"exit {result.returncode}: {(result.stderr or '').strip()}")
    except (OSError, subprocess.TimeoutExpired) as e:
        failure = f"{type(e).__name__}: {e}"
    if failure is None:
        log_operation(_COMPONENT, f"started {AUTOFIX_UNIT} for the queued patches", paths)
        return
    message = (f"could not start {AUTOFIX_UNIT} ({failure}); the queued patches wait for "
               f"the next scan or KEV watch tick to start it")
    log_error(_COMPONENT, message, paths)
    print(f"ERROR: {message}", file=sys.stderr)
    for project in sorted(pending):
        _unit_alert(paths, project, failure)


def _unit_alert(paths: BoxPaths, project: str, failure: str) -> None:
    try:
        alert_once(paths, project, "autofix-unit",
                   {"day": datetime.now(timezone.utc).date().isoformat()},
                   title=f"[boxmunge:{project}] Urgent autofix could not start", priority=1,
                   component=_COMPONENT, message="\n".join([
                       f"{AUTOFIX_UNIT} could not be started ({failure}), so the patch",
                       f"queued for {project} has not run. It stays queued, and the next scan",
                       "or KEV watch tick starts the unit again; as supervisor:",
                       f"sudo systemctl start {AUTOFIX_UNIT}. Alerted once a day while it lasts.",
                   ]))
    except InvalidProjectName:   # a name in the queue that is not a project's: logged above
        return


def after_scan(paths: BoxPaths, *, only: Collection[str] | None = None) -> list[AutofixOutcome]:
    """Hand the queued patches on: as root, start the unit and return no
    outcomes; otherwise run them here (``only`` those projects)."""
    if _is_root():
        start_autofix_unit(paths)
        return []
    return run_urgent_queue(paths, datetime.now(timezone.utc), only=only)


def cmd_autofix_queue(args: list[str], paths: BoxPaths) -> int:
    """boxmunge security autofix-queue: run the queue, each project at most
    once. Exit 2 when a patch failed (its fallback applied), 1 when it
    cannot run."""
    if args:
        print("ERROR: security autofix-queue takes no arguments", file=sys.stderr)
        return 2
    if not _is_root():
        print(f"ERROR: security autofix-queue runs as root ({AUTOFIX_UNIT} runs it)",
              file=sys.stderr)
        return 1
    attempted: set[str] = set()
    outcomes: list[AutofixOutcome] = []
    while pending := _pending(paths) - attempted:
        outcomes += run_urgent_queue(paths, datetime.now(timezone.utc), only=pending)
        attempted |= pending
    print(f"Autofix queue: {len(outcomes)} patch(es) run, "
          f"{sum(not o.ok for o in outcomes)} failed.")
    return 2 if any(not o.ok for o in outcomes) else 0
