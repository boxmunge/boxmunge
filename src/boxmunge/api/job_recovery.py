# SPDX-License-Identifier: Apache-2.0
"""What to do with a job found unfinished, and how the operator recovers.

A job whose worker is gone is marked lost and never run again: the action may
have done part of its work, and running it twice is worse than telling the
operator. The alert names the way out for that action; for an open install
transaction that is the transaction's own options, not a generic "check status".
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Callable

from boxmunge.api.worker_identity import WorkerIdentity
from boxmunge.paths import BoxPaths
from boxmunge.release_txn import load_txn, options_text
from boxmunge.state import StateError


class Recovery(Enum):
    START = "start"                      # queued: a worker may claim it
    LEAVE = "leave"                      # running and its worker is alive
    LOST = "lost"                        # running, worker gone: mark worker_lost
    COMPLETE_FINISH = "complete_finish"  # terminal but still in queue/: finish the move


# {project} is substituted. Actions that may open an install transaction get its
# options instead (recovery_advice), so these cover the no-transaction case.
_ADVICE = {
    "stage": "run 'boxmunge stage {project}' again, or 'boxmunge unstage {project}' to discard it",
    "unstage": "run 'boxmunge unstage {project}' again",
    "pause": "run 'boxmunge pause {project}' again",
    "resume": "run 'boxmunge resume {project}' again",
    "backup": "run 'boxmunge backup {project}' again",
    "restore": "run 'boxmunge restore {project}' again",
    "deploy": "run 'boxmunge status {project}' to see what state it is in",
    "promote": "run 'boxmunge status {project}' to see what state it is in",
    "rollback": "run 'boxmunge status {project}' to see what state it is in",
    "recover": "run 'boxmunge recover {project}' again",
    "abandon_install": "run 'boxmunge prod-deploy {project} --abandon' again",
}


def classify(record: dict[str, Any], *, alive: Callable[[WorkerIdentity], bool]) -> Recovery:
    state = record["state"]
    if state == "queued":
        return Recovery.START
    if state == "running":
        worker = record["worker"]
        if worker is None:
            raise StateError(
                f"Job {record['id']} is running but records no worker. The job record is corrupt."
            )
        return Recovery.LEAVE if alive(WorkerIdentity.from_record(worker)) else Recovery.LOST
    if state in ("succeeded", "failed"):
        return Recovery.COMPLETE_FINISH
    raise StateError(f"Job {record['id']} has unknown state {state!r}. The job record is corrupt.")


def recovery_advice(paths: BoxPaths, action: str, project: str | None) -> str:
    if project is None:
        raise StateError(f"Cannot advise recovery of {action!r} without a project.")
    txn = load_txn(paths, project)
    if txn is not None:
        return f"an install of {txn.ref} is open: {options_text(project, txn)}"
    try:
        return _ADVICE[action].format(project=project)
    except KeyError:
        raise StateError(f"No recovery advice is defined for action {action!r}.") from None


def lost_message(record: dict[str, Any]) -> str:
    return (f"The worker running {record['action']} was lost (the box restarted or the "
            f"worker was killed). The job was not run again, and may have done part of "
            f"its work.")
