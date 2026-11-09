# SPDX-License-Identifier: Apache-2.0
"""Probation promotion — clear probation on user interaction.

When a user or agent runs deploy, rollback, backup, or restore during
the probation window, the upgrade is immediately promoted. This prevents
user-caused issues from triggering an automatic rollback to an older
(potentially insecure) version.

Only operator entry points may call this. A timer-driven backup (backup-all,
container-update's pre-update backup) must not: it would cut probation short
and open container-update's probation gate on a barely-tested platform.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from boxmunge.log import log_operation, log_warning
from boxmunge.upgrade_state import UpgradeStateUnreadable, clear_probation, read_probation

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


def clear_probation_if_active(paths: BoxPaths, command: str) -> None:
    """If in probation, clear the probation marker so the upgrade is promoted.

    Note: the old venv is NOT removed here — this code runs as the deploy
    user which doesn't have permission to rmtree root-owned venv dirs.
    The next health-timer fire (root context) sees the orphan venv and
    cleans it up via boxmunge-upgrade check-probation.

    A marker this user cannot read is the one case that warns and carries
    on: ending probation early is a courtesy to the operator, and the health
    timer still ends it at expiry. Aborting the operator's deploy, backup or
    restore over it would only block the work (#107).
    """
    try:
        prob = read_probation(paths)
    except UpgradeStateUnreadable as e:
        log_warning(
            "upgrade",
            f"Cannot end the upgrade probation early: {e}. The {command} carries on; "
            "until the probation expires, a failing health check can still roll the "
            f"platform back. To let {command} end it, run as root: "
            f"sudo chown root:deploy {paths.probation} && sudo chmod 660 {paths.probation}",
            paths,
        )
        return
    if prob is None:
        return

    clear_probation(paths)
    log_operation(
        "upgrade",
        f"Probation ended early: user interaction ({command})",
        paths,
    )
