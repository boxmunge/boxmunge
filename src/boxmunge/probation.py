# SPDX-License-Identifier: Apache-2.0
"""Probation promotion — clear probation on user interaction.

When a user or agent runs deploy, rollback, backup, or restore during
the probation window, the upgrade is immediately promoted. This prevents
user-caused issues from triggering an automatic rollback to an older
(potentially insecure) version.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from boxmunge.log import log_operation
from boxmunge.upgrade_state import read_probation, clear_probation

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


def clear_probation_if_active(paths: BoxPaths, command: str) -> None:
    """If in probation, clear the probation marker so the upgrade is promoted.

    Note: the old venv is NOT removed here — this code runs as the deploy
    user which doesn't have permission to rmtree root-owned venv dirs.
    The next health-timer fire (root context) sees the orphan venv and
    cleans it up via boxmunge-upgrade check-probation.
    """
    prob = read_probation(paths)
    if prob is None:
        return

    clear_probation(paths)
    log_operation(
        "upgrade",
        f"Probation ended early: user interaction ({command})",
        paths,
    )
