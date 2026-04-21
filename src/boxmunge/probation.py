# SPDX-License-Identifier: Apache-2.0
"""Probation promotion — clear probation on user interaction.

When a user or agent runs deploy, rollback, backup, or restore during
the probation window, the upgrade is immediately promoted. This prevents
user-caused issues from triggering an automatic rollback to an older
(potentially insecure) version.
"""
from __future__ import annotations

import shutil
from typing import TYPE_CHECKING

from boxmunge.log import log_operation
from boxmunge.upgrade_state import read_probation, clear_probation

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


def clear_probation_if_active(paths: BoxPaths, command: str) -> None:
    """If in probation, promote immediately and clean up old venv."""
    prob = read_probation(paths)
    if prob is None:
        return

    previous_slot = prob.get("previous_slot")
    if previous_slot:
        old_venv = paths.root / f"env-{previous_slot}"
        if old_venv.exists():
            shutil.rmtree(old_venv)

    clear_probation(paths)
    log_operation("upgrade", f"Probation ended early: user interaction ({command})", paths)
