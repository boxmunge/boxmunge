# SPDX-License-Identifier: Apache-2.0
"""Health check: does upgrade-state/active-slot agree with env-active?

active-slot is deploy-writable; env-active is root's symlink to the live
venv. The upgrade shim refuses to guess which venv is live when they
disagree (outside a swap a crash interrupted, which it repairs), so every
upgrade and every check-probation stops on it. Those refusals go to the
operational log, and this check reports the disagreement itself, so a
planted active-slot is a visible problem rather than a quiet stall.

Warns, never errors: check-probation runs ``health``, and an exit of 2
during probation would roll the platform back.
"""
from __future__ import annotations

import os
from typing import TYPE_CHECKING

from boxmunge.commands.health_cmd import HealthCheck
from boxmunge.fs_nofollow import read_text_nofollow

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

NAME = "upgrade-slot"
_MARKERS = ("upgrade-inflight", "rollback-inflight")


def check_upgrade_slot(paths: BoxPaths) -> HealthCheck:
    link = paths.root / "env-active"
    try:
        target = os.readlink(link)
    except FileNotFoundError:
        return HealthCheck(NAME, "skip", f"no {link}: not an installed box")
    except OSError as e:
        return HealthCheck(NAME, "warn", f"cannot read {link}: {e}")
    live = {str(paths.root / f"env-{s}"): s for s in "ab"}.get(target)
    if live is None:
        return HealthCheck(NAME, "warn", f"{link} points at {target}, not env-a or env-b: "
                                         "the upgrade shim refuses to run until it is repaired")
    try:
        recorded = read_text_nofollow(paths.active_slot).strip()
    except FileNotFoundError:
        return HealthCheck(NAME, "ok", f"slot {live} is live")
    except (OSError, UnicodeDecodeError) as e:
        return HealthCheck(NAME, "warn", f"cannot read {paths.active_slot}: {e}")
    fix = f"put it back as supervisor: echo {live} | sudo tee {paths.active_slot}"
    if recorded not in ("a", "b"):
        return HealthCheck(NAME, "warn", f"{paths.active_slot} holds '{recorded[:20]}', not a or "
                                         f"b: every upgrade and check-probation refuses it; {fix}")
    if recorded != live and not any((paths.root / f"env-{s}" / m).exists()
                                    for s in "ab" for m in _MARKERS):
        return HealthCheck(NAME, "warn", (
            f"{paths.active_slot} says '{recorded}' but env-active points at env-{live}: "
            f"every upgrade and check-probation refuses to guess which venv is live. "
            f"env-active is root's and is the live slot; unless an upgrade is running, {fix}"))
    return HealthCheck(NAME, "ok", f"slot {live} is live")
