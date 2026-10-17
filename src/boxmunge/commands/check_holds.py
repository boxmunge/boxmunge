# SPDX-License-Identifier: Apache-2.0
"""Why the health tick leaves production alone (after a pause or
quarantine, which _check_one handles first): staging's data copy stopped
it, the staged slot cannot say whether it did, or an install is open.

In each case smoke would test a state boxmunge put production in on
purpose, and a critical result would apply `compose down` to it.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from boxmunge.log import log_operation
from boxmunge.production_stopped import ProductionDownError, start_again
from boxmunge.project_alerts import alert_once, clear_alert
from boxmunge.release_txn import open_install_reason
from boxmunge.staged_release import SlotError, load_slot

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths

SLOT_ALERT = "staged-slot"


def tick_hold(name: str, paths: BoxPaths, read_only: bool) -> int | None:
    """None: run the check. Otherwise the status to report; no smoke runs
    and no critical action is applied. Caller holds the project lock."""
    try:
        meta = load_slot(paths, name)
    except SlotError as e:
        return _unreadable_slot(name, paths, e, read_only)
    if not read_only:
        clear_alert(paths, name, SLOT_ALERT)
    if meta is not None and meta.production_stopped is not None:
        status = _stopped_for_copy(name, paths, read_only)
        if status is not None:
            return status
    return _install_open(name, paths)


def _stopped_for_copy(name: str, paths: BoxPaths, read_only: bool) -> int | None:
    # staging's data copy stopped production and did not start it again (it
    # crashed: this tick holds the lock, so no copy is running): start it
    # now. The stop was deliberate, so the critical action (compose down) is
    # never applied while the marker stands.
    if read_only:
        print(f"{name}: CRITICAL (production stopped for staging's data copy)")
        return 2
    try:
        start_again(paths, name, component="check-all", alert=True)
    except ProductionDownError as e:
        print(f"{name}: CRITICAL ({e})")
        return 2
    return None


def _unreadable_slot(name: str, paths: BoxPaths, error: SlotError, read_only: bool) -> int:
    # start_again cannot name what a copy stopped, and would page on every
    # tick; the alert goes once per error instead.
    message = (f"{name}'s staged slot cannot be read ({error}), so whether staging's data "
               f"copy stopped production cannot be told: the health check runs no smoke "
               f"and takes no critical action. If production is down, run `boxmunge "
               f"recover {name}`; then `unstage {name}`")
    print(f"{name}: CRITICAL ({message})")
    if not read_only:
        alert_once(paths, name, SLOT_ALERT, {"error": str(error)},
                   title=f"{name}: staged slot unreadable", message=message,
                   component="check-all", priority=1)
    return 2


def _install_open(name: str, paths: BoxPaths) -> int | None:
    # An install left open may have refreshed boxmunge-scripts in place, so
    # smoke would run the new release's scripts against the old containers.
    reason = open_install_reason(paths, name)
    if reason is None:
        return None
    print(f"{name}: WARNING (install open: {reason})")
    log_operation("check-all", f"skipped: install open ({reason})", paths, project=name)
    return 1
