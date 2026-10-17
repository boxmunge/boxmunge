# SPDX-License-Identifier: Apache-2.0
"""boxmunge-server userns {check,migrate,rollback,commit} — root only.

Run through the upgrade shim (`sudo /opt/boxmunge/bin/boxmunge-upgrade
userns-migrate [--check] | userns-rollback | userns-commit`), which holds
upgrade.lock and refuses a migration during a probation. migrate, rollback
and commit refuse to run unless they inherited the shim's lock (its
descriptor 9, on upgrade.lock, locked), so they cannot race an upgrade.
Not in the deploy shell's command list.
"""
from __future__ import annotations

import fcntl
import os
import sys

from boxmunge.commands.argv import parse_args, usage_error
from boxmunge.docker_run import DockerError
from boxmunge.fileutil import LockError
from boxmunge.fs_nofollow import open_regular_nofollow
from boxmunge.paths import BoxPaths
from boxmunge.userns import offset as uo
from boxmunge.userns.daemon_config import DaemonConfigError
from boxmunge.userns.images import IMAGES_DIR, ImageError
from boxmunge.userns.inventory import take_inventory
from boxmunge.userns.journal import FORWARD, JournalError, load_journal
from boxmunge.userns.preflight import PreflightRefused, preflight
from boxmunge.userns.shift import ShiftRefused
from boxmunge.userns.switch import MigrationError, host_ids
from boxmunge.userns.volumes import VolumeError

_SUBCOMMANDS = ("check", "migrate", "rollback", "commit")
_SHIM = "sudo /opt/boxmunge/bin/boxmunge-upgrade"
SHIM_LOCK_FD = 9  # scripts/boxmunge-upgrade.d/state.sh, acquire_lock


def require_upgrade_lock_held(paths: BoxPaths, fd: int = SHIM_LOCK_FD) -> None:
    """Refuse unless `fd` is upgrade.lock and the lock is held: the shim
    took it on that descriptor and handed it down."""
    shim = f"ERROR: run this through the shim: {_SHIM} userns-<subcommand>"
    try:
        held, name = os.fstat(fd), os.lstat(paths.upgrade_lock)
    except OSError:
        raise SystemExit(shim) from None
    if (held.st_dev, held.st_ino) != (name.st_dev, name.st_ino):
        raise SystemExit(shim)
    probe = open_regular_nofollow(paths.upgrade_lock, os.O_RDONLY)
    try:
        fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return  # held, by the descriptor the shim passed down
    finally:
        os.close(probe)
    raise SystemExit(shim)


def run_check(paths: BoxPaths) -> int:
    journal = load_journal(paths)
    if journal is not None and journal.phase != "rolled-back":
        if journal.direction == FORWARD and journal.phase in ("applied", "committed"):
            print(f"VERDICT: already {journal.phase} (offset {journal.offset})")
        else:
            print(f"VERDICT: a userns {journal.direction} is in progress (phase "
                  f"{journal.phase}); resume it with the same command, or "
                  f"{_SHIM} userns-rollback")
        return 0
    s = uo.allocate_offset(uo.ETC, host_ids())
    report = preflight(paths, take_inventory(paths), direction=FORWARD, offset=s,
                       images_dir=IMAGES_DIR)
    print(f"remap offset: {s}")
    print(report.text())
    return 0  # a report, never a failed upgrade


def _run(paths: BoxPaths, sub: str) -> None:
    from boxmunge.userns.commit import commit
    from boxmunge.userns.daemon_ctl import SystemdDaemon, SystemdTimers
    from boxmunge.userns.engine import migrate
    from boxmunge.userns.rollback import rollback
    if sub == "migrate":
        j = migrate(paths, daemon=SystemdDaemon(), timers=SystemdTimers())
        failed = sorted(k for k, v in j.items.items()
                        if k.startswith("project:") and v.startswith("failed"))
        print("Migration applied." + (f" Not healthy, on the maintenance page: {failed}"
                                      if failed else ""))
    elif sub == "rollback":
        rollback(paths, daemon=SystemdDaemon(), timers=SystemdTimers())
        print("Rolled back to the prior store.")
    else:
        commit(paths)
        print("Committed: the old root is deleted; rollback is no longer offered.")


def cmd_userns(args: list[str]) -> None:
    sub = parse_args("userns", args, min_positional=1, max_positional=1).positional[0]
    if sub not in _SUBCOMMANDS:
        usage_error("userns", f"unknown subcommand {sub!r}")
    if os.geteuid() != 0:
        print(f"ERROR: userns {sub} runs as root, through: {_SHIM} userns-...", file=sys.stderr)
        sys.exit(1)
    paths = BoxPaths()
    try:
        if sub == "check":
            sys.exit(run_check(paths))
        require_upgrade_lock_held(paths)
        from boxmunge.userns.daemon_ctl import ControlError
        try:
            _run(paths, sub)
        except ControlError as e:
            raise MigrationError(str(e)) from e
    except PreflightRefused as e:
        print(e.report.text(), file=sys.stderr)
        sys.exit(1)
    except (MigrationError, JournalError, LockError, DockerError, ShiftRefused, VolumeError,
            ImageError, DaemonConfigError, uo.RemapError, OSError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
