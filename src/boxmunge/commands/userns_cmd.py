# SPDX-License-Identifier: Apache-2.0
"""boxmunge-server userns {check,migrate,rollback,commit} — root only.

Run through the upgrade shim (`sudo /opt/boxmunge/bin/boxmunge-upgrade
userns-migrate [--check] | userns-rollback | userns-commit`), which holds
upgrade.lock (and the legacy lock) and refuses a migration during a
probation. migrate, rollback and commit refuse to run unless they inherited
both of the shim's locks, held, so they cannot race an upgrade.
Not in the deploy shell's command list.
"""
from __future__ import annotations

import fcntl
import os
import sys
from pathlib import Path

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
from boxmunge.userns.preflight import PreflightRefused, Report, preflight
from boxmunge.userns.shift import ShiftRefused
from boxmunge.userns.switch import MigrationError, host_ids
from boxmunge.userns.volumes import VolumeError

_SUBCOMMANDS = ("check", "migrate", "rollback", "commit")
_SHIM = "sudo /opt/boxmunge/bin/boxmunge-upgrade"
# scripts/boxmunge-upgrade.d/state.sh, acquire_lock: the root-only lock on
# descriptor 9, the legacy one older shims take on 8.
SHIM_LOCK_FDS = (9, 8)


def _held_on(fd: int, path: Path) -> bool:
    """Is `fd` the lock file at `path`, and is that lock held?"""
    try:
        held, name = os.fstat(fd), os.lstat(path)
    except OSError:
        return False
    if (held.st_dev, held.st_ino) != (name.st_dev, name.st_ino):
        return False
    probe = open_regular_nofollow(path, os.O_RDONLY)
    try:
        fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return True  # held, by the descriptor the shim passed down
    finally:
        os.close(probe)
    return False


def require_upgrade_lock_held(paths: BoxPaths, fds: tuple[int, int] = SHIM_LOCK_FDS) -> None:
    """Refuse unless the shim took both upgrade locks on these descriptors
    and handed them down, so no upgrade can run beside the migration."""
    locks = (paths.upgrade_lock, paths.legacy_upgrade_lock)
    if not all(_held_on(fd, path) for fd, path in zip(fds, locks)):
        raise SystemExit(f"ERROR: run this through the shim: {_SHIM} userns-<subcommand>")


def _journal_verdict(journal) -> str | None:
    if journal is None or journal.phase == "rolled-back":
        return None
    if journal.direction == FORWARD and "commit-before" in journal.items:
        return f"a userns-commit stopped part-way; finish it: {_SHIM} userns-commit"
    if journal.direction == FORWARD and journal.phase in ("applied", "committed"):
        return f"already {journal.phase} (offset {journal.offset})"
    if journal.direction == FORWARD:
        return (f"a userns migration stopped at {journal.phase}; resume it: {_SHIM} "
                f"userns-migrate, or undo it: {_SHIM} userns-rollback")
    return f"a userns rollback stopped at {journal.phase}; finish it: {_SHIM} userns-rollback"


def run_check(paths: BoxPaths) -> int:
    """One read-only pass that always ends with a verdict and exits 0: what
    stops it (the journal, the subid files, the daemon) is a refusal row."""
    try:
        verdict = _journal_verdict(load_journal(paths))
        if verdict is not None:
            print(f"VERDICT: {verdict}")
            return 0
        s = uo.allocate_offset(uo.ETC, host_ids())
        report = preflight(paths, take_inventory(paths), direction=FORWARD, offset=s,
                           images_dir=IMAGES_DIR)
        print(f"remap offset: {s}")
    except (JournalError, uo.RemapError, DockerError, OSError, ValueError) as e:
        report = Report(refusals=[f"the check could not run to the end: {e}"])
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
        j = rollback(paths, daemon=SystemdDaemon(), timers=SystemdTimers())
        failed = sorted(k for k, v in j.items.items()
                        if k.startswith(("rb-project:", "abort:")) and v.startswith("failed"))
        print("Rolled back to the prior store." + (f" Not healthy, on the maintenance page: "
                                                   f"{failed}" if failed else ""))
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
