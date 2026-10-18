# SPDX-License-Identifier: Apache-2.0
"""The migration's steps around the downtime: the backups before it, the
disk check just before it, and the checks and report once the box runs.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from boxmunge.backup import BackupKind
from boxmunge.notify import notify
from boxmunge.paths import BoxPaths
from boxmunge.pause import is_paused
from boxmunge.userns.inventory import Inventory
from boxmunge.userns.journal import Journal
from boxmunge.userns.preflight_checks import Report, disk
from boxmunge.userns.switch import MigrationError

COMPONENT = "userns-migrate"
CROWDSEC_LOG = Path("/var/log/crowdsec.log")
_CADDY = "boxmunge-caddy"
_CROWDSEC_WAIT = 60


def _backups(paths: BoxPaths, inv: Inventory) -> None:
    from boxmunge.commands.backup_cmd import backup_locked, run_backup_sync
    for p in inv.projects:
        if not paths.project_manifest(p).exists():
            continue
        if is_paused(p, paths):
            print(f"  {p} is paused: no pre-migration backup (its containers are stopped); "
                  f"its data is carried like any other")
            continue
        if backup_locked(p, paths, kind=BackupKind.PREMIGRATE) != 0:
            raise MigrationError(f"the pre-migration backup of {p} failed; nothing was stopped")
    if run_backup_sync(paths) != 0:
        raise MigrationError("backup-sync failed; nothing was stopped")


def disk_before_downtime(inv: Inventory, images_dir: Path) -> None:
    """Free space again, once the tarballs and backups are written: the
    load and a rollback's own tarballs still need room. Refused here, the
    box has not stopped."""
    r = Report()
    disk(inv, r, images_dir)
    if r.refusals:
        raise MigrationError(f"{r.refusals[0]}; free some space, then run userns-migrate "
                             f"again (nothing was stopped)")


def crowdsec_tails_caddy() -> str | None:
    """Restart CrowdSec and wait until it tails the recreated Caddy, as
    install.sh's bootstrap/crowdsec-acquis.sh verifies. Its docker source
    lost the old daemon's container. Returns why not, or None (also when
    CrowdSec is not installed)."""
    if shutil.which("cscli") is None:
        return None
    offset = CROWDSEC_LOG.stat().st_size if CROWDSEC_LOG.exists() else 0
    result = subprocess.run(["systemctl", "restart", "crowdsec"], capture_output=True,
                            text=True, check=False, timeout=120)
    if result.returncode != 0:
        return f"systemctl restart crowdsec failed: {result.stderr.strip()}"
    needle = f'start tail for container {_CADDY}"'.encode()
    deadline = time.monotonic() + _CROWDSEC_WAIT
    while time.monotonic() < deadline:
        try:
            with open(CROWDSEC_LOG, "rb") as f:
                f.seek(offset if os.fstat(f.fileno()).st_size >= offset else 0)  # rotated
                if needle in f.read():
                    return None
        except FileNotFoundError:
            pass  # not written yet since the restart
        time.sleep(1)
    return (f"CrowdSec is not reading {_CADDY}'s access log: {CROWDSEC_LOG} shows no "
            f"'start tail for container {_CADDY}' within {_CROWDSEC_WAIT}s of its restart")


def _final(paths: BoxPaths, j: Journal, results: dict[str, str]) -> None:
    from boxmunge.commands.check import run_check_all
    from boxmunge.commands.security_actions import cmd_security_scan
    from boxmunge.commands.self_test_cmd import run_self_test
    checks = {"cve-scan": cmd_security_scan([], paths),
              "check-all": run_check_all(paths, read_only=False),
              "self-test": run_self_test(paths)}
    lines = [f"{p}: {status}" for p, status in sorted(results.items())]
    lines += [f"{name}: exit {rc}" for name, rc in checks.items()]
    crowdsec = crowdsec_tails_caddy()
    if crowdsec:
        crowdsec = (f"{crowdsec}. Nothing bans attackers on the sites until it does: "
                    f"systemctl restart crowdsec, then read {CROWDSEC_LOG}")
        print(f"ERROR: {crowdsec}", file=sys.stderr)
        lines.append(f"ERROR: {crowdsec}")
    notify(paths, "userns migration applied",
           "\n".join(lines) + "\nSoak for 48 hours, then: sudo /opt/boxmunge/bin/boxmunge-upgrade "
           "userns-commit. To undo: sudo /opt/boxmunge/bin/boxmunge-upgrade userns-rollback",
           component=COMPONENT, priority=1)
