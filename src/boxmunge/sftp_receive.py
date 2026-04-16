# SPDX-License-Identifier: Apache-2.0
"""SFTP subsystem handler — routes deploy user uploads through the inbox.

Replaces the default sftp-server subsystem. For the deploy user, uploads
land in the deploy user's home directory (sftp-server default behaviour)
and are then post-processed into the inbox by the reception handler.

For all other users, it falls through to the real sftp-server.

Configured in sshd_config:
  Subsystem sftp /opt/boxmunge/bin/boxmunge-sftp
"""

from __future__ import annotations

import getpass
import os
import subprocess
import sys
from pathlib import Path

REAL_SFTP_SERVER = "/usr/lib/openssh/sftp-server"
DEPLOY_USER = "deploy"


def _snapshot_home_files(home: Path) -> set[str]:
    """Snapshot filenames in the deploy user's home directory."""
    if not home.exists():
        return set()
    return {f.name for f in home.iterdir() if f.is_file()}


def main() -> None:
    """SFTP subsystem entry point."""
    try:
        current_user = getpass.getuser()
    except Exception:
        current_user = os.environ.get("USER", "")

    # Non-deploy users get the real sftp-server unmodified
    if current_user != DEPLOY_USER:
        os.execv(REAL_SFTP_SERVER, [REAL_SFTP_SERVER] + sys.argv[1:])
        return  # unreachable after execv

    deploy_home = Path.home()

    # Snapshot files before sftp-server runs
    before = _snapshot_home_files(deploy_home)

    # Run the real sftp-server — it inherits stdin/stdout for the SFTP protocol.
    # We let it use default home dir (not -d inbox) because many clients
    # (including OpenSSH scp in SFTP mode) expect to write to $HOME.
    result = subprocess.run(
        [REAL_SFTP_SERVER] + sys.argv[1:],
        check=False,
    )

    # Post-process: detect new files and route through reception
    after = _snapshot_home_files(deploy_home)
    new_files = sorted(after - before)

    if not new_files:
        sys.exit(result.returncode)

    try:
        from boxmunge.paths import BoxPaths
        from boxmunge.reception import receive_bundle

        paths = BoxPaths()
        for fname in new_files:
            fpath = deploy_home / fname
            if not fpath.exists():
                continue
            try:
                dest = receive_bundle(fpath, paths)
                print(f"Received: {dest.name}", file=sys.stderr)
            except ValueError as e:
                print(f"Upload rejected ({fname}): {e}", file=sys.stderr)
                fpath.unlink(missing_ok=True)
    except Exception as e:
        print(f"boxmunge-sftp post-processing error: {e}", file=sys.stderr)

    sys.exit(result.returncode)
