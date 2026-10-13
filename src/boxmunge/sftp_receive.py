# SPDX-License-Identifier: Apache-2.0
"""SFTP subsystem gate (sshd: `Subsystem sftp /opt/boxmunge/bin/boxmunge-sftp`).

The deploy user gets no SFTP. sftp-server cannot be confined to the inbox
without chrooting every deploy session, and unconfined it hands deploy read
and write access to everything deploy can reach, outside the restricted
shell's allowlist (audit A-04). Bundles are uploaded with the legacy scp
protocol instead (`scp -O`), which the restricted shell receives into the
inbox via `scp -t`.

Every other user (supervisor) gets the real sftp-server unchanged.

For deploy, sshd normally runs this through the login shell, which refuses
SFTP itself; this check covers any path that reaches the wrapper directly.
"""

from __future__ import annotations

import os
import pwd
import sys

REAL_SFTP_SERVER = "/usr/lib/openssh/sftp-server"
DEPLOY_USER = "deploy"
SFTP_REFUSAL = (
    "ERROR: SFTP is disabled for the deploy user. Upload bundles with the legacy "
    "scp protocol: scp -O -P <port> bundle.tar.gz deploy@<host>:"
)


def main() -> None:
    """SFTP subsystem entry point."""
    # The uid, not $USER/$LOGNAME, which a client may be able to influence.
    user = pwd.getpwuid(os.getuid()).pw_name
    if user == DEPLOY_USER:
        print(SFTP_REFUSAL, file=sys.stderr, flush=True)
        sys.exit(1)
    os.execv(REAL_SFTP_SERVER, [REAL_SFTP_SERVER] + sys.argv[1:])
