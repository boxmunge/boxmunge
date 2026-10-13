# SPDX-License-Identifier: Apache-2.0
"""Put the installer on the server and run it, showing progress."""

from __future__ import annotations

import re
import subprocess
import sys
from typing import Callable

from boxmunge_cli.server_setup.progress import parse_marker, render_progress_bar
from boxmunge_cli.server_setup.release import INSTALLER, VerifiedInstaller

# Build ssh argv from (remote command, needs_sudo); scp argv from (local, remote path).
SshBuilder = Callable[[str, bool], list[str]]
ScpBuilder = Callable[[str, str], list[str]]

_REMOTE_TMP = re.compile(r"/tmp/boxmunge-setup\.[A-Za-z0-9]+")


class InstallError(Exception):
    """Raised when the installer cannot be put on the server."""


def make_remote_workdir(ssh: SshBuilder) -> str:
    """Create a private temp dir on the server, owned by the login user."""
    result = subprocess.run(ssh("umask 077 && mktemp -d /tmp/boxmunge-setup.XXXXXXXX", False),
                            capture_output=True, text=True, check=False)
    workdir = result.stdout.strip()
    if result.returncode != 0 or not _REMOTE_TMP.fullmatch(workdir):
        raise InstallError(f"Could not create a temp dir on the server: "
                           f"{(result.stderr or result.stdout).strip()}")
    return workdir


def upload_verified_installer(ssh: SshBuilder, scp: ScpBuilder,
                              installer: VerifiedInstaller) -> tuple[str, str]:
    """Upload the installer; return (workdir, shell snippet that re-checks and runs it)."""
    workdir = make_remote_workdir(ssh)
    remote_path = f"{workdir}/{INSTALLER}"
    if subprocess.run(scp(str(installer.path), remote_path), check=False).returncode != 0:
        raise InstallError("Failed to upload the installer.")
    # Re-check the digest on the server so a corrupted or swapped upload never runs.
    return workdir, (f"cd {workdir} && printf '%s  %s\\n' {installer.sha256} {INSTALLER} "
                     f"| sha256sum -c --quiet - && bash {INSTALLER}")


def upload_local_bundle(ssh: SshBuilder, scp: ScpBuilder, bundle: str) -> tuple[str, str]:
    """Development path: upload an unverified local bundle; return (workdir, run snippet)."""
    print("WARNING: --local-bundle installs an unsigned, unverified local build. "
          "Use it only for development.", file=sys.stderr)
    workdir = make_remote_workdir(ssh)
    if subprocess.run(scp(bundle, f"{workdir}/release.tar.gz"), check=False).returncode != 0:
        raise InstallError("Failed to upload the local bundle.")
    return workdir, (f"cd {workdir} && mkdir release && "
                     f"tar xzf release.tar.gz -C release --strip-components=1 && "
                     f"bash release/install.sh")


def run_with_progress(argv: list[str]) -> int:
    """Run the install over ssh, rendering progress markers; dump the log on failure."""
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    log_buffer: list[str] = []
    last_bar = ""
    for line in proc.stdout:  # type: ignore[union-attr]
        line = line.rstrip("\n")
        log_buffer.append(line)
        marker = parse_marker(line)
        if marker:
            current, total, desc = marker
            bar = render_progress_bar(current, total, desc)
            print(f"\r{bar}    ", end="", flush=True)
            last_bar = bar
    proc.wait()
    if last_bar:
        print()
    if proc.returncode != 0:
        print("\nERROR: Server setup failed. Full log:\n", file=sys.stderr)
        print("\n".join(log_buffer), file=sys.stderr)
        return 1
    return 0
