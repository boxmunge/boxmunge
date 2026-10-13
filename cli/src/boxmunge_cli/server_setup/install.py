# SPDX-License-Identifier: Apache-2.0
"""Put the installer on the server and run it, showing progress."""

from __future__ import annotations

import re
import subprocess
import sys

from boxmunge_cli.server_setup.progress import parse_marker, render_progress_bar
from boxmunge_cli.server_setup.release import INSTALLER, VerifiedInstaller
from boxmunge_cli.server_setup.remote import Target

_REMOTE_TMP = re.compile(r"/tmp/boxmunge-setup\.[A-Za-z0-9]+")

# Constant scripts run with `sh -c SCRIPT sh ARGS...`: the workdir, digest and
# installer arguments arrive as positional parameters, never as shell text.
_RUN_VERIFIED = f"""\
dir=$1; sum=$2; shift 2
cd "$dir" || exit 1
if ! printf '%s  %s\\n' "$sum" {INSTALLER} | sha256sum -c --quiet -; then
    echo "ERROR: uploaded installer does not match the verified checksum" >&2
    rm -rf "$dir"; exit 1
fi
bash {INSTALLER} "$@"; rc=$?
rm -rf "$dir"; exit $rc
"""
_RUN_LOCAL_BUNDLE = """\
dir=$1; shift
cd "$dir" && mkdir release && tar xzf release.tar.gz -C release --strip-components=1 \
    || { rm -rf "$dir"; exit 1; }
bash release/install.sh "$@"; rc=$?
rm -rf "$dir"; exit $rc
"""


class InstallError(Exception):
    """Raised when the installer cannot be put on the server."""


def make_remote_workdir(target: Target) -> str:
    """Create a private temp dir on the server, owned by the login user."""
    argv = ["sh", "-c", "umask 077 && mktemp -d /tmp/boxmunge-setup.XXXXXXXX"]
    result = subprocess.run(target.ssh(argv), capture_output=True, text=True, check=False)
    workdir = result.stdout.strip()
    if result.returncode != 0 or not _REMOTE_TMP.fullmatch(workdir):
        raise InstallError(f"Could not create a temp dir on the server: "
                           f"{(result.stderr or result.stdout).strip()}")
    return workdir


def upload_verified_installer(target: Target, installer: VerifiedInstaller) -> list[str]:
    """Upload the installer; return the argv prefix that re-checks and runs it.

    The digest is checked again on the server, so a corrupted or swapped
    upload never runs. Append the installer's own arguments to the prefix.
    """
    workdir = make_remote_workdir(target)
    scp = target.scp(str(installer.path), f"{workdir}/{INSTALLER}")
    if subprocess.run(scp, check=False).returncode != 0:
        raise InstallError("Failed to upload the installer.")
    return ["sh", "-c", _RUN_VERIFIED, "sh", workdir, installer.sha256]


def upload_local_bundle(target: Target, bundle: str) -> list[str]:
    """Development path: upload an unverified local bundle; return the run argv prefix."""
    print("WARNING: --local-bundle installs an unsigned, unverified local build. "
          "Use it only for development.", file=sys.stderr)
    workdir = make_remote_workdir(target)
    if subprocess.run(target.scp(bundle, f"{workdir}/release.tar.gz"),
                      check=False).returncode != 0:
        raise InstallError("Failed to upload the local bundle.")
    return ["sh", "-c", _RUN_LOCAL_BUNDLE, "sh", workdir]


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
