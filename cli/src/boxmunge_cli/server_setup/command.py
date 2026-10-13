# SPDX-License-Identifier: Apache-2.0
"""Server-setup command: verify, pre-flight, install, report."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from boxmunge_cli.server_setup.args import ServerSetupArgs
from boxmunge_cli.server_setup.hostkeys import HostKeyError, ensure_trusted, record_for_port
from boxmunge_cli.server_setup.install import (
    InstallError,
    run_with_progress,
    upload_local_bundle,
    upload_verified_installer,
)
from boxmunge_cli.server_setup.preflight import (
    PreflightError,
    check_freshness,
    check_is_debian,
    check_not_installed,
    check_privileges,
    check_ssh_access,
)
from boxmunge_cli.server_setup.release import (
    ReleaseError,
    VerifiedInstaller,
    fetch_verified_installer,
)
from boxmunge_cli.server_setup.remote import Target, default_known_hosts
from boxmunge_cli.server_setup.ssh_key import SSHKeyError, detect_ssh_key


def _confirm(prompt: str) -> bool:
    return input(prompt).strip().lower() == "y"


def installer_args(setup_args: ServerSetupArgs, hostname: str, ssh_key: str) -> list[str]:
    """install.sh arguments, one argv element per value (never shell text)."""
    args = ["--hostname", hostname, "--email", setup_args.email,
            "--ssh-key", ssh_key, "--ssh-port", str(setup_args.boxmunge_ssh_port)]
    for flag, enabled in (("--no-aide", setup_args.no_aide),
                          ("--no-crowdsec", setup_args.no_crowdsec),
                          ("--no-auto-updates", setup_args.no_auto_updates),
                          ("--self-signed-tls", setup_args.self_signed_tls)):
        if enabled:
            args.append(flag)
    return args


def _run_install(target: Target, needs_sudo: bool, setup_args: ServerSetupArgs,
                 ssh_key: str, installer: VerifiedInstaller | None) -> int:
    """Upload the release to the server and run it with progress tracking."""
    hostname = setup_args.hostname
    try:
        if installer is None:
            assert setup_args.local_bundle is not None
            print(f"Uploading local bundle: {setup_args.local_bundle}")
            run_prefix = upload_local_bundle(target, setup_args.local_bundle)
        else:
            print(f"Uploading verified installer ({installer.tag})...")
            run_prefix = upload_verified_installer(target, installer)
    except InstallError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    # The installer runs install.sh, which bootstraps the host (init-host.sh)
    # and installs the package, wrapper scripts and systemd units.
    argv = run_prefix + installer_args(setup_args, hostname, ssh_key)
    return run_with_progress(target.ssh(argv, needs_sudo))


def _fetch_installer(setup_args: ServerSetupArgs, workdir: Path) -> VerifiedInstaller | None:
    """Download and verify the release locally, before touching the server."""
    if setup_args.local_bundle:
        return None
    which = setup_args.release or "the latest release"
    print(f"Downloading and verifying {which}...", end=" ", flush=True)
    installer = fetch_verified_installer(setup_args.release, workdir)
    print(f"Ok ({installer.tag}, signature and checksum verified)")
    return installer


def run_server_setup(setup_args: ServerSetupArgs, known_hosts: Path | None = None) -> int:
    """Run server-setup. Returns an exit code."""
    if not setup_args.yes and not sys.stdin.isatty():
        print("ERROR: server-setup asks for confirmation, but stdin is not a terminal. "
              "Pass --yes to confirm non-interactively.", file=sys.stderr)
        return 2
    target = Target(setup_args.user, setup_args.host, setup_args.port,
                    known_hosts or default_known_hosts())

    try:
        public_key = detect_ssh_key(setup_args.ssh_key_arg)
    except SSHKeyError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    print(f"Key to authorise for the deploy and supervisor users: {public_key.describe()}")

    if not setup_args.yes:
        print(f"This will turn [{setup_args.host}] into a boxmunge server.")
        if not _confirm("Are you sure? [y/N] "):
            print("Aborted.")
            return 1
    ssh_key = public_key.line

    with tempfile.TemporaryDirectory(prefix="boxmunge-release-") as workdir:
        try:
            installer = _fetch_installer(setup_args, Path(workdir))
        except ReleaseError as e:
            print("FAILED")
            print(f"\nERROR: {e}", file=sys.stderr)
            return 1
        try:
            ensure_trusted(target, setup_args.host_key_fingerprint,
                           None if setup_args.yes else _confirm)
        except HostKeyError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1
        return _preflight_and_install(target, setup_args, ssh_key, installer)


def _preflight(target: Target, setup_args: ServerSetupArgs) -> bool | None:
    """Run pre-flight checks. Returns needs_sudo, or None to stop."""
    print("Attempting SSH access...", end=" ", flush=True)
    check_ssh_access(target)
    print("Ok")

    print("Verifying this is Debian...", end=" ", flush=True)
    check_is_debian(target)
    print("Ok")

    print("Checking root privileges...", end=" ", flush=True)
    needs_sudo = check_privileges(target)
    print("Ok" + (" (via sudo)" if needs_sudo else ""))

    print("Checking for existing installation...", end=" ", flush=True)
    check_not_installed(target, needs_sudo)
    print("Ok")

    print("Examining filesystem...", end=" ", flush=True)
    warnings = check_freshness(target, needs_sudo)
    if not warnings:
        print("Ok")
        return needs_sudo
    print("WARNING")
    print("\nThis server does not appear to be freshly installed:")
    for w in warnings:
        print(f"  - {w}")
    print("\nboxmunge takes over the entire box. Proceeding may interfere with existing services.")
    if not setup_args.yes and not _confirm("Continue anyway? [y/N] "):
        print("Aborted.")
        return None
    return needs_sudo


def _preflight_and_install(target: Target, setup_args: ServerSetupArgs, ssh_key: str,
                           installer: VerifiedInstaller | None) -> int:
    try:
        needs_sudo = _preflight(target, setup_args)
    except PreflightError as e:
        print("FAILED")
        print(f"\nERROR: {e}", file=sys.stderr)
        return 1
    if needs_sudo is None:
        return 1

    print(f"\nInstalling boxmunge on {setup_args.hostname}...")
    exit_code = _run_install(target, needs_sudo, setup_args, ssh_key, installer)
    if exit_code != 0:
        return exit_code

    bsp = setup_args.boxmunge_ssh_port
    hn = setup_args.hostname
    record_for_port(target, bsp)
    print("\nServer setup complete.")
    print(f"  Host key for [{target.host}]:{bsp} recorded in {target.known_hosts}.")
    print(next_steps(hn, bsp))
    return 0


def next_steps(hostname: str, ssh_port: int) -> str:
    port_flag = "" if ssh_port == 922 else f" --port {ssh_port}"
    return (f"  SSH (deploy): ssh -p {ssh_port} deploy@{hostname}\n"
            f"  SSH (admin):  ssh -p {ssh_port} supervisor@{hostname}\n"
            f"  Next: cd your-project && boxmunge init --server {hostname}{port_flag} "
            "--host <your-app-hostname>")
