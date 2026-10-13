# SPDX-License-Identifier: Apache-2.0
"""Server-setup command — orchestrates pre-flight, install, and progress."""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

from boxmunge_cli.server_setup.args import ServerSetupArgs
from boxmunge_cli.server_setup.install import (
    InstallError,
    run_with_progress,
    upload_local_bundle,
    upload_verified_installer,
)
from boxmunge_cli.server_setup.release import (
    ReleaseError,
    VerifiedInstaller,
    fetch_verified_installer,
)
from boxmunge_cli.server_setup.ssh_key import detect_ssh_key, SSHKeyError
from boxmunge_cli.server_setup.preflight import (
    check_ssh_access,
    check_is_debian,
    check_privileges,
    check_not_installed,
    check_freshness,
    PreflightError,
)


def _ssh_cmd(user: str, host: str, port: int, needs_sudo: bool, command: str) -> list[str]:
    """Build SSH command with optional sudo prefix."""
    remote = f"sudo bash -c {_shell_quote(command)}" if needs_sudo else command
    return ["ssh", "-p", str(port),
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "UserKnownHostsFile=/dev/null",
            f"{user}@{host}", remote]


def _shell_quote(s: str) -> str:
    """Quote a string for embedding in a shell command using $'...' syntax."""
    escaped = s.replace("\\", "\\\\").replace("'", "\\'")
    return f"$'{escaped}'"


def _resolve_hostname(user: str, host: str, port: int, needs_sudo: bool) -> str:
    """Query the server's FQDN when target was an IP."""
    result = subprocess.run(
        _ssh_cmd(user, host, port, needs_sudo, "hostname -f"),
        capture_output=True, text=True, check=False,
    )
    fqdn = result.stdout.strip()
    if result.returncode != 0 or not fqdn:
        return host  # fall back to the IP
    return fqdn


def _scp_cmd(user: str, host: str, port: int, local: str, remote: str) -> list[str]:
    return ["scp", "-P", str(port),
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "UserKnownHostsFile=/dev/null",
            local, f"{user}@{host}:{remote}"]


def _run_install(
    user: str, host: str, port: int, needs_sudo: bool,
    setup_args: ServerSetupArgs, ssh_key: str,
    installer: VerifiedInstaller | None,
) -> int:
    """Upload the release to the server and run it with progress tracking."""
    hostname = setup_args.hostname or host

    def ssh(command: str, sudo: bool) -> list[str]:
        return _ssh_cmd(user, host, port, sudo, command)

    def scp(local: str, remote: str) -> list[str]:
        return _scp_cmd(user, host, port, local, remote)

    try:
        if installer is None:
            assert setup_args.local_bundle is not None
            print(f"Uploading local bundle: {setup_args.local_bundle}")
            workdir, run_prefix = upload_local_bundle(ssh, scp, setup_args.local_bundle)
        else:
            print(f"Uploading verified installer ({installer.tag})...")
            workdir, run_prefix = upload_verified_installer(ssh, scp, installer)
    except InstallError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    # The installer runs install.sh, which bootstraps the host (init-host.sh)
    # and installs the package, wrapper scripts and systemd units.
    init_cmd_parts = [
        run_prefix,
        f"--hostname {hostname}",
        f"--email {setup_args.email}",
        f"--ssh-key '{ssh_key}'",
        f"--ssh-port {setup_args.boxmunge_ssh_port}",
    ]
    if setup_args.no_aide:
        init_cmd_parts.append("--no-aide")
    if setup_args.no_crowdsec:
        init_cmd_parts.append("--no-crowdsec")
    if setup_args.no_auto_updates:
        init_cmd_parts.append("--no-auto-updates")
    if setup_args.self_signed_tls:
        init_cmd_parts.append("--self-signed-tls")

    remote_cmd = " ".join(init_cmd_parts) + f"; rc=$?; rm -rf {workdir}; exit $rc"
    return run_with_progress(_ssh_cmd(user, host, port, needs_sudo, remote_cmd))


def _fetch_installer(setup_args: ServerSetupArgs, workdir: Path) -> VerifiedInstaller | None:
    """Download and verify the release locally, before touching the server."""
    if setup_args.local_bundle:
        return None
    which = setup_args.release or "the latest release"
    print(f"Downloading and verifying {which}...", end=" ", flush=True)
    installer = fetch_verified_installer(setup_args.release, workdir)
    print(f"Ok ({installer.tag}, signature and checksum verified)")
    return installer


def _confirm(prompt: str) -> bool:
    return input(prompt).strip().lower() == "y"


def run_server_setup(setup_args: ServerSetupArgs) -> int:
    """Run server-setup. Returns an exit code."""
    if not setup_args.yes and not sys.stdin.isatty():
        print("ERROR: server-setup asks for confirmation, but stdin is not a terminal. "
              "Pass --yes to confirm non-interactively.", file=sys.stderr)
        return 2
    return _run(setup_args)


def _run(setup_args: ServerSetupArgs) -> int:
    # Interactive confirmation
    if not setup_args.yes:
        print(f"This will turn [{setup_args.host}] into a boxmunge server.")
        if not _confirm("Are you sure? [y/N] "):
            print("Aborted.")
            return 1

    # Detect SSH key
    try:
        ssh_key = detect_ssh_key(setup_args.ssh_key_arg)
    except SSHKeyError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory(prefix="boxmunge-release-") as workdir:
        try:
            installer = _fetch_installer(setup_args, Path(workdir))
        except ReleaseError as e:
            print("FAILED")
            print(f"\nERROR: {e}", file=sys.stderr)
            return 1
        return _preflight_and_install(setup_args, ssh_key, installer)


def _preflight_and_install(setup_args: ServerSetupArgs, ssh_key: str,
                           installer: VerifiedInstaller | None) -> int:
    # Pre-flight checks
    try:
        print("Attempting SSH access...", end=" ", flush=True)
        check_ssh_access(setup_args.user, setup_args.host, setup_args.port)
        print("Ok")

        print("Verifying this is Debian...", end=" ", flush=True)
        check_is_debian(setup_args.user, setup_args.host, setup_args.port)
        print("Ok")

        print("Checking root privileges...", end=" ", flush=True)
        needs_sudo = check_privileges(setup_args.user, setup_args.host, setup_args.port)
        print("Ok" + (" (via sudo)" if needs_sudo else ""))

        print("Checking for existing installation...", end=" ", flush=True)
        check_not_installed(setup_args.user, setup_args.host, setup_args.port, needs_sudo)
        print("Ok")

        print("Examining filesystem...", end=" ", flush=True)
        warnings = check_freshness(setup_args.user, setup_args.host, setup_args.port, needs_sudo)
        if warnings:
            print("WARNING")
            print("\nThis server does not appear to be freshly installed:")
            for w in warnings:
                print(f"  - {w}")
            print("\nboxmunge takes over the entire box. Proceeding may interfere with existing services.")
            if not setup_args.yes:
                if not _confirm("Continue anyway? [y/N] "):
                    print("Aborted.")
                    return 1
        else:
            print("Ok")

    except PreflightError as e:
        print("FAILED")
        print(f"\nERROR: {e}", file=sys.stderr)
        return 1

    # Resolve hostname if target was an IP
    if setup_args.hostname is None:
        setup_args.hostname = _resolve_hostname(
            setup_args.user, setup_args.host, setup_args.port, needs_sudo
        )

    # Install
    print(f"\nInstalling boxmunge on {setup_args.hostname}...")
    exit_code = _run_install(
        setup_args.user, setup_args.host, setup_args.port,
        needs_sudo, setup_args, ssh_key, installer,
    )

    if exit_code == 0:
        bsp = setup_args.boxmunge_ssh_port
        hn = setup_args.hostname
        print("\nServer setup complete.")
        print(f"  SSH (deploy): ssh -p {bsp} deploy@{hn}")
        print(f"  SSH (admin):  ssh -p {bsp} supervisor@{hn}")
        print(f"  Next: cd your-project && boxmunge init --server {hn}")

    return exit_code
