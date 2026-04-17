# SPDX-License-Identifier: Apache-2.0
"""Server-setup command — orchestrates pre-flight, install, and progress."""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass

from boxmunge_cli.server_setup.target import parse_target, is_ip_address
from boxmunge_cli.server_setup.ssh_key import detect_ssh_key, SSHKeyError
from boxmunge_cli.server_setup.preflight import (
    check_ssh_access,
    check_is_debian,
    check_privileges,
    check_not_installed,
    check_freshness,
    PreflightError,
)
from boxmunge_cli.server_setup.progress import parse_marker, render_progress_bar


GITHUB_REPO = "boxmunge/boxmunge"


@dataclass
class ServerSetupArgs:
    user: str
    host: str
    port: int
    email: str
    ssh_key_arg: str | None = None
    hostname: str | None = None
    boxmunge_ssh_port: int = 922
    no_aide: bool = False
    no_crowdsec: bool = False
    no_auto_updates: bool = False
    reboot_window: str = "04:00"
    self_signed_tls: bool = False
    yes: bool = False
    local_bundle: str | None = None


def parse_args(args: list[str]) -> ServerSetupArgs:
    """Parse server-setup command arguments."""
    email: str | None = None
    ssh_key_arg: str | None = None
    hostname: str | None = None
    port = 22
    boxmunge_ssh_port = 922
    no_aide = False
    no_crowdsec = False
    no_auto_updates = False
    reboot_window = "04:00"
    self_signed_tls = False
    yes = False
    local_bundle: str | None = None

    i = 0
    positional: list[str] = []
    while i < len(args):
        if args[i] in ("-p", "--port") and i + 1 < len(args):
            port = int(args[i + 1]); i += 2
        elif args[i] == "--email" and i + 1 < len(args):
            email = args[i + 1]; i += 2
        elif args[i] == "--ssh-key" and i + 1 < len(args):
            ssh_key_arg = args[i + 1]; i += 2
        elif args[i] == "--hostname" and i + 1 < len(args):
            hostname = args[i + 1]; i += 2
        elif args[i] == "--boxmunge-ssh-port" and i + 1 < len(args):
            boxmunge_ssh_port = int(args[i + 1]); i += 2
        elif args[i] == "--no-aide":
            no_aide = True; i += 1
        elif args[i] == "--no-crowdsec":
            no_crowdsec = True; i += 1
        elif args[i] == "--no-auto-updates":
            no_auto_updates = True; i += 1
        elif args[i] == "--reboot-window" and i + 1 < len(args):
            reboot_window = args[i + 1]; i += 2
        elif args[i] == "--self-signed-tls":
            self_signed_tls = True; i += 1
        elif args[i] in ("-y", "--yes"):
            yes = True; i += 1
        elif args[i] == "--local-bundle" and i + 1 < len(args):
            local_bundle = args[i + 1]; i += 2
        elif not args[i].startswith("-"):
            positional.append(args[i]); i += 1
        else:
            i += 1

    if not positional:
        print("Usage: boxmunge server-setup [user@]host --email EMAIL [options]",
              file=sys.stderr)
        sys.exit(2)
    if not email:
        print("ERROR: --email is required (for Let's Encrypt only, never collected by boxmunge).",
              file=sys.stderr)
        sys.exit(2)

    user, host = parse_target(positional[0])

    # Hostname resolution: use the provided name if it's not an IP
    if hostname is None and not is_ip_address(host):
        hostname = host

    return ServerSetupArgs(
        user=user, host=host, port=port, email=email,
        ssh_key_arg=ssh_key_arg, hostname=hostname,
        boxmunge_ssh_port=boxmunge_ssh_port,
        no_aide=no_aide, no_crowdsec=no_crowdsec,
        no_auto_updates=no_auto_updates, reboot_window=reboot_window,
        self_signed_tls=self_signed_tls, yes=yes,
        local_bundle=local_bundle,
    )


def _ssh_cmd(user: str, host: str, port: int, needs_sudo: bool, command: str) -> list[str]:
    """Build SSH command with optional sudo prefix."""
    remote = f"sudo {command}" if needs_sudo else command
    return ["ssh", "-p", str(port),
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "UserKnownHostsFile=/dev/null",
            f"{user}@{host}", remote]


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


def _run_install(
    user: str, host: str, port: int, needs_sudo: bool,
    setup_args: ServerSetupArgs, ssh_key: str,
) -> int:
    """Upload or pull release on the server and run init-host.sh with progress tracking."""
    hostname = setup_args.hostname or host

    # Step 1: Get release onto the server
    if setup_args.local_bundle:
        # Upload local bundle via SCP and extract
        print(f"Uploading local bundle: {setup_args.local_bundle}")
        scp_cmd = [
            "scp",
            "-P", str(port),
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "UserKnownHostsFile=/dev/null",
            setup_args.local_bundle,
            f"{user}@{host}:/tmp/boxmunge-release.tar.gz",
        ]
        result = subprocess.run(scp_cmd, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            print("ERROR: Failed to upload bundle.", file=sys.stderr)
            print(result.stderr, file=sys.stderr)
            return 1
        extract_script = (
            "set -e && cd /tmp && "
            "rm -rf boxmunge-release && mkdir boxmunge-release && "
            "tar xzf boxmunge-release.tar.gz -C boxmunge-release --strip-components=1 && "
            "echo PULL_OK"
        )
        cmd = _ssh_cmd(user, host, port, needs_sudo, f"bash -c '{extract_script}'")
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.returncode != 0 or "PULL_OK" not in result.stdout:
            print("ERROR: Failed to extract bundle on server.", file=sys.stderr)
            print(result.stderr, file=sys.stderr)
            return 1
    else:
        # Pull latest release from GitHub
        pull_script = (
            f"set -e && "
            f"cd /tmp && "
            f"RELEASE_URL=$(curl -sf 'https://api.github.com/repos/{GITHUB_REPO}/releases/latest' "
            f"| python3 -c \"import sys,json; print(json.load(sys.stdin)['tarball_url'])\") && "
            f"curl -sfL \"$RELEASE_URL\" -o boxmunge-release.tar.gz && "
            f"rm -rf boxmunge-release && mkdir boxmunge-release && "
            f"tar xzf boxmunge-release.tar.gz -C boxmunge-release --strip-components=1 && "
            f"echo PULL_OK"
        )
        print("Fetching latest release from GitHub...")
        cmd = _ssh_cmd(user, host, port, needs_sudo, f"bash -c '{pull_script}'")
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.returncode != 0 or "PULL_OK" not in result.stdout:
            print("ERROR: Failed to fetch release from GitHub.", file=sys.stderr)
            print(result.stderr, file=sys.stderr)
            return 1

    # Step 2: Run install.sh (which calls init-host.sh for bootstrapping,
    # then installs the Python package, wrapper scripts, and systemd units)
    init_cmd_parts = [
        "bash /tmp/boxmunge-release/install.sh",
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

    remote_cmd = " ".join(init_cmd_parts)
    ssh_cmd = _ssh_cmd(user, host, port, needs_sudo, remote_cmd)

    proc = subprocess.Popen(
        ssh_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True,
    )

    log_buffer: list[str] = []
    last_bar = ""

    for line in proc.stdout:  # type: ignore[union-attr]
        line = line.rstrip("\n")
        log_buffer.append(line)
        marker = parse_marker(line)
        if marker:
            current, total, desc = marker
            bar = render_progress_bar(current, total, desc)
            # Overwrite previous line
            print(f"\r{bar}    ", end="", flush=True)
            last_bar = bar
        # Non-marker lines are silently buffered

    proc.wait()

    if last_bar:
        print()  # newline after final progress bar

    if proc.returncode != 0:
        print("\nERROR: Server setup failed. Full log:\n", file=sys.stderr)
        print("\n".join(log_buffer), file=sys.stderr)
        return 1

    return 0


def cmd_server_setup(args: list[str]) -> None:
    """CLI entry point for server-setup command."""
    setup_args = parse_args(args)

    # Interactive confirmation
    if not setup_args.yes:
        print(f"This will turn [{setup_args.host}] into a boxmunge server.")
        response = input("Are you sure? [y/N] ").strip().lower()
        if response != "y":
            print("Aborted.")
            sys.exit(0)

    # Detect SSH key
    try:
        ssh_key = detect_ssh_key(setup_args.ssh_key_arg)
    except SSHKeyError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

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
                response = input("Continue anyway? [y/N] ").strip().lower()
                if response != "y":
                    print("Aborted.")
                    sys.exit(0)
        else:
            print("Ok")

    except PreflightError as e:
        print("FAILED")
        print(f"\nERROR: {e}", file=sys.stderr)
        sys.exit(1)

    # Resolve hostname if target was an IP
    if setup_args.hostname is None:
        setup_args.hostname = _resolve_hostname(
            setup_args.user, setup_args.host, setup_args.port, needs_sudo
        )

    # Install
    print(f"\nInstalling boxmunge on {setup_args.hostname}...")
    exit_code = _run_install(
        setup_args.user, setup_args.host, setup_args.port,
        needs_sudo, setup_args, ssh_key,
    )

    if exit_code == 0:
        bsp = setup_args.boxmunge_ssh_port
        hn = setup_args.hostname
        print(f"\nServer setup complete.")
        print(f"  SSH (deploy): ssh -p {bsp} deploy@{hn}")
        print(f"  SSH (admin):  ssh -p {bsp} supervisor@{hn}")
        print(f"  Next: cd your-project && boxmunge init --server {hn}")

    sys.exit(exit_code)
