# SPDX-License-Identifier: Apache-2.0
"""Pre-flight checks for server-setup, run over SSH before installation.

Every remote command is an argv list; values such as the login user are
passed as separate arguments (or as positional parameters to a constant
`sh -c` script), never spliced into shell text.
"""

from __future__ import annotations

import subprocess

from boxmunge_cli.server_setup.remote import Target


class PreflightError(Exception):
    """Raised when a pre-flight check fails."""


def _run_check(target: Target, argv: list[str],
               needs_sudo: bool = False) -> subprocess.CompletedProcess:
    """Run argv over SSH with captured output."""
    return subprocess.run(target.ssh(argv, needs_sudo), capture_output=True,
                          text=True, check=False)


# Debian releases boxmunge is built and tested on, and the CPU it installs for
# (install.sh downloads an amd64 cosign).
SUPPORTED_DEBIAN = ("13",)
SUPPORTED_ARCH = ("x86_64",)


def check_ssh_access(target: Target) -> None:
    """Verify we can SSH into the server."""
    result = _run_check(target, ["echo", "ok"])
    if result.returncode != 0:
        raise PreflightError(
            f"SSH connection failed to {target.user}@{target.host}:{target.port}: "
            f"{result.stderr.strip()}\nCheck hostname, port and SSH key. If an earlier "
            "server-setup got past SSH hardening, sshd now listens on port 922 and "
            f"root login is off: inspect with 'ssh -p 922 supervisor@{target.host}'."
        )


def _os_release(text: str) -> dict[str, str]:
    fields = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            fields[key.strip()] = value.strip().strip('"')
    return fields


def check_is_debian(target: Target) -> None:
    """Verify the server runs a supported Debian release on a supported CPU."""
    result = _run_check(target, ["cat", "/etc/os-release"])
    if result.returncode != 0:
        raise PreflightError("Could not read /etc/os-release.")
    fields = _os_release(result.stdout)
    os_id = fields.get("ID", "")
    if os_id != "debian":
        raise PreflightError(
            f"boxmunge requires Debian. This server is running '{os_id or 'unknown'}'. "
            "See docs for supported platforms."
        )
    version = fields.get("VERSION_ID", "")
    if version not in SUPPORTED_DEBIAN:
        raise PreflightError(
            f"boxmunge supports Debian {', '.join(SUPPORTED_DEBIAN)}; this server runs "
            f"Debian {version or 'unknown'}. Reinstall the VPS with a supported release."
        )
    arch = _run_check(target, ["uname", "-m"])
    machine = arch.stdout.strip()
    if arch.returncode != 0 or machine not in SUPPORTED_ARCH:
        raise PreflightError(
            f"boxmunge installs for {', '.join(SUPPORTED_ARCH)}; this server is "
            f"'{machine or 'unknown'}'."
        )


def check_privileges(target: Target) -> bool:
    """Verify root access. Returns True if sudo is needed, False if already root."""
    result = _run_check(target, ["id", "-u"])
    if result.returncode == 0 and result.stdout.strip() == "0":
        return False

    result = _run_check(target, ["id", "-u"], needs_sudo=True)
    if result.returncode == 0 and result.stdout.strip() == "0":
        return True

    raise PreflightError(
        f"Cannot get root access as {target.user}@{target.host}. "
        "Either log in as root, or configure passwordless sudo:\n"
        f"  echo '{target.user} ALL=(ALL) NOPASSWD: ALL' | sudo tee /etc/sudoers.d/{target.user}"
    )


def check_not_installed(target: Target, needs_sudo: bool) -> None:
    """Verify boxmunge is not installed, fully or partly."""
    done = _run_check(target, ["test", "-f", "/opt/boxmunge/config/boxmunge.yml"], needs_sudo)
    if done.returncode == 0:
        raise PreflightError(
            "boxmunge is already installed on this server. Upgrade it on the server "
            "with 'upgrade' (as deploy or supervisor), not with server-setup."
        )
    partial = _run_check(target, ["test", "-d", "/opt/boxmunge"], needs_sudo)
    if partial.returncode == 0:
        raise PreflightError(
            "A partial boxmunge install was found (/opt/boxmunge exists, but no "
            "config/boxmunge.yml): an earlier server-setup stopped part-way. The "
            "safest recovery is to reinstall the VPS from its image and run "
            "server-setup again. To inspect first, read the install output above "
            "or log in and look at /opt/boxmunge."
        )


# Constant scripts; the login user arrives as $1.
_OTHER_USERS = 'awk -F: -v me="$1" \'$3 >= 1000 && $1 != "nobody" && $1 != me {print $1}\' /etc/passwd'
_LISTENERS = "ss -tlnp 2>/dev/null | grep -E ':80 |:443 '"
_HOME_DATA = 'find /home /var/www -mindepth 1 -maxdepth 1 ! -name "$1" 2>/dev/null | head -5'


def check_freshness(target: Target, needs_sudo: bool) -> list[str]:
    """Scan for signs this isn't a fresh box. Returns list of warning strings."""
    warnings: list[str] = []

    # Exclude the login user: providers often create a default non-root user.
    result = _run_check(target, ["sh", "-c", _OTHER_USERS, "sh", target.user], needs_sudo)
    if result.returncode == 0 and result.stdout.strip():
        users = result.stdout.strip().split("\n")
        warnings.append(f"Non-system users found: {', '.join(users)}")

    result = _run_check(target, ["sh", "-c", "docker ps -q 2>/dev/null"], needs_sudo)
    if result.returncode == 0 and result.stdout.strip():
        count = len(result.stdout.strip().split("\n"))
        warnings.append(f"Docker is running with {count} active container(s)")

    result = _run_check(target, ["sh", "-c", _LISTENERS], needs_sudo)
    if result.returncode == 0 and result.stdout.strip():
        warnings.append("Services already listening on port 80 and/or 443")

    # Exclude the login user's home dir: it's expected on provider images.
    result = _run_check(target, ["sh", "-c", _HOME_DATA, "sh", target.user], needs_sudo)
    if result.returncode == 0 and result.stdout.strip():
        warnings.append("Data found in /home or /var/www")

    return warnings
