# SPDX-License-Identifier: Apache-2.0
"""Pre-flight checks for server-setup — run over SSH before installation."""

from __future__ import annotations

import subprocess


class PreflightError(Exception):
    """Raised when a pre-flight check fails."""


def _ssh_cmd(user: str, host: str, port: int, needs_sudo: bool, command: str) -> list[str]:
    """Build an SSH command for a pre-flight check."""
    remote = f"sudo {command}" if needs_sudo else command
    return ["ssh", "-p", str(port),
            "-o", "ConnectTimeout=10",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "UserKnownHostsFile=/dev/null",
            f"{user}@{host}", remote]


def _run_check(user: str, host: str, port: int, command: str, needs_sudo: bool = False) -> subprocess.CompletedProcess:
    """Run a command over SSH with captured output."""
    cmd = _ssh_cmd(user, host, port, needs_sudo, command)
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def check_ssh_access(user: str, host: str, port: int) -> None:
    """Verify we can SSH into the server."""
    result = _run_check(user, host, port, "echo ok")
    if result.returncode != 0:
        raise PreflightError(
            f"SSH connection failed to {user}@{host}:{port}. "
            f"Check hostname, port, and SSH key. ({result.stderr.strip()})"
        )


def check_is_debian(user: str, host: str, port: int) -> None:
    """Verify the server is running Debian."""
    result = _run_check(user, host, port, "cat /etc/os-release")
    if result.returncode != 0:
        raise PreflightError("Could not read /etc/os-release.")

    os_id = ""
    for line in result.stdout.splitlines():
        if line.startswith("ID="):
            os_id = line.split("=", 1)[1].strip().strip('"')
            break

    if os_id != "debian":
        distro = os_id or "unknown"
        raise PreflightError(
            f"boxmunge requires Debian. This server is running '{distro}'. "
            "See docs for supported platforms."
        )


def check_privileges(user: str, host: str, port: int) -> bool:
    """Verify root access. Returns True if sudo is needed, False if already root."""
    result = _run_check(user, host, port, "id -u")
    if result.returncode == 0 and result.stdout.strip() == "0":
        return False

    result = _run_check(user, host, port, "sudo -n id -u")
    if result.returncode == 0 and result.stdout.strip() == "0":
        return True

    raise PreflightError(
        f"Cannot get root access as {user}@{host}. "
        "Either log in as root, or configure passwordless sudo:\n"
        f"  echo '{user} ALL=(ALL) NOPASSWD: ALL' | sudo tee /etc/sudoers.d/{user}"
    )


def check_not_installed(user: str, host: str, port: int, needs_sudo: bool) -> None:
    """Verify boxmunge is not already installed."""
    result = _run_check(user, host, port, "test -d /opt/boxmunge", needs_sudo)
    if result.returncode == 0:
        raise PreflightError(
            "boxmunge is already installed on this server. "
            "Use 'boxmunge-server upgrade' to update."
        )


def check_freshness(user: str, host: str, port: int, needs_sudo: bool) -> list[str]:
    """Scan for signs this isn't a fresh box. Returns list of warning strings."""
    warnings: list[str] = []

    # Exclude the login user — providers often create a default non-root user
    result = _run_check(
        user, host, port,
        f"awk -F: '$3 >= 1000 && $1 != \"nobody\" && $1 != \"{user}\" {{print $1}}' /etc/passwd",
        needs_sudo,
    )
    if result.returncode == 0 and result.stdout.strip():
        users = result.stdout.strip().split("\n")
        warnings.append(f"Non-system users found: {', '.join(users)}")

    result = _run_check(user, host, port, "docker ps -q 2>/dev/null", needs_sudo)
    if result.returncode == 0 and result.stdout.strip():
        count = len(result.stdout.strip().split("\n"))
        warnings.append(f"Docker is running with {count} active container(s)")

    result = _run_check(
        user, host, port,
        "ss -tlnp 2>/dev/null | grep -E ':80 |:443 '",
        needs_sudo,
    )
    if result.returncode == 0 and result.stdout.strip():
        warnings.append("Services already listening on port 80 and/or 443")

    # Exclude the login user's home dir — it's expected on provider images
    result = _run_check(
        user, host, port,
        f"find /home /var/www -mindepth 1 -maxdepth 1 "
        f"! -name '{user}' 2>/dev/null | head -5",
        needs_sudo,
    )
    if result.returncode == 0 and result.stdout.strip():
        warnings.append("Data found in /home or /var/www")

    return warnings
