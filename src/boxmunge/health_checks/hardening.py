"""Health checks for host hardening components."""

import os
import subprocess

from boxmunge.commands.health_cmd import HealthCheck

# System hardening tools (ufw, sysctl) live in sbin, which is absent from
# some callers' PATH — notably the deploy restricted shell, whose PATH is
# /usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/opt/boxmunge/bin.
# Without sbin, subprocess raises FileNotFoundError and the check falsely
# reports the tool "not installed" — which, for ufw, escalates health to
# exit 2 (CRITICAL) and made it look like the firewall was missing when it
# was installed and active all along. Augment PATH with the standard sbin
# dirs so binary resolution is independent of the caller's environment.
_SBIN_DIRS = ["/usr/local/sbin", "/usr/sbin", "/sbin"]


def _hardening_env() -> dict[str, str]:
    """A copy of the environment with the standard sbin dirs on PATH."""
    env = dict(os.environ)
    parts = env.get("PATH", "").split(os.pathsep) if env.get("PATH") else []
    for d in _SBIN_DIRS:
        if d not in parts:
            parts.append(d)
    env["PATH"] = os.pathsep.join(parts)
    return env


def _run(args: list[str], timeout: int) -> subprocess.CompletedProcess:
    """Run a hardening-probe command with sbin on PATH.

    Centralises the PATH augmentation so every check resolves sbin tools
    the same way regardless of which user/shell invoked health.
    """
    return subprocess.run(
        args, capture_output=True, text=True, check=False,
        timeout=timeout, env=_hardening_env(),
    )


def check_ufw(ssh_port: int = 922) -> HealthCheck:
    """Check if UFW firewall is active with expected rules.

    ``ufw status`` requires root. When health runs as a non-root user — e.g.
    the deploy restricted shell, whose PATH also lacks sbin — we cannot
    inspect UFW. Report an indeterminate WARN rather than a misleading
    "error" that escalates the whole health run to CRITICAL (exit 2) and
    reads as a firewall outage. The authoritative UFW verdict comes from the
    root-context health timer / upgrade shim, which run as root.
    """
    if os.geteuid() != 0:
        # Not a problem with the system — we simply lack the privilege to
        # inspect UFW. Report a neutral SKIP (exit-code-neutral) rather than
        # a WARN, so running 'health' from the non-root deploy shell doesn't
        # land in WARNINGS for a non-issue. The root health timer/upgrade
        # shim run as root and give the authoritative UFW verdict.
        return HealthCheck(
            "ufw", "skip",
            "requires root; verified by the scheduled health timer",
        )
    try:
        result = _run(["ufw", "status"], timeout=10)
        if result.returncode != 0:
            return HealthCheck("ufw", "error", "UFW command failed")
        if "Status: inactive" in result.stdout:
            return HealthCheck("ufw", "error", "UFW is inactive")
        if "Status: active" in result.stdout:
            missing = []
            if f"{ssh_port}/tcp" not in result.stdout:
                missing.append(f"SSH ({ssh_port}/tcp)")
            if "80/tcp" not in result.stdout:
                missing.append("HTTP (80/tcp)")
            if "443/tcp" not in result.stdout:
                missing.append("HTTPS (443/tcp)")
            if missing:
                return HealthCheck(
                    "ufw", "warn", f"Missing rules: {', '.join(missing)}",
                )
            return HealthCheck("ufw", "ok", "UFW active with expected rules")
        return HealthCheck("ufw", "warn", "UFW status unclear")
    except FileNotFoundError:
        return HealthCheck("ufw", "error", "UFW not installed")
    except subprocess.TimeoutExpired:
        return HealthCheck("ufw", "error", "UFW status timed out")


def check_crowdsec() -> HealthCheck:
    """Check if CrowdSec is running."""
    try:
        result = _run(["systemctl", "is-active", "crowdsec"], timeout=10)
        if result.returncode == 0:
            return HealthCheck("crowdsec", "ok", "CrowdSec active")
        return HealthCheck(
            "crowdsec", "warn",
            "CrowdSec not active (threat intelligence offline)",
        )
    except FileNotFoundError:
        return HealthCheck("crowdsec", "warn", "systemctl not available")
    except subprocess.TimeoutExpired:
        return HealthCheck("crowdsec", "warn", "CrowdSec status timed out")


def check_aide_status() -> HealthCheck:
    """Check if AIDE is installed and the database exists.

    The AIDE database lives under /var/lib/aide, which is root-only (0700).
    A non-root caller (the deploy restricted shell) can tell aide is
    installed but cannot stat the database — Path.exists() raises
    PermissionError. Report SKIP rather than crashing the whole health
    command or warning about a database we simply can't see. The root
    health timer gives the authoritative verdict.
    """
    try:
        result = _run(["which", "aide"], timeout=5)
        if result.returncode != 0:
            return HealthCheck("aide", "warn", "AIDE not installed")
        from pathlib import Path

        try:
            for db_path in [
                Path("/var/lib/aide/aide.db"),
                Path("/var/lib/aide/aide.db.new"),
            ]:
                if db_path.exists():
                    return HealthCheck(
                        "aide", "ok", "AIDE installed with database",
                    )
        except PermissionError:
            return HealthCheck(
                "aide", "skip",
                "installed; database not verifiable without root",
            )
        return HealthCheck(
            "aide", "warn", "AIDE installed but database not initialised",
        )
    except subprocess.TimeoutExpired:
        return HealthCheck("aide", "warn", "AIDE check timed out")


def check_auditd() -> HealthCheck:
    """Check if auditd is running."""
    try:
        result = _run(["systemctl", "is-active", "auditd"], timeout=10)
        if result.returncode == 0:
            return HealthCheck("auditd", "ok", "Auditd active")
        return HealthCheck("auditd", "warn", "Auditd not active")
    except FileNotFoundError:
        return HealthCheck("auditd", "warn", "systemctl not available")
    except subprocess.TimeoutExpired:
        return HealthCheck("auditd", "warn", "Auditd status timed out")


def check_unattended_upgrades() -> HealthCheck:
    """Check if unattended-upgrades is enabled."""
    try:
        result = _run(["systemctl", "is-active", "unattended-upgrades"], timeout=10)
        if result.returncode == 0:
            return HealthCheck(
                "auto-updates", "ok", "Unattended upgrades active",
            )
        return HealthCheck(
            "auto-updates", "warn", "Unattended upgrades not active",
        )
    except FileNotFoundError:
        return HealthCheck("auto-updates", "warn", "systemctl not available")
    except subprocess.TimeoutExpired:
        return HealthCheck("auto-updates", "warn", "Check timed out")


def check_sysctl_hardening() -> HealthCheck:
    """Check critical kernel hardening parameters."""
    expected = {
        "net.ipv4.tcp_syncookies": "1",
        "kernel.unprivileged_bpf_disabled": "1",
        "kernel.kptr_restrict": "2",
        "fs.suid_dumpable": "0",
    }
    wrong = []
    for key, want in expected.items():
        try:
            result = _run(["sysctl", "-n", key], timeout=5)
            if result.returncode != 0:
                # Key doesn't exist on this system (e.g. macOS, non-Linux)
                continue
            got = result.stdout.strip()
            if got != want:
                wrong.append(f"{key}={got} (expected {want})")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            # sysctl not available (e.g. macOS) — skip all checks
            return HealthCheck("sysctl", "ok", "sysctl not available (non-Linux)")
    if wrong:
        return HealthCheck(
            "sysctl", "warn", f"Non-hardened: {'; '.join(wrong)}",
        )
    return HealthCheck("sysctl", "ok", "Kernel parameters hardened")


def check_systemd_timers() -> HealthCheck:
    """Check that boxmunge systemd timers are active."""
    timers = ["boxmunge-health.timer", "boxmunge-backup.timer"]
    inactive = []
    for timer in timers:
        try:
            result = _run(["systemctl", "is-active", timer], timeout=5)
            if result.returncode != 0:
                inactive.append(timer)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            inactive.append(timer)
    if inactive:
        return HealthCheck(
            "timers", "warn", f"Inactive: {', '.join(inactive)}",
        )
    return HealthCheck("timers", "ok", "All boxmunge timers active")
