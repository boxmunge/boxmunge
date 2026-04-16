"""Health checks for host hardening components."""

import subprocess

from boxmunge.commands.health_cmd import HealthCheck


def check_ufw(ssh_port: int = 922) -> HealthCheck:
    """Check if UFW firewall is active with expected rules."""
    try:
        result = subprocess.run(
            ["ufw", "status"],
            capture_output=True, text=True, check=False, timeout=10,
        )
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
        result = subprocess.run(
            ["systemctl", "is-active", "crowdsec"],
            capture_output=True, text=True, check=False, timeout=10,
        )
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
    """Check if AIDE is installed and the database exists."""
    try:
        result = subprocess.run(
            ["which", "aide"],
            capture_output=True, check=False, timeout=5,
        )
        if result.returncode != 0:
            return HealthCheck("aide", "warn", "AIDE not installed")
        from pathlib import Path

        for db_path in [
            Path("/var/lib/aide/aide.db"),
            Path("/var/lib/aide/aide.db.new"),
        ]:
            if db_path.exists():
                return HealthCheck(
                    "aide", "ok", "AIDE installed with database",
                )
        return HealthCheck(
            "aide", "warn", "AIDE installed but database not initialised",
        )
    except subprocess.TimeoutExpired:
        return HealthCheck("aide", "warn", "AIDE check timed out")


def check_auditd() -> HealthCheck:
    """Check if auditd is running."""
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "auditd"],
            capture_output=True, text=True, check=False, timeout=10,
        )
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
        result = subprocess.run(
            ["systemctl", "is-active", "unattended-upgrades"],
            capture_output=True, text=True, check=False, timeout=10,
        )
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
            result = subprocess.run(
                ["sysctl", "-n", key],
                capture_output=True, text=True, check=False, timeout=5,
            )
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
            result = subprocess.run(
                ["systemctl", "is-active", timer],
                capture_output=True, text=True, check=False, timeout=5,
            )
            if result.returncode != 0:
                inactive.append(timer)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            inactive.append(timer)
    if inactive:
        return HealthCheck(
            "timers", "warn", f"Inactive: {', '.join(inactive)}",
        )
    return HealthCheck("timers", "ok", "All boxmunge timers active")
