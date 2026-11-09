# SPDX-License-Identifier: Apache-2.0
"""boxmunge health -- non-destructive platform health audit.

Checks system configuration, component health, config drift, and
recent log patterns. No writes, no restarts.

Exit 2 during an upgrade's probation rolls the platform back and blocklists
the release, and a traceback exits 1, which reads as healthy. So only a
platform component a probe positively saw broken is an error; a probe that
timed out or could not tell, and any per-project input, warns; and no check
can take the report down with it (run_guarded).
"""

import json
import os
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass, field

from boxmunge.docker import COMPOSE_PROJECT_LABEL
from boxmunge.docker_run import docker_env
from boxmunge.paths import BoxPaths


@dataclass
class HealthCheck:
    name: str
    # "ok" | "warn" | "error" | "skip". "skip" means the check could not be
    # performed (e.g. it needs root and health was run as a non-root user);
    # it is informational and never affects the exit code.
    status: str
    detail: str


@dataclass
class HealthReport:
    checks: list[HealthCheck] = field(default_factory=list)

    @property
    def exit_code(self) -> int:
        if any(c.status == "error" for c in self.checks):
            return 2
        if any(c.status == "warn" for c in self.checks):
            return 1
        return 0

    def format_text(self) -> str:
        lines = ["boxmunge health report:", ""]
        for check in self.checks:
            icon = {
                "ok": "OK", "warn": "WARN", "error": "ERR", "skip": "SKIP",
            }[check.status]
            line = f"  {icon:4s} {check.name}"
            if check.detail:
                line += f" -- {check.detail}"
            lines.append(line)
        lines.append("")
        if self.exit_code == 0:
            lines.append("RESULT: HEALTHY")
        elif self.exit_code == 1:
            lines.append("RESULT: WARNINGS")
        else:
            lines.append("RESULT: ISSUES FOUND")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "healthy": self.exit_code == 0,
            "exit_code": self.exit_code,
            "checks": [
                {"name": c.name, "status": c.status, "detail": c.detail}
                for c in self.checks
            ],
        }

    def format_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


def check_docker_running() -> HealthCheck:
    """Check if Docker daemon is running."""
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True, text=True, check=False, timeout=10,
            env=docker_env(),
        )
        if result.returncode == 0:
            return HealthCheck("docker", "ok", "Docker daemon running")
        return HealthCheck("docker", "error", "Docker daemon not responding")
    except FileNotFoundError:
        return HealthCheck("docker", "error", "docker CLI not found")
    # A timeout says the daemon is busy, not that it is down: run_guarded warns.


def check_caddy_container() -> HealthCheck:
    """Check if Caddy container is running and healthy.

    The host's CrowdSec follows boxmunge-caddy by name, so a container of
    that name from any compose project but the platform's own `caddy`
    (caddy/compose.yml) is an error: CrowdSec would read its output as
    Caddy's. Compose sets the project label itself; a service cannot."""
    try:
        result = subprocess.run(
            ["docker", "inspect", "--format",
             f'{{{{.State.Health.Status}}}}|{{{{index .Config.Labels "{COMPOSE_PROJECT_LABEL}"}}}}',
             "boxmunge-caddy"],
            capture_output=True, text=True, check=False, timeout=10,
            env=docker_env(),
        )
        if result.returncode != 0:
            return HealthCheck("caddy", "error", "Caddy container not found")
        status, _, project = result.stdout.strip().partition("|")
        if project != "caddy":
            return HealthCheck(
                "caddy", "error",
                f"boxmunge-caddy belongs to compose project {project!r}, not the "
                f"platform's caddy: CrowdSec reads its output as Caddy's. Remove it "
                f"and run: docker compose -f /opt/boxmunge/caddy/compose.yml up -d")
        if status == "healthy":
            return HealthCheck("caddy", "ok", "Caddy container healthy")
        return HealthCheck("caddy", "warn", f"Caddy container status: {status}")
    except FileNotFoundError:
        return HealthCheck("caddy", "error", "docker CLI not found, so Caddy cannot be checked")


def check_system_container(paths: BoxPaths) -> HealthCheck:
    """Check boxmunge-system is running with this root's mounts, on an image
    built from the installed definition.

    An error when it is not usable: age and rclone have no host fallback, so
    backups, restores and backup-sync all fail while it fails. A warning when
    it runs a previous image (a rebuild failed): backups still work, and an
    error would roll back a platform upgrade in probation.
    """
    from boxmunge.system_container import (
        SystemContainerError, SystemContainerTimeout, connect, stale_image,
    )
    try:
        connect(paths)
        stale = stale_image(paths)
    except SystemContainerTimeout as e:  # Docker is busy: it says nothing about the container
        return HealthCheck("system-container", "warn", str(e))
    except SystemContainerError as e:
        return HealthCheck("system-container", "error", str(e))
    if stale:
        return HealthCheck("system-container", "warn", stale)
    return HealthCheck("system-container", "ok", "boxmunge-system running")


def check_file_permissions(paths: BoxPaths) -> HealthCheck:
    """Check critical file permissions."""
    issues = []
    if paths.backup_key.exists():
        mode = paths.backup_key.stat().st_mode & 0o777
        if mode not in (0o600, 0o640):
            issues.append(
                f"backup.key mode {oct(mode)} (expected 0600/0640)"
            )
    if paths.host_secrets.exists():
        mode = paths.host_secrets.stat().st_mode & 0o777
        if mode != 0o600:
            issues.append(
                f"host secrets.env mode {oct(mode)} (expected 0600)"
            )
    if issues:
        return HealthCheck("permissions", "warn", "; ".join(issues))
    return HealthCheck("permissions", "ok", "Critical file permissions correct")


def check_age_key(paths: BoxPaths) -> HealthCheck:
    """Check if the age backup key is valid."""
    if not paths.backup_key.exists():
        return HealthCheck("age-key", "error", "Backup key not found")
    try:
        content = paths.backup_key.read_text()
    except (OSError, UnicodeDecodeError) as e:
        if isinstance(e, PermissionError) and os.geteuid() != 0:
            raise  # run_guarded: needs root
        return HealthCheck("age-key", "error", f"cannot read the backup key: {e}")
    if "AGE-SECRET-KEY-" not in content:
        return HealthCheck(
            "age-key", "error",
            "Backup key does not contain an age identity",
        )
    return HealthCheck("age-key", "ok", "Backup key valid")


def check_recent_errors(paths: BoxPaths) -> HealthCheck:
    """Scan operational log for recent errors."""
    from boxmunge.commands.log_cmd import query_log

    read = query_log(paths, level="error", since="24h")
    errors = read.entries

    if read.torn:
        return HealthCheck(
            "recent-errors", "warn",
            f"{len(errors)} error(s) in last 24h, and {len(read.torn)} torn "
            f"line(s) in the operational log that may have been errors (first: "
            f"{read.torn[0]}); `log --since 24h` lists them",
        )
    if len(errors) > 10:
        return HealthCheck(
            "recent-errors", "warn",
            f"{len(errors)} errors in last 24h",
        )
    if errors:
        return HealthCheck(
            "recent-errors", "ok",
            f"{len(errors)} error(s) in last 24h (within threshold)",
        )
    return HealthCheck("recent-errors", "ok", "No errors in last 24h")


def timeout_detail(e: subprocess.TimeoutExpired) -> str:
    """A timed-out probe's warning, naming the command."""
    cmd = " ".join(map(str, e.cmd)) if isinstance(e.cmd, (list, tuple)) else str(e.cmd)
    return (f"`{cmd}` did not answer within {e.timeout:g}s, so this could not be checked "
            f"(a busy host does this); run `health` again, and `doctor` if it repeats")


def run_guarded(name: str, check: Callable[[], HealthCheck], paths: BoxPaths) -> HealthCheck:
    """Run one check so that nothing it raises takes the report down.

    A timed-out probe warns, naming the command. A PermissionError from a
    non-root caller (the deploy shell) is a SKIP: the root health timer gives
    the verdict. Anything else is a defect in the check: it warns with the
    exception and is logged, so the operator sees it and can report it.
    """
    try:
        return check()
    except subprocess.TimeoutExpired as e:
        return HealthCheck(name, "warn", timeout_detail(e))
    except Exception as e:  # noqa: BLE001 -- reported below, never swallowed
        if isinstance(e, PermissionError) and os.geteuid() != 0:
            return HealthCheck(name, "skip", f"needs root ({e}); "
                               f"`sudo boxmunge-server health` checks it")
        from boxmunge.log import log_error
        message = f"the {name} check failed unexpectedly ({type(e).__name__}: {e})"
        log_error("health", message, paths)
        return HealthCheck(name, "warn", f"{message}; run `health` again, and report it "
                           f"with this line if it repeats")


def _ssh_port(paths: BoxPaths) -> int:
    from boxmunge.config import ConfigError, load_config
    from boxmunge.log import log_warning
    try:
        return load_config(paths).get("ssh_port", 922)
    except ConfigError as e:
        log_warning("health", f"could not load config, defaulting ssh_port=922: {e}", paths)
        return 922


def _checks(paths: BoxPaths) -> list[tuple[str, Callable[[], HealthCheck]]]:
    """(name, check) for every health check, in report order."""
    from boxmunge.health_checks import (
        alerts, container_updates, hardening, operational_log, os_updates,
        platform_updates, projects, registry, security, service_users, sshd,
        upgrade_probation, userns,
    )
    return [
        ("docker", check_docker_running),
        ("caddy", check_caddy_container),
        ("system-container", lambda: check_system_container(paths)),
        ("permissions", lambda: check_file_permissions(paths)),
        ("age-key", lambda: check_age_key(paths)),
        ("project-containers", lambda: projects.check_project_containers(paths)),
        ("lifecycle", lambda: projects.check_lifecycle_blocked(paths)),
        ("config-drift", lambda: projects.check_config_drift(paths)),
        ("recent-errors", lambda: check_recent_errors(paths)),
        ("operational-log", lambda: operational_log.check_operational_log(paths)),
        ("alerts", lambda: alerts.check_alerts(paths)),
        ("container-updates", lambda: container_updates.check_container_updates(paths)),
        ("platform-updates", lambda: platform_updates.check_platform_updates(paths)),
        ("upgrade-probation", lambda: upgrade_probation.check_upgrade_probation(paths)),
        ("docker-userns", lambda: userns.check_docker_userns(paths)),
        ("sshd-hardening", lambda: sshd.check_sshd_hardening()),
        ("sshd-deploy-env", lambda: sshd.check_sshd_deploy_env()),
        ("security-profiles", lambda: security.check_security_profiles(paths)),
        ("cve-scan", lambda: security.check_cve_scan_freshness(paths)),
        ("cve-hardening", lambda: security.check_cve_hardening_upcoming(paths)),
        ("service-users", lambda: service_users.check_service_users(paths)),
        ("registry", lambda: registry.check_registry_drift(paths)),
        ("ufw", lambda: hardening.check_ufw(ssh_port=_ssh_port(paths))),
        ("crowdsec", lambda: hardening.check_crowdsec()),
        ("aide", lambda: hardening.check_aide_status()),
        ("auditd", lambda: hardening.check_auditd()),
        ("auto-updates", lambda: os_updates.check_os_updates()),
        ("sysctl", lambda: hardening.check_sysctl_hardening()),
        ("timers", lambda: hardening.check_systemd_timers()),
    ]


def collect_health(paths: BoxPaths) -> HealthReport:
    """Run every health check. `health` and the MCP health tool both use this."""
    return HealthReport(checks=[run_guarded(name, check, paths)
                                for name, check in _checks(paths)])


def run_health(paths: BoxPaths, *, as_json: bool = False) -> int:
    """Run all health checks and report."""
    report = collect_health(paths)
    if as_json:
        print(report.format_json())
    else:
        print(report.format_text())

    return report.exit_code


def cmd_health(args: list[str]) -> None:
    """CLI entry point for health command."""
    from boxmunge.commands.argv import parse_args
    parsed = parse_args("health", args, flags={"--json"})
    paths = BoxPaths()
    sys.exit(run_health(paths, as_json=parsed.has("--json")))
