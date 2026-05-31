# SPDX-License-Identifier: Apache-2.0
"""boxmunge health -- non-destructive platform health audit.

Checks system configuration, component health, config drift, and
recent log patterns. No writes, no restarts.
"""

import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from boxmunge.cve.quarantine import is_quarantined, read_quarantine_state
from boxmunge.lifecycle import is_blocked
from boxmunge.pause import is_paused
from boxmunge.paths import BoxPaths


@dataclass
class HealthCheck:
    name: str
    status: str  # "ok", "warn", "error"
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
            icon = {"ok": "OK", "warn": "WARN", "error": "ERR"}[check.status]
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

    def format_json(self) -> str:
        return json.dumps({
            "healthy": self.exit_code == 0,
            "exit_code": self.exit_code,
            "checks": [
                {"name": c.name, "status": c.status, "detail": c.detail}
                for c in self.checks
            ],
        }, indent=2)


def check_docker_running() -> HealthCheck:
    """Check if Docker daemon is running."""
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True, text=True, check=False, timeout=10,
        )
        if result.returncode == 0:
            return HealthCheck("docker", "ok", "Docker daemon running")
        return HealthCheck("docker", "error", "Docker daemon not responding")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return HealthCheck("docker", "error", "Docker not found or timed out")


def check_caddy_container() -> HealthCheck:
    """Check if Caddy container is running and healthy."""
    try:
        result = subprocess.run(
            ["docker", "inspect", "--format",
             "{{.State.Health.Status}}", "boxmunge-caddy"],
            capture_output=True, text=True, check=False, timeout=10,
        )
        status = result.stdout.strip()
        if status == "healthy":
            return HealthCheck("caddy", "ok", "Caddy container healthy")
        if result.returncode != 0:
            return HealthCheck("caddy", "error", "Caddy container not found")
        return HealthCheck("caddy", "warn", f"Caddy container status: {status}")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return HealthCheck("caddy", "error", "Could not check Caddy container")


def check_system_container() -> HealthCheck:
    """Check if boxmunge-system container is running."""
    try:
        result = subprocess.run(
            ["docker", "inspect", "--format",
             "{{.State.Status}}", "boxmunge-system"],
            capture_output=True, text=True, check=False, timeout=10,
        )
        if result.returncode == 0 and "running" in result.stdout:
            return HealthCheck(
                "system-container", "ok", "boxmunge-system running",
            )
        return HealthCheck(
            "system-container", "warn",
            "boxmunge-system not running (host fallback active)",
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return HealthCheck(
            "system-container", "warn",
            "Could not check system container",
        )


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
    content = paths.backup_key.read_text()
    if "AGE-SECRET-KEY-" not in content:
        return HealthCheck(
            "age-key", "error",
            "Backup key does not contain an age identity",
        )
    return HealthCheck("age-key", "ok", "Backup key valid")


def check_project_containers(paths: BoxPaths) -> HealthCheck:
    """Check if all deployed projects have running containers.

    Projects in operator/system-blocked lifecycle states (paused,
    CVE-quarantined) are excluded from the container check itself —
    surfacing them as "no running containers" would mis-attribute an
    intentional offline state as a health failure. The OK message
    distinguishes total deployed from actually-checked so the operator
    can see at a glance whether the all-green claim covers everything.
    The blocked projects themselves are reported by `lifecycle`.
    """
    if not paths.projects.exists():
        return HealthCheck("project-containers", "ok", "No projects deployed")

    projects = [
        p.name for p in paths.projects.iterdir()
        if p.is_dir() and (p / "manifest.yml").exists()
    ]
    if not projects:
        return HealthCheck("project-containers", "ok", "No projects deployed")

    down_projects = []
    blocked_count = 0
    for name in projects:
        if is_blocked(name, paths):
            blocked_count += 1
            continue
        compose_cmd = ["docker", "compose", "-f", "compose.yml"]
        override = paths.project_compose_override(name)
        if override.exists():
            compose_cmd.extend(["-f", "compose.boxmunge.yml"])
        compose_cmd.extend(["ps", "--format", "json"])
        result = subprocess.run(
            compose_cmd,
            cwd=paths.project_dir(name), capture_output=True, text=True,
            check=False, timeout=10,
        )
        if result.returncode != 0 or not result.stdout.strip():
            down_projects.append(name)

    if down_projects:
        return HealthCheck(
            "project-containers", "warn",
            f"Projects with no running containers: {', '.join(down_projects)}",
        )
    checked = len(projects) - blocked_count
    if blocked_count:
        detail = (
            f"All {checked} checked project(s) have running containers "
            f"({blocked_count} blocked — see `lifecycle`)"
        )
    else:
        detail = f"All {checked} project(s) have running containers"
    return HealthCheck("project-containers", "ok", detail)


def check_lifecycle_blocked(paths: BoxPaths) -> HealthCheck:
    """Surface projects in paused or CVE-quarantined states.

    Quarantined projects warn — they're offline due to an unfixed CVE
    and may surprise an operator who only glanced at the report.
    Paused projects pass as OK with a note — that's an intentional
    operator action, not a problem.

    Without this check the broader health report says nothing about
    blocked projects; `project-containers` excludes them by design, so
    a quarantined site can be silently offline while the report reads
    HEALTHY.
    """
    if not paths.projects.exists():
        return HealthCheck("lifecycle", "ok", "No projects deployed")
    paused: list[str] = []
    quarantined: list[tuple[str, str]] = []
    for proj_dir in sorted(paths.projects.iterdir()):
        if not proj_dir.is_dir() or not (proj_dir / "manifest.yml").exists():
            continue
        name = proj_dir.name
        # Mirrors lifecycle.is_blocked precedence: quarantine wins if
        # both markers exist.
        if is_quarantined(name, paths):
            qstate = read_quarantine_state(name, paths) or {}
            cve = qstate.get("cve_id", "?")
            quarantined.append((name, cve))
        elif is_paused(name, paths):
            paused.append(name)
    parts: list[str] = []
    if quarantined:
        parts.append(
            "quarantined: "
            + ", ".join(f"{n} ({c})" for n, c in quarantined)
        )
    if paused:
        parts.append("paused: " + ", ".join(paused))
    if quarantined:
        return HealthCheck("lifecycle", "warn", "; ".join(parts))
    if paused:
        return HealthCheck("lifecycle", "ok", "; ".join(parts))
    return HealthCheck("lifecycle", "ok", "No projects in blocked states")


def check_config_drift(paths: BoxPaths) -> HealthCheck:
    """Check if generated configs match what they should be."""
    from boxmunge.caddy import generate_caddy_config
    from boxmunge.manifest import ManifestError, load_manifest

    if not paths.projects.exists():
        return HealthCheck("config-drift", "ok", "No projects to check")

    drifted = []
    for project_dir in sorted(paths.projects.iterdir()):
        if not project_dir.is_dir():
            continue
        manifest_path = project_dir / "manifest.yml"
        if not manifest_path.exists():
            continue
        try:
            manifest = load_manifest(manifest_path)
        except ManifestError:
            continue

        project_name = manifest.get("project", project_dir.name)
        # Skip blocked projects: when paused/quarantined the .conf
        # intentionally holds the maintenance fragment, so comparing
        # against generate_caddy_config produces a false-positive drift
        # warning. The blocked state itself is reported by `lifecycle`.
        if is_blocked(project_name, paths):
            continue
        site_conf = paths.project_caddy_site(project_name)
        override = paths.project_caddy_override(project_name)

        if site_conf.exists() and not override.exists():
            expected = generate_caddy_config(manifest)
            if site_conf.read_text() != expected:
                drifted.append(project_name)

    if drifted:
        return HealthCheck(
            "config-drift", "warn",
            f"Caddy config drifted for: {', '.join(drifted)}",
        )
    return HealthCheck("config-drift", "ok", "All generated configs match")


def check_recent_errors(paths: BoxPaths) -> HealthCheck:
    """Scan operational log for recent errors."""
    from boxmunge.commands.log_cmd import filter_log_entries, parse_log_file

    entries = parse_log_file(paths.log_file)
    errors = filter_log_entries(entries, level="error", since="24h")

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


def run_health(paths: BoxPaths, *, as_json: bool = False) -> int:
    """Run all health checks and report."""
    report = HealthReport()
    report.checks.append(check_docker_running())
    report.checks.append(check_caddy_container())
    report.checks.append(check_system_container())
    report.checks.append(check_file_permissions(paths))
    report.checks.append(check_age_key(paths))
    report.checks.append(check_project_containers(paths))
    report.checks.append(check_lifecycle_blocked(paths))
    report.checks.append(check_config_drift(paths))
    report.checks.append(check_recent_errors(paths))

    from boxmunge.health_checks.container_updates import check_container_updates
    report.checks.append(check_container_updates(paths))

    from boxmunge.health_checks.security import check_security_profiles
    report.checks.append(check_security_profiles(paths))

    # Host hardening checks
    from boxmunge.health_checks.hardening import (
        check_aide_status,
        check_auditd,
        check_crowdsec,
        check_sysctl_hardening,
        check_systemd_timers,
        check_ufw,
        check_unattended_upgrades,
    )

    from boxmunge.config import ConfigError, load_config
    from boxmunge.log import log_warning

    try:
        config = load_config(paths)
        ssh_port = config.get("ssh_port", 922)
    except ConfigError as e:
        log_warning(
            "health",
            f"could not load config, defaulting ssh_port=922: {e}",
            paths,
        )
        ssh_port = 922

    report.checks.append(check_ufw(ssh_port=ssh_port))
    report.checks.append(check_crowdsec())
    report.checks.append(check_aide_status())
    report.checks.append(check_auditd())
    report.checks.append(check_unattended_upgrades())
    report.checks.append(check_sysctl_hardening())
    report.checks.append(check_systemd_timers())

    if as_json:
        print(report.format_json())
    else:
        print(report.format_text())

    return report.exit_code


def cmd_health(args: list[str]) -> None:
    """CLI entry point for health command."""
    as_json = "--json" in args
    paths = BoxPaths()
    sys.exit(run_health(paths, as_json=as_json))
