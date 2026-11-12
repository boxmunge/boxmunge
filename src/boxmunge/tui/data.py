"""TUI data loading — pure functions, no Textual dependency.

Reads boxmunge state files, manifests, and system info to provide
data for the TUI screens.
"""

import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone

from boxmunge import compose_inventory
from boxmunge.config import read_config, ConfigError
from boxmunge.docker_run import DockerError, docker_env
from boxmunge.manifest import load_manifest, ManifestError
from boxmunge.paths import BoxPaths
from boxmunge.state import StateError, read_state


@dataclass
class ProjectStatus:
    name: str
    status: str
    last_check: str
    deployed_at: str
    current_ref: str
    failure_reason: str


@dataclass
class HostInfo:
    hostname: str
    disk_free_gb: float
    caddy_running: bool
    # Why boxmunge.yml cannot be loaded, or which of its settings are
    # wrong; empty when it is sound.
    config_error: str = ""


@dataclass
class ServiceInfo:
    name: str
    svc_type: str
    port: int
    route: str
    docker_health: str | None


@dataclass
class BackupInfo:
    filename: str
    size_bytes: int
    modified: str


def relative_time(iso_timestamp: str) -> str:
    """Convert an ISO timestamp to a human-readable relative time string."""
    if not iso_timestamp or iso_timestamp == "-":
        return "-"

    try:
        then = datetime.fromisoformat(iso_timestamp)
        if then.tzinfo is None:
            then = then.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        delta = now - then
        seconds = int(delta.total_seconds())

        if seconds < 60:
            return "just now"
        elif seconds < 3600:
            return f"{seconds // 60}m ago"
        elif seconds < 86400:
            return f"{seconds // 3600}h ago"
        else:
            return f"{seconds // 86400}d ago"
    except (ValueError, TypeError):
        return "-"


def load_all_project_status(paths: BoxPaths) -> list[ProjectStatus]:
    """Load status for all registered projects."""
    projects_dir = paths.projects
    if not projects_dir.exists():
        return []

    results = []
    for pdir in sorted(projects_dir.iterdir()):
        if not pdir.is_dir() or not (pdir / "manifest.yml").exists():
            continue

        name = pdir.name
        try:
            health = read_state(paths.project_health_state(name))
            deploy = read_state(paths.project_deploy_state(name))
        except StateError as e:
            # Show the broken project as an error row rather than letting
            # one corrupt file take down the whole console.
            results.append(ProjectStatus(
                name=name, status="error", last_check="", deployed_at="",
                current_ref="", failure_reason=str(e),
            ))
            continue

        results.append(ProjectStatus(
            name=name,
            status=health.get("status", "unknown"),
            last_check=health.get("last_check", ""),
            deployed_at=deploy.get("deployed_at", ""),
            current_ref=deploy.get("current_ref", ""),
            failure_reason=health.get("failure_reason", ""),
        ))

    return results


def load_host_info(paths: BoxPaths) -> HostInfo:
    """Load host-level information."""
    try:
        config, problems = read_config(paths)
        hostname = str(config["hostname"])
        config_error = "; ".join(p.message for p in problems)
    except ConfigError as e:
        hostname, config_error = "unknown", str(e)

    try:
        usage = shutil.disk_usage(paths.root)
        disk_free_gb = round(usage.free / (1024**3), 1)
    except OSError:
        disk_free_gb = 0.0

    # Polled every 10 s: one `docker ps` for the platform's caddy project,
    # no compose file parsed. Docker not answering shows as stopped.
    try:
        caddy_running = compose_inventory.running_inventory("caddy").is_running("caddy", "caddy")
    except (DockerError, OSError):
        caddy_running = False

    return HostInfo(
        hostname=hostname,
        disk_free_gb=disk_free_gb,
        caddy_running=caddy_running,
        config_error=config_error,
    )


def load_project_services(paths: BoxPaths, project: str) -> list[ServiceInfo]:
    """Load service info for a project from its manifest."""
    try:
        manifest = load_manifest(paths.project_manifest(project))
    except ManifestError:
        return []

    services = manifest.get("services", {})
    health = _docker_health([f"{project}-{name}-1" for name in services])
    results = []
    for svc_name, svc in services.items():
        routes = svc.get("routes", [])
        if routes and isinstance(routes[0], dict):
            route_str = routes[0].get("path", "")
        elif routes and isinstance(routes[0], str):
            route_str = routes[0]
        else:
            route_str = ""

        results.append(ServiceInfo(
            name=svc_name,
            svc_type=svc.get("type", ""),
            port=svc.get("port", 0),
            route=route_str,
            docker_health=health.get(f"{project}-{svc_name}-1"),
        ))

    return results


def _docker_health(containers: list[str]) -> dict[str, str]:
    """{container: its healthcheck status}, from one `docker inspect` of them
    all. A container that is missing or has no healthcheck is left out."""
    if not containers:
        return {}
    try:
        r = subprocess.run(
            ["docker", "inspect", "--format",
             "{{.Name}}\t{{if .State.Health}}{{.State.Health.Status}}{{end}}", *containers],
            capture_output=True, text=True, check=False, env=docker_env(),
        )
    except OSError:
        return {}
    # A missing container makes inspect exit 1 after describing the others.
    found = (line.split("\t", 1) for line in r.stdout.splitlines() if "\t" in line)
    return {name.lstrip("/"): status for name, status in found if status}


def load_project_backups(paths: BoxPaths, project: str) -> list[BackupInfo]:
    """Load backup info for a project, newest first."""
    bdir = paths.project_backups(project)
    if not bdir.exists():
        return []

    results = []
    for f in sorted(bdir.glob(f"{project}-*.tar.gz.age"),
                    key=lambda p: p.stat().st_mtime, reverse=True):
        stat = f.stat()
        modified = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()
        results.append(BackupInfo(
            filename=f.name,
            size_bytes=stat.st_size,
            modified=modified,
        ))

    return results
