"""boxmunge check <project> — run health checks."""

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from boxmunge.config import load_config, ConfigError
from boxmunge.docker import compose_down, DockerError
from boxmunge.log import log_operation, log_warning, log_error
from boxmunge.manifest import load_manifest, ManifestError
from boxmunge.paths import BoxPaths
from boxmunge.pushover import format_alert, format_recovery, send_notification
from boxmunge.state import read_state, write_state


@dataclass
class SmokeResult:
    status: str  # "ok", "warning", "critical"
    message: str


def parse_smoke_stderr(stderr: str) -> str:
    """Parse smoke test stderr according to the boxmunge contract."""
    lines = [line.strip() for line in stderr.splitlines() if line.strip()]

    if not lines:
        return "Smoke check failed (no detail provided)"
    if len(lines) == 1:
        return lines[0]
    return "Manual failure analysis required (smoke script produced multiple lines)"


def interpret_smoke_result(exit_code: int, stderr: str) -> SmokeResult:
    """Interpret a smoke test exit code and stderr into a SmokeResult."""
    message = parse_smoke_stderr(stderr)

    if exit_code == 0:
        return SmokeResult(status="ok", message="")
    elif exit_code == 2:
        return SmokeResult(status="critical", message=message)
    else:
        return SmokeResult(status="warning", message=message)


def _container_name(project_name: str, svc_name: str) -> str:
    """Derive the Docker container name from project and service name."""
    return f"{project_name}-{svc_name}-1"


def run_smoke_in_container(
    project_dir: Path,
    manifest: dict[str, Any],
    compose_files: list[str],
    project_name: str | None = None,
) -> SmokeResult:
    """Execute per-service smoke tests inside their respective containers.

    Uses ``docker exec`` directly (not ``docker compose exec``) to avoid
    reading compose files — which would fail when the invoking user cannot
    read secrets.env.

    The compose overlay mounts ./boxmunge-scripts into the container, so
    localhost:PORT naturally reaches the service.

    Returns the first failing result, or ok if all pass.
    """
    services = manifest.get("services", {})
    compose_project = project_name or manifest.get("project", project_dir.name)

    for svc_name, svc in services.items():
        smoke = svc.get("smoke", "")
        if not smoke:
            continue

        script_name = Path(smoke).name
        container_script = f"/boxmunge-scripts/{script_name}"
        container = _container_name(compose_project, svc_name)

        cmd = ["docker", "exec", container, "sh", container_script, svc_name]

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60,
            )
            sr = interpret_smoke_result(result.returncode, result.stderr)
        except subprocess.TimeoutExpired:
            sr = SmokeResult(
                status="warning",
                message=f"Smoke test for {svc_name} timed out (60s)",
            )
        except OSError as e:
            sr = SmokeResult(
                status="warning",
                message=f"Smoke test for {svc_name}: {e}",
            )

        if sr.status != "ok":
            return sr

    return SmokeResult(status="ok", message="")


def should_downgrade_smoke_failure(project_name: str, paths: BoxPaths) -> bool:
    """Return True if this is a first deploy (no deploy state exists).

    On first deploy, smoke test failures are downgraded from critical/failure
    to warning, since secrets and other config may not be fully in place yet.
    """
    state_path = paths.project_deploy_state(project_name)
    return not state_path.exists()


def run_check(project_name: str, paths: BoxPaths, verbose: bool = True) -> int:
    """Run health checks on a project.

    Returns 0 if healthy, 1 if warning, 2 if critical.
    """
    project_dir = paths.project_dir(project_name)
    manifest_path = paths.project_manifest(project_name)

    if not project_dir.exists():
        if verbose:
            print(f"ERROR: Project not found: {project_name}")
        return 1

    if paths.is_project_pre_registered(project_name):
        if verbose:
            print(f"ERROR: Project '{project_name}' is pre-registered (secrets set) but "
                  f"not yet deployed. Deploy first with: boxmunge deploy {project_name}")
        return 1

    try:
        manifest = load_manifest(manifest_path)
    except ManifestError as e:
        if verbose:
            print(f"ERROR: {e}")
        return 1

    if verbose:
        print(f"{project_name}: checking...")

    worst_status = 0

    # Per-service smoke tests — exec inside each container
    has_smoke = any(svc.get("smoke") for svc in manifest.get("services", {}).values())
    if has_smoke:
        compose_files = ["compose.yml", "compose.boxmunge.yml"]
        result = run_smoke_in_container(
            project_dir, manifest, compose_files,
        )
        if verbose:
            if result.status == "ok":
                print(f"  smoke:    in-container -> passed")
            else:
                print(f"  smoke:    in-container -> {result.status}: {result.message}")
        if result.status == "critical":
            worst_status = max(worst_status, 2)
        elif result.status == "warning":
            worst_status = max(worst_status, 1)

    if verbose:
        if worst_status == 0:
            print(f"{project_name}: OK")
        elif worst_status == 1:
            print(f"{project_name}: WARNING")
        else:
            print(f"{project_name}: CRITICAL")

    return worst_status


def update_health_state(
    project_name: str,
    check_result: int,
    message: str,
    paths: BoxPaths,
) -> None:
    """Update health state and send alerts as needed.

    check_result: 0=ok, 1=warning, 2=critical
    """
    from datetime import datetime, timezone

    state_path = paths.project_health_state(project_name)
    state = read_state(state_path)
    now = datetime.now(timezone.utc).isoformat()

    try:
        config = load_config(paths)
    except ConfigError:
        config = {}

    threshold = config.get("health", {}).get("alert_threshold", 3)
    pushover = config.get("pushover", {})
    user_key = pushover.get("user_key", "")
    app_token = pushover.get("app_token", "")

    prev_status = state.get("status", "ok")
    prev_message = state.get("failure_reason", "")
    consecutive = state.get("consecutive_failures", 0)
    alerted = state.get("alerted", False)

    if check_result == 0:
        # Recovery
        if prev_status != "ok" and alerted:
            title, body = format_recovery(project_name)
            send_notification(user_key, app_token, title, body)
            log_operation("health", "Recovered — alert cleared", paths, project=project_name)

        write_state(state_path, {
            "last_check": now,
            "status": "ok",
            "consecutive_failures": 0,
            "alerted": False,
            "last_alert": state.get("last_alert", ""),
            "last_success": now,
            "failure_reason": "",
        })
        return

    # Failure path
    consecutive += 1

    if check_result == 2:
        # Critical — alert immediately, stop containers
        title, body = format_alert(project_name, "critical", message)
        send_notification(user_key, app_token, title, body, priority=1)
        log_error("health", f"CRITICAL: {message} — stopping containers", paths, project=project_name)

        project_dir = paths.project_dir(project_name)
        try:
            compose_down(project_dir)
        except DockerError:
            pass

        write_state(state_path, {
            "last_check": now,
            "status": "critical_stopped",
            "consecutive_failures": consecutive,
            "alerted": True,
            "last_alert": now,
            "last_success": state.get("last_success", ""),
            "failure_reason": message,
        })
        return

    # Warning — alert after threshold
    should_alert = False
    if consecutive >= threshold and not alerted:
        should_alert = True
    elif alerted and message != prev_message:
        should_alert = True  # Message changed — re-alert

    if should_alert:
        title, body = format_alert(project_name, "warning", message)
        send_notification(user_key, app_token, title, body)
        log_warning("health", f"Alert sent: {message}", paths, project=project_name)

    write_state(state_path, {
        "last_check": now,
        "status": "failing",
        "consecutive_failures": consecutive,
        "alerted": alerted or should_alert,
        "last_alert": now if should_alert else state.get("last_alert", ""),
        "last_success": state.get("last_success", ""),
        "failure_reason": message,
    })


def cmd_check(args: list[str]) -> None:
    """CLI entry point for check command."""
    if not args:
        print("Usage: boxmunge check <project>", file=sys.stderr)
        sys.exit(2)

    from boxmunge.paths import validate_project_name
    try:
        validate_project_name(args[0])
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(2)

    paths = BoxPaths()
    sys.exit(run_check(args[0], paths))


def cmd_check_all(args: list[str]) -> None:
    """CLI entry point for check-all command."""
    paths = BoxPaths()
    worst = 0
    projects_dir = paths.projects
    if not projects_dir.exists():
        print("No projects directory.")
        sys.exit(0)

    projects = sorted(
        p.name for p in projects_dir.iterdir()
        if p.is_dir() and (p / "manifest.yml").exists()
    )

    if not projects:
        print("No projects to check.")
        sys.exit(0)

    for name in projects:
        result = run_check(name, paths)

        # Determine message from smoke test
        try:
            manifest = load_manifest(paths.project_manifest(name))
        except ManifestError:
            manifest = {}
        message = ""
        if result != 0:
            has_smoke = any(
                svc.get("smoke") for svc in manifest.get("services", {}).values()
            )
            if has_smoke:
                project_dir = paths.project_dir(name)
                compose_files = ["compose.yml", "compose.boxmunge.yml"]
                sr = run_smoke_in_container(
                    project_dir, manifest, compose_files,
                )
                message = sr.message

        update_health_state(name, result, message, paths)
        worst = max(worst, result)

    sys.exit(worst)
