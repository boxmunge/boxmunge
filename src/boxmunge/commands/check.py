"""boxmunge check <project> — run health checks."""

import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from boxmunge.commands.argv import parse_args, require_project_name
from boxmunge.commands.health_state import (
    is_monitor_stopped, record_still_stopped, update_health_state,
)
from boxmunge.config import ConfigError, load_config
from boxmunge.docker_run import docker_env
from boxmunge.fileutil import project_lock, LockError
from boxmunge.fleet import PROJECT_INPUT_ERRORS, report_project_failure
from boxmunge.lifecycle import BlockReason, is_blocked
from boxmunge.log import log_error, log_operation
from boxmunge.manifest import load_manifest, ManifestError
from boxmunge.paths import BoxPaths


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


# Stderr signatures that mean the smoke test could not be RUN — the container
# is gone/renamed/not running, or `sh` could not open the script — as opposed
# to the app's smoke test running and reporting a problem. These are harness /
# infrastructure failures: they carry no signal about app health, so they must
# never escalate to CRITICAL (which stops+removes the container via the health
# monitor). Note `sh` exits 2 when it cannot open a script — colliding with the
# app-critical exit code — so exit code alone cannot distinguish them.
_HARNESS_FAILURE_SIGNATURES = (
    "no such container",
    "is not running",
    "is restarting",
    "cannot open",
    "can't open",
    "exec failed",
    "executable file not found",
    "oci runtime",
)


def _is_harness_failure(stderr: str) -> bool:
    """True if stderr indicates the smoke could not be run (not app-critical)."""
    low = stderr.lower()
    return any(sig in low for sig in _HARNESS_FAILURE_SIGNATURES)


def interpret_smoke_result(exit_code: int, stderr: str) -> SmokeResult:
    """Interpret a smoke test exit code and stderr into a SmokeResult."""
    message = parse_smoke_stderr(stderr)

    if exit_code == 0:
        return SmokeResult(status="ok", message="")
    # A failure whose stderr shows the smoke could not even run (container
    # gone, script unopenable) is downgraded to WARNING regardless of exit
    # code: it is an infrastructure fault, not evidence the app is unhealthy,
    # and must not trip the CRITICAL -> compose_down path that takes prod
    # offline. Surfaced (not silenced) so the operator still gets an alert.
    if exit_code != 0 and _is_harness_failure(stderr):
        return SmokeResult(
            status="warning",
            message=f"smoke could not run (infrastructure, not app): {message}",
        )
    if exit_code == 2:
        return SmokeResult(status="critical", message=message)
    else:
        return SmokeResult(status="warning", message=message)


def _smoke_one(container: str, script: str, svc_name: str) -> SmokeResult:
    cmd = ["docker", "exec", container, "sh", script, svc_name]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60,
                                env=docker_env())
    except subprocess.TimeoutExpired:
        return SmokeResult(
            status="warning",
            message=f"Smoke test for {svc_name} timed out (60s)",
        )
    except OSError as e:
        return SmokeResult(status="warning", message=f"Smoke test for {svc_name}: {e}")
    return interpret_smoke_result(result.returncode, result.stderr)


def _cannot_run(message: str) -> SmokeResult:
    """A smoke that could not be run says nothing about the app's health."""
    return SmokeResult(
        status="warning",
        message=f"smoke could not run (infrastructure, not app): {message}",
    )


def run_smoke_in_container(
    project_dir: Path,
    manifest: dict[str, Any],
    compose_files: list[str],
    project_name: str | None = None,
) -> SmokeResult:
    """Execute per-service smoke tests inside their running containers.

    Uses ``docker exec`` directly (not ``docker compose exec``) to avoid
    reading compose files — which would fail when the invoking user cannot
    read secrets.env. Containers are found by their Compose labels, which
    needs no compose file either; every running replica is tested.

    The compose overlay mounts the release's boxmunge-scripts/ at
    /boxmunge-scripts (production its own copy, so a stage cannot change
    it), and localhost:PORT naturally reaches the service.

    Returns the first failing result, or ok if all pass.
    """
    from boxmunge.docker_containers import running_by_service
    from boxmunge.docker_run import DockerError

    services = manifest.get("services", {})
    compose_project = project_name or manifest.get("project", project_dir.name)
    smoke_services = {n: s["smoke"] for n, s in services.items() if s.get("smoke")}
    if not smoke_services:
        return SmokeResult(status="ok", message="")
    try:
        targets = running_by_service(compose_project)
    except DockerError as e:
        return _cannot_run(f"cannot list the containers of {compose_project}: {e}")

    for svc_name, smoke in smoke_services.items():
        script = f"/boxmunge-scripts/{Path(smoke).name}"
        containers = targets.get(svc_name)
        if not containers:
            sr = _cannot_run(
                f"service {svc_name!r} has no running container in compose "
                f"project {compose_project!r}"
            )
        else:
            sr = SmokeResult(status="ok", message="")
            for container in containers:
                sr = _smoke_one(container, script, svc_name)
                if sr.status != "ok":
                    break

        if sr.status != "ok":
            # v0.9: enrich the failure message with a writable hint when
            # container logs show a read-only-fs error. Non-fatal — if
            # enrichment fails, return the original message unchanged.
            try:
                from boxmunge.writable_diagnostics import (
                    enrich_failure_with_writable_hint,
                )
                enriched = enrich_failure_with_writable_hint(
                    sr.message, project_dir, manifest, svc_name,
                )
                if enriched != sr.message:
                    sr = SmokeResult(status=sr.status, message=enriched)
            except Exception:
                pass
            return sr

    return SmokeResult(status="ok", message="")


def should_downgrade_smoke_failure(project_name: str, paths: BoxPaths) -> bool:
    """Return True if this is a first deploy (no deploy has been recorded).

    On first deploy, smoke test failures are downgraded from critical/failure
    to warning, since secrets and other config may not be fully in place yet.
    The state file alone is not evidence of a deploy: deploy registers the
    project's ULID there before the smoke test runs (audit D-36).
    """
    from boxmunge.state import read_state
    return "current_ref" not in read_state(paths.project_deploy_state(project_name))


def run_check(project_name: str, paths: BoxPaths, verbose: bool = True) -> int:
    """Run health checks on a project.

    Returns 0 if healthy, 1 if warning, 2 if critical.
    """
    project_dir = paths.project_dir(project_name)
    manifest_path = paths.project_manifest(project_name)

    if not project_dir.exists():
        if verbose:
            print(f"ERROR: Project not found: {project_name}", file=sys.stderr)
        return 1

    if paths.is_project_pre_registered(project_name):
        if verbose:
            print(f"ERROR: Project '{project_name}' is pre-registered (secrets set) but "
                  f"not yet deployed. Deploy first with: boxmunge deploy {project_name}", file=sys.stderr)
        return 1

    try:
        manifest = load_manifest(manifest_path)
    except ManifestError as e:
        if verbose:
            print(f"ERROR: {e}", file=sys.stderr)
        return 1

    if verbose:
        print(f"{project_name}: checking...")

    worst_status = 0

    # Surface security posture during routine checks.
    # - profile: off services produce a WARNING line (no exit-code escalation
    #   — the operator opted in with a reason; the deploy-time warning is the
    #   canonical alert, this is just routine visibility).
    # - per-flag overrides produce an INFO line so they are visible to a new
    #   operator scanning a project, without implying anything is wrong.
    # Default profile + no overrides produces no message (silent success).
    from boxmunge.security_overlay import (
        services_with_off_profile, services_with_overrides,
    )
    if verbose:
        for svc_name, reason in services_with_off_profile(manifest):
            reason_text = reason or "(no reason recorded)"
            print(
                f"  security: WARNING SECURITY OFF -- {svc_name} "
                f"(reason: {reason_text})"
            )
        for svc_name, diffs in services_with_overrides(manifest):
            print(
                f"  security: INFO override -- {svc_name} "
                f"({', '.join(diffs)})"
            )

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


_STATUS_FROM_EXIT = {0: "ok", 1: "warning", 2: "critical"}


def collect_check(project_name: str, paths: BoxPaths) -> dict[str, Any]:
    """Run the project's smoke checks and return the `check --json` payload.

    Schema:
      {"project": "X", "exit_code": 0, "status": "ok", "smoke": {"status": "...", "message": "..."}}

    The smoke object is omitted when no service in the manifest declares one.
    A project that cannot be checked gets exit_code 1 and an "error" message
    instead of status and smoke.
    """
    project_dir = paths.project_dir(project_name)
    manifest_path = paths.project_manifest(project_name)
    payload: dict[str, Any] = {"project": project_name}

    if not project_dir.exists():
        payload["exit_code"] = 1
        payload["error"] = f"Project not found: {project_name}"
        return payload

    if paths.is_project_pre_registered(project_name):
        payload["exit_code"] = 1
        payload["error"] = (
            f"Project '{project_name}' is pre-registered (secrets set) but "
            f"not yet deployed."
        )
        return payload

    try:
        manifest = load_manifest(manifest_path)
    except ManifestError as e:
        payload["exit_code"] = 1
        payload["error"] = str(e)
        return payload

    has_smoke = any(svc.get("smoke") for svc in manifest.get("services", {}).values())
    smoke_obj: dict[str, str] | None = None
    worst = 0
    if has_smoke:
        compose_files = ["compose.yml", "compose.boxmunge.yml"]
        result = run_smoke_in_container(project_dir, manifest, compose_files)
        smoke_obj = {"status": result.status, "message": result.message}
        if result.status == "critical":
            worst = 2
        elif result.status == "warning":
            worst = 1

    payload["exit_code"] = worst
    payload["status"] = _STATUS_FROM_EXIT.get(worst, "unknown")
    if smoke_obj is not None:
        payload["smoke"] = smoke_obj
    return payload


def _run_check_json(project_name: str, paths: BoxPaths) -> int:
    """Emit the check payload as a single JSON object on stdout."""
    payload = collect_check(project_name, paths)
    print(json.dumps(payload))
    return payload["exit_code"]


def cmd_check(args: list[str]) -> None:
    """CLI entry point for check command."""
    parsed = parse_args(
        "check", args, flags={"--json"}, min_positional=1, max_positional=1,
    )
    project = require_project_name("check", parsed.positional[0])
    paths = BoxPaths()
    if parsed.has("--json"):
        sys.exit(_run_check_json(project, paths))
    sys.exit(run_check(project, paths))


def run_check_all(paths: BoxPaths, *, read_only: bool) -> int:
    """Run health checks across every project.

    Default mode (mutator): writes health state, may call ``compose_down``
    on critical results, and emits Pushover notifications. This is the
    form the systemd timer drives.

    ``read_only``: run the same per-project checks and print the report,
    but skip every side effect — no state writes, no container stops,
    no notifications. The exit code still reflects the worst severity.

    A project whose inputs cannot be read (manifest, state files) is
    reported on stderr and in the log, and the loop carries on with the
    rest. An unusable host config is reported the same way.

    Returns the worst per-project status (0 ok, 1 warning, 2 critical),
    and at least 1 if any project could not be checked.
    """
    worst = 0
    failed: list[str] = []
    if not read_only and not _host_config_usable(paths):
        worst = 1
    projects_dir = paths.projects
    if not projects_dir.exists():
        print("No projects directory.")
        return 0

    projects = sorted(
        p.name for p in projects_dir.iterdir()
        if p.is_dir() and (p / "manifest.yml").exists()
    )

    if not projects:
        print("No projects to check.")
        return worst

    for name in projects:
        try:
            worst = max(worst, _check_project(name, paths, read_only))
        except PROJECT_INPUT_ERRORS as e:
            report_project_failure("check-all", name, e, paths)
            failed.append(name)

    if failed:
        print(
            f"ERROR: check-all: {len(failed)} project(s) could not be "
            f"checked: {', '.join(failed)}",
            file=sys.stderr,
        )
        worst = max(worst, 1)
    return worst


def _host_config_usable(paths: BoxPaths) -> bool:
    """Report an unusable host config loudly. Alerts depend on it."""
    try:
        load_config(paths)
    except ConfigError as e:
        print(f"ERROR: check-all: alerts cannot be sent: {e}", file=sys.stderr)
        log_error("check-all", f"alerts cannot be sent: {e}", paths)
        return False
    return True


def _check_project(name: str, paths: BoxPaths, read_only: bool) -> int:
    """Check one project unless it is blocked or locked. Returns its status."""
    # A blocked (paused or CVE-quarantined) project is intentionally
    # stopped. Running smoke (which depends on a live container)
    # would fail, escalate to alerts via update_health_state, and
    # possibly call compose_down on an already-stopped project.
    # Quarantine adds a structured log entry; paused historically
    # did not (preserved).
    block = is_blocked(name, paths)
    if block:
        if block.reason is BlockReason.QUARANTINED:
            log_operation(
                "check-all", block.skip_message,
                paths, project=name,
            )
        return 0

    # Maintenance window: a deploy/stage/promote/restore in progress
    # holds the project lock. Stage transiently stops the prod container
    # to snapshot its data; a smoke run racing that transient state
    # escalates to CRITICAL and calls compose_down, leaving production
    # OFFLINE until the next promote. Hold the lock for the whole check
    # so we either skip (op in progress) or run with no lifecycle op
    # able to start underneath us — never act on a transient state.
    try:
        with project_lock(name, paths):
            return _check_one(name, paths, read_only)
    except LockError:
        log_operation(
            "check-all",
            "skipped — lifecycle operation in progress (lock held)",
            paths, project=name,
        )
        return 0


def _check_one(name: str, paths: BoxPaths, read_only: bool) -> int:
    """Run a single project's check (caller holds the project lock).

    An unreadable manifest is fed to the health state machine as a
    warning carrying the cause (so the normal threshold alert fires
    instead of the project silently dropping out of monitoring), then
    re-raised for the fleet loop to report.
    """
    # The monitor removed this project's containers after a critical
    # result. Running smoke now would only report "No such container" and
    # overwrite the real stop reason; the stop stands until recover or a
    # successful deploy (audit C-04).
    if is_monitor_stopped(name, paths):
        print(f"{name}: CRITICAL (stopped by the health monitor; "
              f"run 'boxmunge recover {name}' or redeploy)")
        if not read_only:
            record_still_stopped(name, paths)
        return 2
    try:
        manifest = load_manifest(paths.project_manifest(name))
    except ManifestError as e:
        if not read_only:
            update_health_state(name, 1, str(e), paths)
        raise

    result = run_check(name, paths)

    if not read_only:
        # Mutator path: also runs the smoke a second time to capture
        # the failure message for Pushover. Skipped under --read-only
        # because there is no state to update and no alert to send.
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

    return result


def cmd_check_all(args: list[str]) -> None:
    """CLI entry point for check-all command.

    Without --read-only this is the timer-driven mutator: it writes per-
    project health state, can call compose_down on critical results, and
    emits Pushover notifications. With --read-only it only prints the
    report; no side effects. Any other argument is a usage error, so a
    mistyped --read-only can never fall through to the mutator (audit D-04).
    """
    parsed = parse_args("check-all", args, flags={"--read-only"})
    paths = BoxPaths()
    sys.exit(run_check_all(paths, read_only=parsed.has("--read-only")))
