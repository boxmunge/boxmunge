"""boxmunge check <project> — run health checks."""

import json
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from boxmunge import compose_inventory
from boxmunge.commands.argv import parse_args, require_project_name
from boxmunge.commands.smoke_result import SmokeResult, interpret_smoke_result
from boxmunge.docker_run import docker_env
from boxmunge.manifest import load_manifest, ManifestError
from boxmunge.paths import BoxPaths

if TYPE_CHECKING:
    from boxmunge.compose_inventory import RunningInventory
    from boxmunge.staged_release import ComposeTarget

    # The containers running on the box, listed once per check-all tick.
    TickListing = Callable[[], RunningInventory]


# In the smoke's environment on check-all's tick only: every other smoke run
# gates something, so an alert-only check runs under this (PROJECT_CONVENTIONS.md).
PERIODIC_ENV = "BOXMUNGE_CHECK=periodic"


def _smoke_one(container: str, script: str, svc_name: str,
               periodic: bool = False) -> SmokeResult:
    env = ["-e", PERIODIC_ENV] if periodic else []
    cmd = ["docker", "exec", *env, container, "sh", script, svc_name]
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


def _logs_through(target: "ComposeTarget | None") -> Callable[[str], str] | None:
    if target is None:
        return None
    from boxmunge.docker import compose_logs_capture

    def fetch(service: str) -> str:
        return compose_logs_capture(target.cwd, service=service, **target.kwargs())
    return fetch


def run_smoke_in_container(
    project_dir: Path,
    manifest: dict[str, Any],
    compose_files: list[str],
    project_name: str | None = None,
    *,
    logs_target: "ComposeTarget | None" = None,
    hint: "Callable[[str], str | None] | None" = None,
    periodic: bool = False,
    tick: "TickListing | None" = None,
) -> SmokeResult:
    """Execute per-service smoke tests inside their running containers.

    Uses ``docker exec`` directly (not ``docker compose exec``) to avoid
    reading compose files — which would fail when the invoking user cannot
    read secrets.env. Containers are found by their Compose labels, which
    needs no compose file either; every running replica is tested.

    The compose overlay mounts boxmunge-scripts/ at /boxmunge-scripts: each
    environment mounts its own release's boxmunge-scripts/ (production's
    project dir, staging's slot), and localhost:PORT naturally reaches the
    service.

    A failure's writable hint reads the service's logs through
    ``logs_target`` (staging passes its slot target); without one, through
    production's compose files in ``project_dir``. ``hint(service)`` may add
    a line about the failing service (deploy's default-user hint).
    ``periodic`` (check-all's tick only) sets PERIODIC_ENV in the script's
    environment.

    ``tick`` is check-all's listing of the whole box, taken once per tick;
    without it the project's own containers are listed.

    Returns the first failing result, or ok if all pass.
    """
    from boxmunge.docker_run import DockerError

    services = manifest.get("services", {})
    compose_project = project_name or manifest.get("project", project_dir.name)
    smoke_services = {n: s["smoke"] for n, s in services.items() if s.get("smoke")}
    if not smoke_services:
        return SmokeResult(status="ok", message="")

    def listed() -> dict[str, list[str]]:
        return compose_inventory.running_inventory(compose_project).services(compose_project)

    try:
        targets = listed() if tick is None else tick().services(compose_project)
        if tick is not None and not smoke_services.keys() <= targets.keys():
            # The tick's listing predates this project's lock: a deploy that
            # ended since may have recreated the service. Ask before saying
            # it has no container.
            targets = listed()
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
                sr = _smoke_one(container, script, svc_name, periodic)
                if sr.status != "ok":
                    break

        if sr.status != "ok":
            from boxmunge.writable_diagnostics import smoke_failure_message
            message = smoke_failure_message(sr.message, project_dir, manifest, svc_name,
                                            _logs_through(logs_target))
            extra = hint(svc_name) if hint is not None else None
            return SmokeResult(status=sr.status,
                               message=f"{message}\n{extra}" if extra else message)

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
    return check_with_reason(project_name, paths, verbose)[0]


def check_with_reason(project_name: str, paths: BoxPaths, verbose: bool = True,
                      *, periodic: bool = False,
                      tick: "TickListing | None" = None) -> tuple[int, str]:
    """run_check's status, and the smoke message that decided it ("" when
    smoke passed or did not run): check-all records the very failure that
    set the status, from the one smoke run. check-all alone passes
    ``periodic`` and ``tick`` (run_smoke_in_container)."""
    project_dir = paths.project_dir(project_name)
    manifest_path = paths.project_manifest(project_name)

    if not project_dir.exists():
        if verbose:
            print(f"ERROR: Project not found: {project_name}", file=sys.stderr)
        return 1, ""

    if paths.is_project_pre_registered(project_name):
        if verbose:
            print(f"ERROR: Project '{project_name}' is pre-registered (secrets set) but "
                  f"not yet deployed. Upload its first bundle, then deploy it with: "
                  f"boxmunge prod-deploy {project_name}", file=sys.stderr)
        return 1, ""

    try:
        manifest = load_manifest(manifest_path)
    except ManifestError as e:
        if verbose:
            print(f"ERROR: {e}", file=sys.stderr)
        return 1, ""

    if verbose:
        print(f"{project_name}: checking...")
        # Not a health result: the running containers are fine, the next
        # deploy is not. Reported on every check until it is re-linked.
        from boxmunge.git_layout import relink_advice, unlinked_files
        unlinked = unlinked_files(project_dir, manifest)
        if unlinked:
            print(f"  git:      WARNING {relink_advice(project_dir, unlinked)}")

    worst_status = 0
    smoke_message = ""

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
            project_dir, manifest, compose_files, periodic=periodic, tick=tick,
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
        if result.status != "ok":
            smoke_message = result.message

    if verbose:
        if worst_status == 0:
            print(f"{project_name}: OK")
        elif worst_status == 1:
            print(f"{project_name}: WARNING")
        else:
            print(f"{project_name}: CRITICAL")

    return worst_status, smoke_message


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
