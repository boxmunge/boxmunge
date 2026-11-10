# SPDX-License-Identifier: Apache-2.0
"""Health checks that walk every project directory: project-containers,
lifecycle and config-drift.

A project's input that cannot be read (a pre-0.10.1 `<x>-staging` directory,
a torn quarantine or pause marker, a broken manifest) is a warning naming the
project, the cause and the fix, and the walk carries on with the rest. Never
an error: one app's broken file is not a platform failure, and `health`
exiting 2 during an upgrade's probation rolls the platform back.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

from boxmunge.commands.health_cmd import HealthCheck, timeout_detail
from boxmunge.commands.health_state import is_monitor_stopped
from boxmunge.config import ConfigError
from boxmunge.cve.quarantine import QuarantineError, is_quarantined, read_quarantine_state
from boxmunge.docker import compose_command
from boxmunge.docker_run import docker_env
from boxmunge.fleet import PROJECT_INPUT_ERRORS
from boxmunge.lifecycle import is_blocked
from boxmunge.manifest import ManifestError
from boxmunge.pause import awaiting_deploy, is_paused, pause_incomplete
from boxmunge.paths import InvalidProjectName
from boxmunge.state import StateError

if TYPE_CHECKING:
    from boxmunge.paths import BoxPaths


def unreadable(paths: BoxPaths, name: str, error: Exception) -> str:
    """'<project>: <cause>; fix: <what to do>' for an input health cannot read."""
    return f"{name}: {error}; fix: {_fix(paths, name, error)}"


def _fix(paths: BoxPaths, name: str, error: Exception) -> str:
    if isinstance(error, InvalidProjectName):
        return (f"boxmunge cannot manage a project under this name, so recreate it under "
                f"another name, then move {paths.projects / name} out of {paths.projects}")
    if isinstance(error, ManifestError):
        return f"correct the manifest (`validate {name}` names the problem)"
    if isinstance(error, QuarantineError):
        return ("repair the file or restore it from a backup; it holds the restart "
                "policies that lifting the quarantine gives back")
    if isinstance(error, ConfigError):
        return f"correct {paths.config_file}"
    if isinstance(error, (StateError, json.JSONDecodeError)):
        return "repair the file named or restore it from a backup"
    return "make the file named readable by the deploy user (compare a healthy project's)"


def _project_dirs(paths: BoxPaths) -> list[Path]:
    return [d for d in sorted(paths.projects.iterdir())
            if d.is_dir() and (d / "manifest.yml").exists()]


def check_project_containers(paths: BoxPaths) -> HealthCheck:
    """Check that every deployed project has running containers.

    Projects in operator/system-blocked lifecycle states (paused,
    CVE-quarantined, monitor-stopped) are excluded: surfacing them as "no
    running containers" would mis-attribute an intentional offline state.
    The OK message distinguishes total deployed from actually-checked; the
    blocked projects themselves are reported by `lifecycle`.
    """
    if not paths.projects.exists() or not (dirs := _project_dirs(paths)):
        return HealthCheck("project-containers", "ok", "No projects deployed")
    down: list[str] = []
    unchecked: list[str] = []
    blocked_count = 0
    for name in (d.name for d in dirs):
        try:
            if is_blocked(name, paths) or is_monitor_stopped(name, paths):
                blocked_count += 1
                continue
            files = ["compose.yml"]
            if paths.project_compose_override(name).exists():
                files.append("compose.boxmunge.yml")
        except PROJECT_INPUT_ERRORS as e:
            unchecked.append(unreadable(paths, name, e))
            continue
        try:
            result = subprocess.run(
                [*compose_command(name, files), "ps", "--format", "json"],
                cwd=paths.project_dir(name), capture_output=True, text=True,
                check=False, timeout=10, env=docker_env(),
            )
        except subprocess.TimeoutExpired as e:
            unchecked.append(f"{name}: {timeout_detail(e)}")
            continue
        except FileNotFoundError as e:  # no docker CLI: the `docker` check says so too
            unchecked.append(f"{name}: cannot run docker compose ({e})")
            continue
        if result.returncode != 0 or not result.stdout.strip():
            down.append(name)
    parts = []
    if down:
        parts.append(f"Projects with no running containers: {', '.join(down)}")
    if unchecked:
        parts.append(f"Could not check: {'; '.join(unchecked)}")
    if parts:
        return HealthCheck("project-containers", "warn", "; ".join(parts))
    checked = len(dirs) - blocked_count
    detail = f"All {checked} project(s) have running containers"
    if blocked_count:
        detail = (f"All {checked} checked project(s) have running containers "
                  f"({blocked_count} blocked — see `lifecycle`)")
    return HealthCheck("project-containers", "ok", detail)


def check_lifecycle_blocked(paths: BoxPaths) -> HealthCheck:
    """Surface projects in paused, CVE-quarantined, or monitor-stopped states.

    Quarantined projects warn: they're offline due to an unfixed CVE and may
    surprise an operator who only glanced at the report. Paused projects
    pass as OK with a note: an intentional operator action. Without this
    check a quarantined site could be silently offline while the report
    reads HEALTHY, since `project-containers` excludes it by design.
    """
    if not paths.projects.exists():
        return HealthCheck("lifecycle", "ok", "No projects deployed")
    paused: list[str] = []
    awaiting: list[str] = []
    quarantined: list[tuple[str, str]] = []
    bad: list[str] = []
    stopped: list[str] = []
    incomplete: list[str] = []
    for name in (d.name for d in _project_dirs(paths)):
        # Mirrors lifecycle.is_blocked precedence: quarantine wins if both
        # markers exist. A directory whose name is no longer a valid project
        # name (a legacy `-staging` one) fails the first lookup.
        try:
            if is_quarantined(name, paths):
                qstate = read_quarantine_state(name, paths) or {}
                quarantined.append((name, qstate.get("cve_id", "?")))
            elif pause_incomplete(name, paths):
                incomplete.append(name)
            elif awaiting_deploy(name, paths):
                awaiting.append(name)
            elif is_paused(name, paths):
                paused.append(name)
            elif is_monitor_stopped(name, paths):
                stopped.append(name)
        except PROJECT_INPUT_ERRORS as e:
            bad.append(unreadable(paths, name, e))
    parts = [label + text for label, text, names in (
        ("unreadable state: ", "; ".join(bad), bad),
        ("quarantined: ", ", ".join(f"{n} ({c})" for n, c in quarantined), quarantined),
        ("monitor-stopped: ", ", ".join(stopped) + " (run `recover <project>` once fixed)",
         stopped),
        ("pause incomplete: ", ", ".join(incomplete) + " (may still be serving; run `pause "
         "<project>` again to finish, or `resume <project>`)", incomplete),
        ("paused, awaiting a deploy: ", ", ".join(awaiting) + " (down behind the "
         "maintenance page until `prod-deploy <project> --redeploy`, or `prod-deploy "
         "<project>` after an upload)", awaiting),
        ("paused: ", ", ".join(paused), paused),
    ) if names]
    if bad or quarantined or stopped or incomplete or awaiting:
        return HealthCheck("lifecycle", "warn", "; ".join(parts))
    if paused:
        return HealthCheck("lifecycle", "ok", "; ".join(parts))
    return HealthCheck("lifecycle", "ok", "No projects in blocked states")


def _drifted(paths: BoxPaths, project_dir: Path) -> str | None:
    """The project's name if its generated Caddy config drifted, else None.
    Raises a PROJECT_INPUT_ERRORS error when an input cannot be read."""
    from boxmunge.caddy import generate_caddy_config
    from boxmunge.manifest import load_manifest, validate_manifest

    manifest = load_manifest(project_dir / "manifest.yml")
    name = project_dir.name
    if manifest.get("project", name) != name:
        raise ManifestError(f"its project field {manifest['project']!r} does not match "
                            f"its directory name")
    # Blocked projects are skipped: their .conf intentionally holds the
    # maintenance fragment. `lifecycle` reports the blocked state.
    if is_blocked(name, paths):
        return None
    site_conf = paths.project_caddy_site(name)
    if not site_conf.exists() or paths.project_caddy_override(name).exists():
        return None
    try:
        expected = generate_caddy_config(manifest)
    except Exception as e:
        # The manifest's fault only if validation says so; otherwise a
        # defect in boxmunge, which run_guarded reports as such.
        errors, _ = validate_manifest(manifest, name, lenient_values=True)
        if errors:
            raise ManifestError(f"cannot generate its Caddy config: {'; '.join(errors)}") from e
        raise
    return name if site_conf.read_text() != expected else None


def check_config_drift(paths: BoxPaths) -> HealthCheck:
    """Check if generated configs match what they should be."""
    if not paths.projects.exists():
        return HealthCheck("config-drift", "ok", "No projects to check")
    drifted: list[str] = []
    bad: list[str] = []
    for project_dir in _project_dirs(paths):
        try:
            name = _drifted(paths, project_dir)
        except PROJECT_INPUT_ERRORS as e:
            bad.append(unreadable(paths, project_dir.name, e))
            continue
        if name:
            drifted.append(name)
    parts = []
    if drifted:
        parts.append(f"Caddy config drifted for: {', '.join(drifted)}")
    if bad:
        parts.append(f"Could not check: {'; '.join(bad)}")
    if parts:
        return HealthCheck("config-drift", "warn", "; ".join(parts))
    return HealthCheck("config-drift", "ok", "All generated configs match")
