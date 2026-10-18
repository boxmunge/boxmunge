# SPDX-License-Identifier: Apache-2.0
"""Between installing a release and starting it: its users, then its configs.

decide_release_users builds the release from a scratch overlay whose built
images carry a candidate tag, so production's image names and files stay
as they were until the switch, whatever is refused or fails before it; it
decides and checks every service's user (deploy_images) and records
nothing. A CVE-quarantined project's release is scanned there too, before
the hook (quarantine_gate), so a refusal leaves its install abandonable.
generate_release_config writes the Caddy site and the overlay with those
users, then the users record. promote_candidates, at the
switch, moves the built names onto the candidates the users were decided
from, just before the start, which does not build.
"""
from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from boxmunge import docker_containers, user_drift
from boxmunge.caddy import prepare_caddy_config
from boxmunge.commands import deploy_images
from boxmunge.commands.deploy_images import CANDIDATE, candidate_name
from boxmunge.commands.quarantine_gate import Clearance, QuarantineRefused, clear_release
from boxmunge.compose import (
    ComposeError, load_user_compose, prepare_compose_override, render_compose_override,
)
from boxmunge.compose_images import BUILT_IMAGE_HOST, built_image_name
from boxmunge.compose_resolve import ComposeResolveError
from boxmunge.cve.quarantine import is_quarantined
from boxmunge.docker_run import DockerError, run as _run
from boxmunge.paths import BoxPaths
from boxmunge.release_target import DeployRefused, production_target
from boxmunge.run_as import RunAsError, ServiceUser


def _built(user_compose: dict[str, Any], project: str) -> list[str]:
    services = user_compose.get("services") or {}
    return sorted(built_image_name(project, n) for n, s in services.items()
                  if isinstance(s, dict) and s.get("build") is not None)


def _candidate_overlay(text: str, user_compose: dict[str, Any], project: str) -> str:
    doc = yaml.safe_load(text)
    for name, svc in (doc.get("services") or {}).items():
        if svc.get("image") in _built(user_compose, project):
            svc["image"] = candidate_name(project, name)
    return yaml.safe_dump(doc, sort_keys=False)


@dataclass(frozen=True)
class ReleaseDecision:
    users: dict[str, ServiceUser]
    # Set when the project is CVE-quarantined: the release's images were
    # scanned clean, and its deploy lifts the quarantine (quarantine_gate).
    clearance: Clearance | None = None


def decide_release_users(project_name: str, paths: BoxPaths, manifest: dict,
                         component: str) -> ReleaseDecision:
    """Build the release installed in the project dir under candidate tags,
    and decide and check who each service runs as; nothing is recorded.
    A quarantined project's release is then scanned, and its candidates
    removed if that refuses it. Raises DeployRefused (QuarantineRefused)
    or DockerError."""
    print("  Building images and deciding who each service runs as...")
    remove_candidates(project_name)
    try:
        user_compose = load_user_compose(paths.project_dir(project_name) / "compose.yml",
                                         project_name)
        with tempfile.TemporaryDirectory(prefix="boxmunge-users-") as scratch:
            overlay = Path(scratch) / "compose.boxmunge.yml"
            overlay.write_text(_candidate_overlay(
                render_compose_override(paths, manifest, user_compose), user_compose,
                project_name))
            target = production_target(paths, project_name, overlay)
            users = deploy_images.prepare_release_users(
                paths, target, manifest,
                component=component, rollback=component == "rollback",
                refetch=user_drift.held_back(paths, project_name))
            if not is_quarantined(project_name, paths):
                return ReleaseDecision(users)
            try:
                return ReleaseDecision(users, clear_release(paths, target, manifest))
            except QuarantineRefused as refused:
                try:
                    remove_candidates(project_name)
                except DockerError as e:
                    raise QuarantineRefused([*refused.problems, f"Removing its candidate "
                                             f"images failed too: {e}"]) from e
                raise
    except (RunAsError, ComposeResolveError, ComposeError) as e:
        raise DeployRefused([str(e)]) from e


def generate_release_config(project_name: str, paths: BoxPaths, manifest: dict,
                            component: str, users: dict[str, ServiceUser]) -> None:
    """Write the release's Caddy site and compose overlay (not yet live)
    with `users`, then record them. Raises OSError or ValueError."""
    print("  Generating Caddy config...")
    prepare_caddy_config(paths, manifest)
    print("  Generating compose overlay...")
    prepare_compose_override(paths, manifest, component=component, users=users or None)
    deploy_images.record_release_users(paths, production_target(paths, project_name),
                                       manifest, users, component=component)


def promote_candidates(paths: BoxPaths, project_name: str) -> None:
    """Give the real names to the candidates the users were decided from:
    each built image, and each held-back registry image pulled again (a
    rerun after a crash finds them moved already). Then nothing is held
    back any more. Raises DockerError or ComposeError."""
    user_compose = load_user_compose(paths.project_dir(project_name) / "compose.yml",
                                     project_name)
    for svc, spec in sorted((user_compose.get("services") or {}).items()):
        if not isinstance(spec, dict):
            continue
        name = (built_image_name(project_name, svc) if spec.get("build") is not None
                else spec.get("image"))
        candidate = candidate_name(project_name, svc)
        if not isinstance(name, str) or docker_containers.local_image(candidate) is None:
            continue
        _run(["docker", "tag", candidate, name], capture=True)
        _run(["docker", "image", "rm", candidate], capture=True)
    user_drift.clear(paths, project_name)


def remove_candidates(project_name: str) -> None:
    """Drop the candidates a refused, abandoned or interrupted install of
    this project left (this project's names only). Raises DockerError."""
    listed = _run(["docker", "image", "ls", "--format", "{{.Repository}}:{{.Tag}}",
                   "--filter", f"reference={BUILT_IMAGE_HOST}/{project_name}/*:{CANDIDATE}"],
                  capture=True).stdout.split()
    if listed:
        _run(["docker", "image", "rm", *listed], capture=True)
