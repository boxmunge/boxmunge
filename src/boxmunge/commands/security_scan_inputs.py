# SPDX-License-Identifier: Apache-2.0
"""Inputs to a per-project CVE scan: manifest meta, images, suppressions.

Split from security_scan_core.py so the scan body stays focused on
evaluating and persisting. Everything here reads on-box files, Compose's
resolved model and Docker's containers, and turns them into validated
values. A malformed per-project input raises
ProjectScanError (a RuntimeError) naming the project, so the fleet scan can
report that one project and carry on with the rest (audit B-12).
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from boxmunge.compose_resolve import ComposeResolveError, resolve_deployed_config
from boxmunge.cve.hardening import HardeningProfile, hardening_profile_from_compose
from boxmunge.cve.policy import PolicyError, Posture, parse_posture
from boxmunge.cve.suppressions import Suppression, SuppressionsError, load_suppressions
from boxmunge.deployed_inventory import (
    DeployedInventory, InventoryError, load_deployed_inventory,
)
from boxmunge.manifest import load_manifest
from boxmunge.paths import BoxPaths
from boxmunge.security_overlay import services_with_off_profile


class ProjectScanError(RuntimeError):
    """A per-project scan input is missing or malformed."""


@dataclass(frozen=True)
class ProjectMeta:
    """The manifest facts a scan needs, validated once."""

    manifest: dict[str, Any]
    posture_str: str
    posture: Posture
    dangerously: bool
    declared_runtimes: Any
    hosts: list[str]
    compose_files: list[str]


@dataclass(frozen=True)
class ScanTarget:
    """One image to scan, and the manifest service it belongs to."""

    service: str
    image_ref: str


def project_suppressions_path(paths: BoxPaths, project: str) -> Path:
    return paths.project_dir(project) / "security" / "suppressions.yml"


def project_compose_files(paths: BoxPaths, project: str) -> list[str]:
    """compose.yml plus the generated overlay when it exists."""
    files = ["compose.yml"]
    if paths.project_compose_override(project).exists():
        files.append("compose.boxmunge.yml")
    return files


def load_project_meta(paths: BoxPaths, project: str) -> ProjectMeta:
    """Load the manifest, validate the security: block."""
    manifest = load_manifest(paths.project_manifest(project))
    sec_block = manifest.get("security") or {}
    if not isinstance(sec_block, dict):
        raise ProjectScanError(
            f"project {project!r}: manifest security: must be a mapping, "
            f"got {type(sec_block).__name__}"
        )
    posture_str = sec_block.get("posture") or "balanced"
    try:
        posture = parse_posture(posture_str)
    except PolicyError as e:
        raise ProjectScanError(f"project {project!r}: {e}") from e
    ddq = sec_block.get("dangerously_disable_quarantine", False)
    if not isinstance(ddq, bool):
        raise ProjectScanError(
            f"project {project!r}: security.dangerously_disable_quarantine "
            f"must be true or false, got {ddq!r}"
        )
    return ProjectMeta(
        manifest=manifest,
        posture_str=posture_str,
        posture=posture,
        dangerously=ddq,
        declared_runtimes=sec_block.get("runtimes"),
        hosts=list(manifest.get("hosts") or []),
        compose_files=project_compose_files(paths, project),
    )


def hardening_profile(meta: ProjectMeta, user_model: dict[str, Any]) -> HardeningProfile:
    """Overlay-aware hardening profile for the penalty calculation.

    ``user_model`` is compose.yml as Compose resolves it, so a setting that
    arrives through `include:` or `extends:` counts. Services with profile
    != off get boxmunge's hardening overlay applied at runtime, so the
    policy does not penalise a project for relying on overlay defaults
    (e.g. no-new-privileges) it did not redeclare in compose.yml.
    """
    off_services = {svc for svc, _ in services_with_off_profile(meta.manifest)}
    overlay_services = set((user_model.get("services") or {}).keys()) - off_services
    return hardening_profile_from_compose(
        user_model, services_with_overlay=overlay_services,
    )


def load_user_model(paths: BoxPaths, project: str) -> dict[str, Any]:
    """compose.yml resolved on its own: the user's settings, before the overlay."""
    try:
        return resolve_deployed_config(paths.project_dir(project), ["compose.yml"], project)
    except ComposeResolveError as e:
        raise ProjectScanError(f"project {project!r}: {e}") from e


def load_inventory(paths: BoxPaths, project: str, meta: ProjectMeta) -> DeployedInventory:
    """The project's deployed services and the containers running them."""
    try:
        return load_deployed_inventory(paths.project_dir(project), meta.compose_files, project)
    except InventoryError as e:
        raise ProjectScanError(f"project {project!r}: {e}") from e


def load_all_suppressions(paths: BoxPaths, project: str) -> tuple[Suppression, ...]:
    """Project suppressions first (they win on collision), then host-scoped."""
    try:
        project_supps = load_suppressions(project_suppressions_path(paths, project))
    except SuppressionsError as e:
        raise ProjectScanError(
            f"Failed to load suppressions for {project!r}: {e}"
        ) from e
    try:
        host_supps = load_suppressions(paths.host_suppressions, scope="host")
    except SuppressionsError as e:
        raise ProjectScanError(f"Failed to load host-scoped suppressions: {e}") from e
    return project_supps + host_supps


@dataclass(frozen=True)
class ImageInventory:
    """What to scan for one project, and what could not be scanned."""

    targets: list[ScanTarget]
    # Services `up` starts that have no container: nothing shows what they run.
    unidentified: list[str]
    # Services behind an inactive Compose profile with no container.
    not_started: list[str]


def identify_images(manifest: dict[str, Any], deployed: DeployedInventory) -> ImageInventory:
    """The image of every container the project has, by service.

    Every service is covered, not only those the manifest lists: databases,
    caches and sidecars run too (audit B-10), wherever the resolved model
    defines them. Each container is scanned by the image it was created
    from, never by the image its tag names now, since a pull moves the tag
    without touching running containers. A service with no container is
    inactive only behind an inactive profile; otherwise it is unidentified,
    so the scan is incomplete rather than silently smaller.
    """
    names = list(manifest.get("services") or {})
    names += [n for n in deployed.services if n not in names]
    inventory = ImageInventory([], [], [])
    for service in names:
        deployed_svc = deployed.services.get(service)
        if deployed_svc is None or not deployed_svc.containers:
            if deployed_svc is not None and not deployed_svc.expected:
                inventory.not_started.append(service)
            else:
                inventory.unidentified.append(service)
            continue
        refs = dict.fromkeys(c.image_ref for c in deployed_svc.containers)
        inventory.targets.extend(ScanTarget(service, ref) for ref in refs)
    return inventory
