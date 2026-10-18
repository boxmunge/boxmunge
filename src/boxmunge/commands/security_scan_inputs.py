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

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from boxmunge import docker_containers
from boxmunge.commands.health_state import is_monitor_stopped
from boxmunge.compose_resolve import ComposeResolveError, resolve_deployed_config
from boxmunge.cve.hardening import HardeningProfile, effective_hardening_profile
from boxmunge.cve.policy import PolicyError, Posture, parse_posture
from boxmunge.cve.security_policy import security_policy
from boxmunge.cve.scan_state import BASIS_CONTAINERS, BASIS_STARTUP_IMAGES
from boxmunge.cve.suppressions import Suppression, SuppressionsError, load_suppressions
from boxmunge.deployed_inventory import (
    DeployedInventory, InventoryError, load_deployed_inventory, startup_image_ref,
)
from boxmunge.docker_run import DockerError
from boxmunge.lifecycle import is_blocked
from boxmunge.manifest import load_manifest
from boxmunge.paths import BoxPaths
from boxmunge.security_overlay import PROFILE_OFF, effective_profile, resolve_security


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

    def policy(self) -> dict[str, Any]:
        return security_policy(posture=self.posture, dangerously=self.dangerously,
                               runtimes=self.declared_runtimes)


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
    return project_meta(project, load_manifest(paths.project_manifest(project)),
                        project_compose_files(paths, project))


def project_meta(project: str, manifest: dict[str, Any],
                 compose_files: list[str]) -> ProjectMeta:
    """Validate a manifest's security: block (the deployed one's, or a
    release's not yet deployed)."""
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
        compose_files=compose_files,
    )


def hardening_profile(meta: ProjectMeta, user_model: dict[str, Any]) -> HardeningProfile:
    """Overlay-aware hardening profile for the penalty calculation.

    ``user_model`` is compose.yml as Compose resolves it, so a setting that
    arrives through `include:` or `extends:` counts. Each service is judged
    with what boxmunge's overlay applies to it (resolved from the same
    security blocks the overlay is built from): the project does not lose
    points for an overlay default it did not redeclare, and a manifest
    relaxation the overlay emits (no_new_privileges: false, cap_add) counts
    as a deviation.
    """
    project_sec = meta.manifest.get("security")
    declared = meta.manifest.get("services") or {}
    applied, off = {}, set()
    for svc in (user_model.get("services") or {}):
        entry = declared.get(svc)
        svc_sec = entry.get("security") if isinstance(entry, dict) else None
        applied[svc] = resolve_security(project_sec, svc_sec)
        if effective_profile(project_sec, svc_sec) == PROFILE_OFF:
            off.add(svc)
    return effective_hardening_profile(user_model, applied, off)


def load_user_model(paths: BoxPaths, project: str) -> dict[str, Any]:
    """compose.yml resolved on its own: the user's settings, before the overlay."""
    try:
        return resolve_deployed_config(paths.project_dir(project), ["compose.yml"], project)
    except ComposeResolveError as e:
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

    basis: str
    # Why the platform has the project stopped (startup-images basis only).
    stopped_reason: str | None
    targets: list[ScanTarget] = field(default_factory=list)
    # service → why its image cannot be identified.
    unidentified: dict[str, str] = field(default_factory=dict)
    # Services `up` does not start (inactive profile, zero replicas) that
    # have no container.
    not_started: list[str] = field(default_factory=list)


def stopped_reason(paths: BoxPaths, project: str) -> str | None:
    """Why the platform has the project stopped on purpose, or None.

    Read from boxmunge's own state (pause, quarantine and health-monitor
    stop markers), never inferred from which containers happen to exist.
    """
    block = is_blocked(project, paths)
    if block:
        return block.reason.value
    if is_monitor_stopped(project, paths):
        return "stopped by the health monitor"
    return None


def _manifest_first(manifest: dict[str, Any], deployed: DeployedInventory) -> list[str]:
    names = list(manifest.get("services") or {})
    return names + [n for n in deployed.services if n not in names]


def identify_images(manifest: dict[str, Any], deployed: DeployedInventory) -> ImageInventory:
    """The image of every container the project has, by service.

    Every service is covered, not only those the manifest lists: databases,
    caches and sidecars run too (audit B-10), wherever the resolved model
    defines them. Each container is scanned by the image it was created
    from, never by the image its tag names now, since a pull moves the tag
    without touching running containers. A service with no container is
    inactive only when `up` does not start it (an inactive profile, zero
    replicas); otherwise it is unidentified, so the scan is incomplete
    rather than silently smaller.
    """
    inventory = ImageInventory(BASIS_CONTAINERS, None)
    for service in _manifest_first(manifest, deployed):
        deployed_svc = deployed.services.get(service)
        if deployed_svc is None or not deployed_svc.containers:
            if deployed_svc is not None and not deployed_svc.expected:
                inventory.not_started.append(service)
            else:
                inventory.unidentified[service] = (
                    "should be running but has no container, so the image it "
                    "runs cannot be identified; redeploy the project so it can "
                    "be scanned"
                )
            continue
        refs = dict.fromkeys(c.image_ref for c in deployed_svc.containers)
        inventory.targets.extend(ScanTarget(service, ref) for ref in refs)
    return inventory


def identify_startup_images(
    manifest: dict[str, Any], deployed: DeployedInventory, reason: str,
) -> ImageInventory:
    """For a project the platform stopped on purpose (paused, quarantined,
    stopped by the health monitor): the image of every container it still
    has, plus the images `compose up` would start.

    Such a project's containers may be gone (a monitor stop removes them; a
    prune removes stopped ones), and a pull may have moved its tags since
    they were created. Bringing it back (resume, recover) starts what each
    service's image reference names now, so that is scanned, and a resume
    re-scan checks exactly what the resume will run. A stop marker does not
    prove nothing runs (a stop can fail after the marker is written; `stop`
    leaves one-off containers), so every existing container is scanned too:
    the scan never covers less than what is running.
    """
    inventory = ImageInventory(BASIS_STARTUP_IMAGES, reason)
    for service in _manifest_first(manifest, deployed):
        deployed_svc = deployed.services.get(service)
        if deployed_svc is None:
            inventory.unidentified[service] = (
                "is in the manifest but not in the resolved compose model, so "
                "no image would be started for it"
            )
            continue
        refs = dict.fromkeys(c.image_ref for c in deployed_svc.containers)
        if deployed_svc.expected:
            ref = startup_image_ref(deployed.project, deployed_svc)
            image = docker_containers.local_image(ref)
            if image is None:
                inventory.unidentified[service] = (
                    f"the image `compose up` would start ({ref}) is not in the "
                    f"local image store; pull or build it, then scan again"
                )
            else:
                refs[image.image_ref] = None
        elif not refs:
            inventory.not_started.append(service)
        inventory.targets.extend(ScanTarget(service, r) for r in refs)
    return inventory


def identify(paths: BoxPaths, project: str, meta: ProjectMeta) -> ImageInventory:
    """What to scan for one project, by the rule its lifecycle state selects."""
    try:
        deployed = load_deployed_inventory(paths.project_dir(project), meta.compose_files, project)
        reason = stopped_reason(paths, project)
        if reason is None:
            return identify_images(meta.manifest, deployed)
        return identify_startup_images(meta.manifest, deployed, reason)
    except (InventoryError, DockerError) as e:
        raise ProjectScanError(f"project {project!r}: {e}") from e
