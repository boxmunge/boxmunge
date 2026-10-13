# SPDX-License-Identifier: Apache-2.0
"""Inputs to a per-project CVE scan: manifest meta, images, suppressions.

Split from security_scan_core.py so the scan body stays focused on
evaluating and persisting. Everything here reads on-box files and turns
them into validated values. A malformed per-project input raises
ProjectScanError (a RuntimeError) naming the project, so the fleet scan can
report that one project and carry on with the rest (audit B-12).
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from boxmunge.cve.hardening import HardeningProfile, hardening_profile_from_compose
from boxmunge.cve.policy import PolicyError, Posture, parse_posture
from boxmunge.cve.suppressions import Suppression, SuppressionsError, load_suppressions
from boxmunge.docker import container_image_digest, container_image_id, local_image_id
from boxmunge.manifest import load_manifest
from boxmunge.paths import BoxPaths
from boxmunge.security_overlay import services_with_off_profile


class ProjectScanError(RuntimeError):
    """A per-project scan input is missing or malformed."""


@dataclass(frozen=True)
class ProjectMeta:
    """The manifest/compose facts a scan needs, validated once."""

    manifest: dict[str, Any]
    compose: dict[str, Any]
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


def container_name(project: str, service: str) -> str:
    """Replicate the convention used in commands/check.py."""
    return f"{project}-{service}-1"


def load_compose(project_dir: Path) -> dict[str, Any]:
    """Load the user compose.yml as a parsed dict. Missing file → {}."""
    path = project_dir / "compose.yml"
    if not path.exists():
        return {}
    try:
        data = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as e:
        raise ProjectScanError(f"Failed to parse compose.yml: {e}") from e
    if not isinstance(data, dict):
        raise ProjectScanError(
            f"compose.yml must be a mapping, got {type(data).__name__}"
        )
    return data


def load_project_meta(paths: BoxPaths, project: str) -> ProjectMeta:
    """Load manifest + compose, validate the security: block."""
    manifest = load_manifest(paths.project_manifest(project))
    compose = load_compose(paths.project_dir(project))
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
        compose=compose,
        posture_str=posture_str,
        posture=posture,
        dangerously=ddq,
        declared_runtimes=sec_block.get("runtimes"),
        hosts=list(manifest.get("hosts") or []),
        compose_files=project_compose_files(paths, project),
    )


def hardening_profile(meta: ProjectMeta) -> HardeningProfile:
    """Overlay-aware hardening profile for the penalty calculation.

    Services with profile != off get boxmunge's hardening overlay applied at
    runtime, so the policy does not penalise a project for relying on overlay
    defaults (e.g. no-new-privileges) it did not redeclare in compose.yml.
    """
    off_services = {svc for svc, _ in services_with_off_profile(meta.manifest)}
    overlay_services = set((meta.compose.get("services") or {}).keys()) - off_services
    return hardening_profile_from_compose(
        meta.compose, services_with_overlay=overlay_services,
    )


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


def _strip_tag(ref: str) -> str:
    """Drop a :tag from an image reference, keeping a registry :port."""
    name, sep, tag = ref.rpartition(":")
    return name if sep and "/" not in tag else ref


@dataclass(frozen=True)
class ImageInventory:
    """What to scan for one project, and what could not be scanned."""

    targets: list[ScanTarget]
    # No container, no local image, no image: in compose — cannot be scanned.
    unidentified: list[str]
    # Compose-profile services that are not running: nothing deployed to scan.
    not_started: list[str]


def _image_for(project: str, service: str, svc_compose: dict[str, Any]) -> str | None:
    """The image to scan for one service, most exact first.

    1. The container's image pinned by registry digest (repo@sha256:...).
    2. The container's local image ID — what is actually running, and the
       only identity a locally built image has (audit B-10).
    3. The compose-declared image tag.
    4. The image compose builds for the service (<project>-<service>).
    """
    cname = container_name(project, service)
    base_ref = svc_compose.get("image")
    digest = container_image_digest(cname)
    if digest and base_ref and "@" not in base_ref:
        return f"{_strip_tag(base_ref)}@{digest}"
    return (
        container_image_id(cname)
        or base_ref
        or local_image_id(f"{project}-{service}")
    )


def identify_images(
    manifest: dict[str, Any], compose: dict[str, Any], project: str,
) -> ImageInventory:
    """Find the image of every service the project runs.

    Every compose service is scanned, not only those the manifest lists:
    databases, caches and sidecars run too (audit B-10).
    """
    compose_services = compose.get("services") or {}
    names = list(manifest.get("services") or {})
    names += [n for n in compose_services if n not in names]
    inventory = ImageInventory([], [], [])
    for service in names:
        svc_compose = compose_services.get(service)
        svc_compose = svc_compose if isinstance(svc_compose, dict) else {}
        image = _image_for(project, service, svc_compose)
        if image:
            inventory.targets.append(ScanTarget(service, image))
        elif svc_compose.get("profiles"):
            inventory.not_started.append(service)
        else:
            inventory.unidentified.append(service)
    return inventory
