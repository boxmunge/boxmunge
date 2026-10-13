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
from boxmunge.cve.policy import Posture, parse_posture
from boxmunge.cve.suppressions import Suppression, SuppressionsError, load_suppressions
from boxmunge.docker import container_image_digest
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
        return {}
    return data


def load_project_meta(paths: BoxPaths, project: str) -> ProjectMeta:
    """Load manifest + compose, validate the security: block."""
    manifest = load_manifest(paths.project_manifest(project))
    compose = load_compose(paths.project_dir(project))
    sec_block = manifest.get("security") or {}
    posture_str = sec_block.get("posture") or "balanced"
    posture = parse_posture(posture_str)
    ddq = bool(sec_block.get("dangerously_disable_quarantine", False))
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


def identify_images(
    manifest: dict[str, Any], compose: dict[str, Any], project: str,
) -> tuple[list[ScanTarget], list[str]]:
    """Return (targets, unidentified service names).

    For each manifest service: prefer the running (or stopped) container's
    image digest; fall back to the compose-declared image. A service with
    neither cannot be scanned and is reported as unidentified.
    """
    targets: list[ScanTarget] = []
    unidentified: list[str] = []
    compose_services = compose.get("services") or {}

    for svc_name in (manifest.get("services") or {}).keys():
        svc_compose = compose_services.get(svc_name, {})
        base_ref = svc_compose.get("image") if isinstance(svc_compose, dict) else None
        digest = container_image_digest(container_name(project, svc_name))
        if digest:
            if base_ref and "@" not in base_ref:
                # Strip any tag and pin to digest.
                short = base_ref.split(":", 1)[0]
                targets.append(ScanTarget(svc_name, f"{short}@{digest}"))
            else:
                targets.append(ScanTarget(svc_name, digest))
        elif base_ref:
            targets.append(ScanTarget(svc_name, base_ref))
        else:
            unidentified.append(svc_name)
    return targets, unidentified
