# SPDX-License-Identifier: Apache-2.0
"""Deploying a fix to a CVE-quarantined project.

A quarantined project still takes a deploy, a promote or a stage, because
that is how a fix ships. After the release's images are built and pulled
(under candidate names until the switch) and before anything is stopped,
started or switched, every image the release would start is scanned the
way `security resume` scans: audit-only, failing closed (a failed image
scan, a budget skip or an image that cannot be identified refuses), with
the cached KEV catalog, under the release's own manifest and compose
(its posture and hardening) and the project's suppressions (server-side
state no release carries). A quarantine-level finding refuses the release.

A production release that clears starts as any deploy does, and once its
smoke test passes the quarantine is lifted (cve.quarantine.lift_quarantine).
If it fails after the switch, the quarantine stays: the next scan puts the
maintenance page back. Staging lifts nothing; production stays quarantined
until the promote, which scans again.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from boxmunge import docker_containers
from boxmunge.commands.deploy_images import candidate_name
from boxmunge.commands.security_scan_core import ProjectScan, audit_targets
from boxmunge.commands.security_scan_inputs import (
    ScanTarget, hardening_profile, load_all_suppressions, project_meta,
)
from boxmunge.compose_images import built_image_name
from boxmunge.compose_resolve import ComposeResolveError, resolve_deployed_config
from boxmunge.cve.kev import load_kev
from boxmunge.cve.policy import Disposition, FindingDisposition
from boxmunge.cve.quarantine import QuarantineError, lift_quarantine, read_quarantine_state
from boxmunge.cve.scan_state import BASIS_STARTUP_IMAGES
from boxmunge.cve.scanner import TrivyNotInstalledError, refresh_db
from boxmunge.docker_run import DockerError
from boxmunge.log import log_error, log_operation
from boxmunge.notify import notify
from boxmunge.paths import BoxPaths
from boxmunge.release_target import DeployRefused, ReleaseTarget, resolved_services


class QuarantineRefused(DeployRefused):
    """The release cannot ship as a quarantine's fix; nothing was started."""


@dataclass(frozen=True)
class StartImage:
    scan_ref: str   # the image as it is named now (a candidate until the switch)
    final_ref: str  # the name the release starts it under, after the switch


@dataclass(frozen=True)
class Clearance:
    """A production release scanned clean while its project is quarantined:
    the quarantine it lifts, and {service: (name started under, image ID)}."""
    project: str
    cve_id: str
    images: dict[str, tuple[str, str]]


def start_images(target: ReleaseTarget) -> tuple[dict[str, StartImage], dict[str, str]]:
    """Every service's image as the release would start it (all profiles,
    as deploy_images builds and pulls them), and the services whose image
    cannot be named. A build and a held-back image pulled again wait under
    candidate names; the switch gives them their own (promote_candidates)."""
    _model, services = resolved_services(target)
    starts: dict[str, StartImage] = {}
    unnamed: dict[str, str] = {}
    for name, svc in sorted(services.items()):
        ref = svc.get("image")
        if not isinstance(ref, str) or not ref:
            unnamed[name] = "has no image reference, so the image it would start is unknown"
            continue
        candidate = candidate_name(target.compose_project, name)
        if ref == candidate:
            starts[name] = StartImage(candidate, built_image_name(target.compose_project, name))
        elif not target.staging and docker_containers.local_image(candidate) is not None:
            starts[name] = StartImage(candidate, ref)
        else:
            starts[name] = StartImage(ref, ref)
    return starts, unnamed


def _quarantined_cve(paths: BoxPaths, project: str) -> str:
    try:
        state = read_quarantine_state(project, paths)
    except QuarantineError as e:
        raise QuarantineRefused([f"{e}. Nothing was started."]) from e
    cve = (state or {}).get("cve_id")
    return cve if isinstance(cve, str) and cve else "<unknown>"


def _scan(paths: BoxPaths, target: ReleaseTarget, manifest: dict[str, Any],
          starts: dict[str, StartImage], unnamed: dict[str, str],
          ) -> tuple[ProjectScan, dict[str, str], list[ScanTarget]]:
    """The audit-only scan, {service: image ID} of what it scanned, and the
    scan's targets."""
    project = target.project
    release = target.compose.project_directory or target.compose.cwd
    refresh_db()
    meta = project_meta(project, manifest, [])
    supps = load_all_suppressions(paths, project)
    user_model = resolve_deployed_config(
        release, ["compose.yml"], target.compose_project,
        project_directory=target.compose.project_directory, env_file=target.compose.env_file)
    targets: list[ScanTarget] = []
    ids: dict[str, str] = {}
    unidentified = dict(unnamed)
    for name, start in starts.items():
        image = docker_containers.local_image(start.scan_ref)
        if image is None:
            unidentified[name] = (f"its image {start.scan_ref} is not in the local image "
                                  f"store after the build and pull")
            continue
        ids[name] = image.image_id
        targets.append(ScanTarget(name, image.image_ref))
    scan = audit_targets(
        paths, project, meta=meta, profile=hardening_profile(meta, user_model), supps=supps,
        targets=targets, unidentified=unidentified, kev=load_kev(paths),
        basis=BASIS_STARTUP_IMAGES)
    return scan, ids, targets


def _fix_advice(f: FindingDisposition) -> str:
    if f.finding.fixed_version:
        return (f"fixed in {f.finding.fixed_version}: update the package, or rebuild on a "
                f"base image that has it")
    return "no fixed version is published yet: remove the package or wait for a fix"


def _blocking_lines(scan: ProjectScan, services: dict[str, list[str]]) -> list[str]:
    lines: dict[tuple[str, str, str], str] = {}
    for decision in scan.decisions:
        service = ", ".join(services[decision.image_ref])
        for f in decision.findings:
            if f.disposition != Disposition.QUARANTINE:
                continue
            key = (f.finding.cve_id, f.finding.package, decision.image_ref)
            kev = ", CISA KEV: actively exploited" if f.kev_listed else ""
            lines.setdefault(key, (
                f"{f.finding.cve_id} ({f.effective_severity.value}{kev}) in "
                f"{f.finding.package} {f.finding.installed_version}, service {service} "
                f"(image {decision.image_ref}): {_fix_advice(f)}"))
    return list(lines.values())


def clear_release(paths: BoxPaths, target: ReleaseTarget,
                  manifest: dict[str, Any]) -> Clearance:
    """Scan every image the release would start; return the clearance, or
    raise QuarantineRefused naming each finding or unscanned image."""
    project = target.project
    cve = _quarantined_cve(paths, project)
    where = "staging" if target.staging else "production"
    print(f"  Scanning every image this release would start ({project} is CVE-quarantined "
          f"for {cve})...")
    try:
        starts, unnamed = start_images(target)
        scan, ids, scan_targets = _scan(paths, target, manifest, starts, unnamed)
    except (TrivyNotInstalledError, RuntimeError, ComposeResolveError, DockerError) as e:
        raise QuarantineRefused([
            f"The scan of the release's images failed: {e}",
            f"The quarantine stays in place and nothing was started in {where}. Fix the "
            f"cause and deploy again."]) from e
    if not scan.complete:
        raise QuarantineRefused([
            *scan.incomplete_reasons(),
            f"The scan did not cover every image the release would start, so boxmunge "
            f"cannot show it fixes the quarantine; it stays in place and nothing was "
            f"started in {where}. Fix the cause and deploy again."])
    services: dict[str, list[str]] = {}
    for target_ in scan_targets:
        services.setdefault(target_.image_ref, []).append(target_.service)
    blocking = _blocking_lines(scan, services)
    if blocking:
        raise QuarantineRefused([
            *blocking,
            f"This release would still be quarantined: the quarantine stays in place and "
            f"nothing was started in {where}. Ship a release without these findings, or "
            f"suppress one that does not apply (`boxmunge security suppress <CVE> --project "
            f"{project} --until <YYYY-MM-DD> --reason <text>`; a CISA KEV finding cannot "
            f"be suppressed) and deploy again."])
    print(f"  Scan: clear ({len(ids)} image(s), no quarantine-level findings).")
    return Clearance(project, cve, {n: (starts[n].final_ref, ids[n]) for n in starts})


def require_unchanged(clearance: Clearance) -> None:
    """At the switch, after the candidates got their names: each name the
    release starts must still be the image that was scanned."""
    moved = []
    for service, (ref, image_id) in sorted(clearance.images.items()):
        image = docker_containers.local_image(ref)
        if image is None or image.image_id != image_id:
            moved.append(f"service {service}: {ref} no longer names the image that was "
                         f"scanned ({image_id})")
    if moved:
        raise QuarantineRefused([*moved, "Nothing was started; deploy again."])


def lift_after_deploy(paths: BoxPaths, project: str, ref: str, clearance: Clearance,
                      before: dict[str, datetime], *, txn: str | None, component: str) -> int:
    """The release is live and its smoke test passed: lift the quarantine.
    ``before``: each container's creation time before the start, so the
    held restart policies go back only to the containers it did not
    recreate. Returns 0, or 1 with the failure reported."""
    try:
        now = docker_containers.created_times(project)
        recreated = {name for name, created in now.items() if before.get(name) != created}
        site = paths.project_caddy_site(project).read_text()
        lift_quarantine(project, paths, project_caddy_site_content=site,
                        compose_files=["compose.yml", "compose.boxmunge.yml"],
                        recreated=recreated, txn=txn, component=component)
    except (QuarantineError, DockerError, OSError) as e:
        print(f"ERROR: {ref} is deployed and its images were scanned clean, but lifting the "
              f"quarantine ({clearance.cve_id}) failed: {e}. The quarantine stays in place "
              f"and the next scan re-asserts it; run `boxmunge security resume {project}` "
              f"once the cause is fixed.", file=sys.stderr)
        log_error(component, f"Lifting the quarantine after deploying {ref} failed: {e}",
                  paths, project=project)
        return 1
    message = f"quarantine ({clearance.cve_id}) lifted by deploying {ref}"
    print(f"  {message[0].upper()}{message[1:]}: every image it starts was scanned clean.")
    log_operation(component, f"CVE {message}", paths, project=project,
                  detail={"cve_id": clearance.cve_id, "ref": ref})
    notify(paths, f"{project}: quarantine lifted by deploying {ref}",
           f"The CVE quarantine of {project} ({clearance.cve_id}) was lifted by deploying "
           f"{ref}: every image it starts was scanned with no quarantine-level finding.",
           component=component, project=project, priority=0)
    return 0
