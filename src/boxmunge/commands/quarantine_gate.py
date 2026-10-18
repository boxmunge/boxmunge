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
from boxmunge.cve.quarantine import (
    QuarantineError, checked_quarantine_record, is_quarantined, lift_quarantine,
    read_quarantine_state,
)
from boxmunge.cve.scan_state import BASIS_STARTUP_IMAGES
from boxmunge.cve.scanner import TrivyNotInstalledError, refresh_db
from boxmunge.docker_run import DockerError
from boxmunge.log import log_error, log_operation
from boxmunge.notify import notify
from boxmunge.paths import BoxPaths
from boxmunge.release_target import (
    DeployRefused, ReleaseTarget, production_target, resolved_services,
)


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
    cannot be named. A build, a service that names one of this project's
    builds, and a held-back image pulled again wait under candidate names
    until the switch gives them their own (promote_candidates)."""
    _model, services = resolved_services(target)
    cp = target.compose_project
    builds = {built_image_name(cp, n): candidate_name(cp, n) for n in services}
    built_from = {candidate: built for built, candidate in builds.items()}
    starts: dict[str, StartImage] = {}
    unnamed: dict[str, str] = {}
    for name, svc in sorted(services.items()):
        ref = svc.get("image")
        if not isinstance(ref, str) or not ref:
            unnamed[name] = "has no image reference, so the image it would start is unknown"
        elif ref in built_from:
            starts[name] = StartImage(ref, built_from[ref])
        elif target.staging:
            starts[name] = StartImage(ref, ref)
        elif ref in builds and docker_containers.local_image(builds[ref]) is not None:
            starts[name] = StartImage(builds[ref], ref)
        elif docker_containers.local_image(candidate_name(cp, name)) is not None:
            starts[name] = StartImage(candidate_name(cp, name), ref)
        else:
            starts[name] = StartImage(ref, ref)
    return starts, unnamed


def production_now(paths: BoxPaths, project: str) -> str:
    """Where production stands when a deploy stops before its start."""
    if is_quarantined(project, paths):
        return "production stays CVE-quarantined behind its maintenance page"
    return "production runs its previous containers"


def _quarantined_cve(paths: BoxPaths, project: str) -> str:
    path = paths.project_quarantine_state(project)
    try:
        return checked_quarantine_record(read_quarantine_state(project, paths), path)["cve_id"]
    except QuarantineError as e:
        raise QuarantineRefused([f"{e} Nothing was started."]) from e


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
    # Services sharing an image are scanned once: the budget is the project's.
    once = list({t.image_ref: t for t in targets}.values())
    scan = audit_targets(
        paths, project, meta=meta, profile=hardening_profile(meta, user_model), supps=supps,
        targets=once, unidentified=unidentified, kev=load_kev(paths),
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
    print(f"  Scan: clear ({len(ids)} service image(s), no quarantine-level finding under "
          f"the release's security policy).")
    return Clearance(project, cve, {n: (starts[n].final_ref, ids[n]) for n in starts})


def require_unchanged(paths: BoxPaths, clearance: Clearance) -> None:
    """Once the release's configs are written, before the switch: the
    release must still start exactly what was scanned (the hook may have
    rewritten compose.yml or an env file since). Raises QuarantineRefused."""
    try:
        starts, unnamed = start_images(production_target(paths, clearance.project))
        now = {name: (start.final_ref, docker_containers.local_image(start.scan_ref))
               for name, start in starts.items()}
    except (ComposeResolveError, DockerError) as e:
        raise QuarantineRefused([f"Checking what the release starts failed: {e}",
                                 "Nothing was started; deploy again."]) from e
    moved = [f"service {name}: {why}" for name, why in sorted(unnamed.items())]
    for name in sorted(set(now) | set(clearance.images)):
        if name not in clearance.images:
            moved.append(f"service {name} was not in the release that was scanned")
            continue
        if name not in now:
            moved.append(f"service {name} is no longer in the release")
            continue
        (ref, image), (scanned_ref, scanned_id) = now[name], clearance.images[name]
        if ref != scanned_ref or image is None or image.image_id != scanned_id:
            moved.append(f"service {name} would start {ref} "
                         f"({image.image_id if image else 'not in the local image store'}), "
                         f"not the scanned {scanned_ref} ({scanned_id})")
    if moved:
        raise QuarantineRefused([*moved, "The release changed after its images were scanned "
                                 "(by its pre-deploy hook?). Nothing was started; the "
                                 "quarantine stays in place. Deploy again."])


def _verify_running(clearance: Clearance) -> dict[str, str]:
    """Every container the project runs must be a scanned image; returns
    {container: its service}."""
    services: dict[str, str] = {}
    wrong = []
    for c in docker_containers.project_containers(clearance.project):
        if c.oneoff:
            continue
        services[c.name] = c.service
        scanned = clearance.images.get(c.service)
        if scanned is None or c.image_id != scanned[1]:
            wrong.append(f"{c.name} runs {c.image_id}, not a scanned image")
    if wrong:
        raise QuarantineError("; ".join(wrong))
    return services


def _release_policies(paths: BoxPaths, project: str,
                      services: dict[str, str]) -> dict[str, str]:
    """{container: its release's own restart policy}: what compose gives a
    container it creates, so a held one the deploy did not recreate gets the
    same, never a policy saved from an earlier release."""
    _model, model = resolved_services(production_target(paths, project))
    return {name: str(model[svc].get("restart") or "no") for name, svc in services.items()}


def lift_after_deploy(paths: BoxPaths, project: str, ref: str, clearance: Clearance, *,
                      txn: str | None, component: str) -> int:
    """The release is live and its smoke test passed: check that every
    container runs a scanned image, then lift the quarantine. Returns 0, or
    1 with the failure reported (the quarantine stays)."""
    try:
        policies = _release_policies(paths, project, _verify_running(clearance))
        site = paths.project_caddy_site(project).read_text()
        lift_quarantine(project, paths, project_caddy_site_content=site,
                        compose_files=["compose.yml", "compose.boxmunge.yml"],
                        restore=policies, txn=txn, component=component)
    except (QuarantineError, DockerError, ComposeResolveError, OSError) as e:
        print(f"ERROR: {ref} is deployed, but lifting the quarantine ({clearance.cve_id}) "
              f"failed: {e}. The quarantine stays in place and the next scan re-asserts it; "
              f"run `boxmunge security resume {project}` once the cause is fixed.",
              file=sys.stderr)
        log_error(component, f"Lifting the quarantine after deploying {ref} failed: {e}",
                  paths, project=project)
        return 1
    message = f"quarantine ({clearance.cve_id}) lifted by deploying {ref}"
    print(f"  {message[0].upper()}{message[1:]}: every image it runs was scanned, with no "
          f"quarantine-level finding under the release's security policy.")
    log_operation(component, f"CVE {message}", paths, project=project,
                  detail={"cve_id": clearance.cve_id, "ref": ref})
    notify(paths, f"{project}: quarantine lifted by deploying {ref}",
           f"The CVE quarantine of {project} ({clearance.cve_id}) was lifted by deploying "
           f"{ref}: every image it runs was scanned, with no quarantine-level finding under "
           f"the release's security policy.",
           component=component, project=project, priority=0)
    return 0
