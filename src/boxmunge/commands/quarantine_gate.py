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
If it fails after the switch, the quarantine stays and keep_quarantined puts
the maintenance page back and stops the containers at once. The release is
judged under its own manifest's policy, so it may clear the quarantine by
relaxing that policy; the lift then says so (Clearance.relaxed) against the
policy the quarantine recorded. Staging lifts nothing; production stays
quarantined until the promote, which scans again.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Any

from boxmunge import docker_containers
from boxmunge.commands.deploy_images import candidate_name
from boxmunge.commands.security_scan_core import ProjectScan, audit_targets
from boxmunge.commands.security_scan_inputs import (
    ProjectHardening, ProjectMeta, ProjectScanError, ScanTarget, hardening_profile,
    load_all_suppressions, project_meta,
)
from boxmunge.compose_images import built_image_name
from boxmunge.compose_resolve import ComposeResolveError, resolve_deployed_config
from boxmunge.cve.kev import load_kev
from boxmunge.cve.policy_explain import HARDENING_UPCOMING_FIX, hardening_cause
from boxmunge.cve.policy import Disposition, FindingDisposition
from boxmunge.cve.quarantine import (
    QuarantineError, checked_quarantine_record, is_quarantined, lift_quarantine,
    read_quarantine_state, reassert_quarantine,
)
from boxmunge.manifest import ManifestError, load_manifest
from boxmunge.cve.scan_state import BASIS_STARTUP_IMAGES
from boxmunge.cve.scanner import TrivyNotInstalledError, refresh_db
from boxmunge.cve.security_policy import relaxations
from boxmunge.docker_run import DockerError
from boxmunge.log import log_error, log_operation, log_warning
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
    the quarantine it lifts, {service: (name started under, image ID)}, the
    hardening profile it was judged with (a hook must not change it), the
    policy it was judged under and the one the quarantine recorded (None:
    unknown), and the findings it leaves running at risk."""
    project: str
    compose_project: str
    cve_id: str
    images: dict[str, tuple[str, str]]
    profile: ProjectHardening
    policy: dict[str, Any]
    quarantined_under: dict[str, Any] | None
    at_risk: tuple[str, ...]

    def relaxed(self) -> list[str]:
        """What the release loosened against the policy at quarantine time."""
        return relaxations(self.quarantined_under, self.policy) if self.quarantined_under else []


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


def _quarantine_record(paths: BoxPaths, project: str) -> dict[str, Any]:
    path = paths.project_quarantine_state(project)
    try:
        return checked_quarantine_record(read_quarantine_state(project, paths), path)
    except QuarantineError as e:
        raise QuarantineRefused([f"{e} Nothing was started."]) from e


def _profile(target: ReleaseTarget, meta: ProjectMeta) -> ProjectHardening:
    """The hardening the release's compose.yml and manifest give its services."""
    release = target.compose.project_directory or target.compose.cwd
    return hardening_profile(meta, resolve_deployed_config(
        release, ["compose.yml"], target.compose_project,
        project_directory=target.compose.project_directory, env_file=target.compose.env_file))


def _scan(paths: BoxPaths, target: ReleaseTarget, meta: ProjectMeta,
          starts: dict[str, StartImage], unnamed: dict[str, str],
          ) -> tuple[ProjectScan, dict[str, str], list[ScanTarget], ProjectHardening]:
    """The audit-only scan, {service: image ID} of what it scanned, the
    scan's targets and the hardening profile it was judged with."""
    project = target.project
    refresh_db()
    supps = load_all_suppressions(paths, project)
    profile = _profile(target, meta)
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
        paths, project, meta=meta, profile=profile, supps=supps,
        targets=once, unidentified=unidentified, kev=load_kev(paths),
        basis=BASIS_STARTUP_IMAGES)
    return scan, ids, targets, profile


def _fix_advice(f: FindingDisposition) -> str:
    if f.finding.fixed_version:
        return (f"fixed in {f.finding.fixed_version}: update the package, or rebuild on a "
                f"base image that has it")
    return "no fixed version is published yet: remove the package or wait for a fix"


def _finding_lines(scan: ProjectScan, services: dict[str, list[str]],
                   disposition: Disposition) -> list[str]:
    lines: dict[tuple[str, str, str], str] = {}
    for decision in scan.decisions:
        service = ", ".join(services[decision.image_ref])
        for f in decision.findings:
            if f.disposition != disposition:
                continue
            key = (f.finding.cve_id, f.finding.package, decision.image_ref)
            kev = ", CISA KEV: actively exploited" if f.kev_listed else ""
            lines.setdefault(key, (
                f"{f.finding.cve_id} ({f.effective_severity.value}{kev}) in "
                f"{f.finding.package} {f.finding.installed_version}, service {service} "
                f"(image {decision.image_ref}): {_fix_advice(f)}"))
    return list(lines.values())


def _upcoming_lines(scan: ProjectScan, services: dict[str, list[str]]) -> list[str]:
    """Findings that quarantine from 0.12 but not now: warned, never refused."""
    lines: dict[tuple[str, str, str], str] = {}
    for decision in scan.decisions:
        service = ", ".join(services[decision.image_ref])
        for f in decision.findings:
            if f.hardening_would_quarantine:
                lines.setdefault((f.finding.cve_id, f.finding.package, decision.image_ref), (
                    f"{f.finding.cve_id} ({f.effective_severity.value}) in {f.finding.package} "
                    f"{f.finding.installed_version}, service {service} (image "
                    f"{decision.image_ref})"))
    return list(lines.values())


def clear_release(paths: BoxPaths, target: ReleaseTarget, manifest: dict[str, Any],
                  previous: dict[str, Any] | None = None) -> Clearance:
    """Scan every image the release would start; return the clearance, or
    raise QuarantineRefused naming each finding or unscanned image.
    `previous` is the manifest the install replaced, the baseline for a
    quarantine whose record predates the policy it keeps."""
    project = target.project
    record = _quarantine_record(paths, project)
    cve = record["cve_id"]
    where = "staging" if target.staging else "production"
    print(f"  Scanning every image this release would start ({project} is CVE-quarantined "
          f"for {cve})...")
    try:
        starts, unnamed = start_images(target)
        meta = project_meta(project, manifest, [])
        scan, ids, scan_targets, profile = _scan(paths, target, meta, starts, unnamed)
        before = record.get("policy")
        if before is None and previous is not None:
            before = project_meta(project, previous, []).policy()
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
    blocking = _finding_lines(scan, services, Disposition.QUARANTINE)
    if blocking:
        raise QuarantineRefused([
            *blocking,
            f"This release would still be quarantined: the quarantine stays in place and "
            f"nothing was started in {where}. Ship a release without these findings, or "
            f"suppress one that does not apply (`boxmunge security suppress <CVE> --project "
            f"{project} --until <YYYY-MM-DD> --reason <text>`; a CISA KEV finding cannot "
            f"be suppressed) and deploy again."])
    upcoming = _upcoming_lines(scan, services)
    if upcoming and profile.upcoming is not None:
        print(f"  WARNING: from 0.12 this release would still be quarantined for "
              f"{len(upcoming)} finding(s); 0.11.0 does not refuse it:")
        for line in upcoming:
            print(f"    {line}")
        print(f"    Cause: {hardening_cause(profile.upcoming.services)}. {HARDENING_UPCOMING_FIX}")
    print(f"  Scan: clear ({len(ids)} service image(s), no quarantine-level finding under "
          f"the release's security policy).")
    return Clearance(
        project, target.compose_project, cve,
        {n: (starts[n].final_ref, ids[n]) for n in starts}, profile, meta.policy(), before,
        tuple(_finding_lines(scan, services, Disposition.STILL_RUNNING_AT_RISK)))


def require_unchanged(paths: BoxPaths, clearance: Clearance) -> None:
    """Once the release's configs are written, before the switch: the
    release must still start exactly what was scanned (the hook may have
    rewritten compose.yml or an env file since) and with the hardening it was
    judged with (the hook may have dropped read_only or a cap_drop, which
    would make a finding the hardening held down quarantine-level for what
    runs). Raises QuarantineRefused."""
    try:
        target = production_target(paths, clearance.project)
        profile = _profile(target, project_meta(
            clearance.project, load_manifest(paths.project_manifest(clearance.project)), []))
        starts, unnamed = start_images(target)
        now = {name: (start.final_ref, docker_containers.local_image(start.scan_ref))
               for name, start in starts.items()}
    except (ComposeResolveError, DockerError, ManifestError, ProjectScanError) as e:
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
    if profile.applied != clearance.profile.applied:
        moved.append(f"the hardening of its services changed from "
                     f"{clearance.profile.applied} to {profile.applied}")
    if moved:
        raise QuarantineRefused([*moved, "The release changed after its images were scanned "
                                 "(by its pre-deploy hook?). Nothing was started; the "
                                 "quarantine stays in place. Deploy again."])


def _verify_running(paths: BoxPaths, clearance: Clearance, component: str, *,
                    warn_held: bool = True) -> dict[str, str]:
    """Every running container must be on a scanned image. Returns
    {container: its service} of those the lift gives a restart policy back:
    a stopped container on another image (an inactive profile's, left from
    an earlier release) stays held at "no", so a daemon restart cannot
    start it, and is named."""
    services: dict[str, str] = {}
    wrong, held = [], []
    for c in docker_containers.project_containers(clearance.compose_project):
        if c.oneoff:
            continue
        scanned = clearance.images.get(c.service)
        if scanned is not None and c.image_id == scanned[1]:
            services[c.name] = c.service
        elif c.running:
            wrong.append(f"{c.name} runs {c.image_id}, not a scanned image")
        else:
            held.append(c.name)
    if wrong:
        raise QuarantineError("; ".join(wrong))
    if held and warn_held:
        message = (f"stopped containers on images this deploy did not scan keep restart "
                   f"policy \"no\": {', '.join(held)}; remove them if they are not needed")
        print(f"  WARNING: {message}")
        log_warning(component, message, paths, project=clearance.project)
    return services


_CONDITIONS = {"none": "no", "any": "always", "on-failure": "on-failure"}


def _policy(svc: dict[str, Any]) -> str:
    """The restart policy compose gives a container of ``svc``."""
    if svc.get("restart"):
        return str(svc["restart"])
    rule = (svc.get("deploy") or {}).get("restart_policy") or {}
    condition = rule.get("condition")
    if not condition:
        return "no"
    if condition not in _CONDITIONS:
        raise QuarantineError(f"deploy.restart_policy.condition {condition!r} is not one "
                              f"of {', '.join(_CONDITIONS)}")
    attempts = rule.get("max_attempts")
    return f"on-failure:{attempts}" if condition == "on-failure" and attempts else \
        _CONDITIONS[condition]


def _release_policies(paths: BoxPaths, project: str,
                      services: dict[str, str]) -> dict[str, str]:
    """{container: its release's own restart policy}: what compose gives a
    container it creates, so a held one the deploy did not recreate gets the
    same, never a policy saved from an earlier release."""
    _model, model = resolved_services(production_target(paths, project))
    gone = sorted({svc for svc in services.values() if svc not in model})
    if gone:
        raise QuarantineError(f"services {', '.join(gone)} are no longer in the release")
    return {name: _policy(model[svc]) for name, svc in services.items()}


def keep_quarantined(paths: BoxPaths, project: str) -> None:
    """A fix's deploy stopped after its configs replaced the maintenance
    site: re-assert the quarantine now (maintenance page, stop, held
    restart policies) rather than leave its hosts routed to nothing until
    the next scan. A failure is said loudly; the next scan retries it."""
    try:
        hosts = list(load_manifest(paths.project_manifest(project)).get("hosts") or [])
        files = ["compose.yml"] + (["compose.boxmunge.yml"]
                                   if paths.project_compose_override(project).exists() else [])
        reassert_quarantine(project, paths, project_dir=paths.project_dir(project),
                            hosts=hosts, compose_files=files)
    except (QuarantineError, ManifestError, OSError) as e:
        print(f"ERROR: {project} stays CVE-quarantined, but putting its maintenance page "
              f"back failed: {e}. The next scan retries it.", file=sys.stderr)
        return
    print(f"  {project} stays CVE-quarantined: its maintenance page is back and its "
          f"containers are stopped. Deploy a fix again, or run `boxmunge security resume "
          f"{project}`.", file=sys.stderr)


def verify_started(paths: BoxPaths, clearance: Clearance, component: str) -> None:
    """After a start, every running container of the release is still on a
    scanned image: a tag another project pulled in between would have had
    compose recreate it on one nobody scanned. Raises QuarantineError."""
    _verify_running(paths, clearance, component, warn_held=False)


def _lift_report(clearance: Clearance, ref: str) -> tuple[str, dict[str, Any]]:
    """(what the lift says, the log detail) of a lift.
    A scan that is clear only because the release loosened its security
    policy says so, and what is left running at risk; it is not a fix."""
    cve = clearance.cve_id
    detail: dict[str, Any] = {"cve_id": cve, "ref": ref}
    done = f"quarantine ({cve}) lifted by deploying {ref}"
    relaxed = clearance.relaxed()
    if relaxed:
        risk = (f" Still running at risk: {'; '.join(clearance.at_risk)}." if clearance.at_risk
                else "")
        text = (f"{done}, by relaxing the security policy ({'; '.join(relaxed)}), not by a "
                f"fix: the images were not shown to be fixed.{risk}")
        detail.update(relaxed=relaxed, policy_before=clearance.quarantined_under,
                      policy_after=clearance.policy, at_risk=list(clearance.at_risk))
        return text[0].upper() + text[1:], detail
    text = (f"{done}: every image it runs was scanned, with no quarantine-level finding "
            f"under the release's security policy.")
    if clearance.quarantined_under is None:
        text += (" Policy at quarantine time unknown: a relaxation of the security policy "
                 "cannot be ruled out.")
        detail["policy_baseline"] = "unknown"
    return text[0].upper() + text[1:], detail


def manifest_in_force(paths: BoxPaths, project: str) -> dict[str, Any] | None:
    """The on-box manifest of a quarantined project, read before an install
    replaces it: the baseline for a quarantine whose record does not keep the
    policy. None when the project is not quarantined or the manifest cannot
    be read (the lift then reports the policy at quarantine time unknown)."""
    if not is_quarantined(project, paths):
        return None
    try:
        return load_manifest(paths.project_manifest(project))
    except ManifestError:
        return None


def lift_after_deploy(paths: BoxPaths, project: str, ref: str, clearance: Clearance, *,
                      txn: str | None, component: str) -> int:
    """The release is live and its smoke test passed: check that every
    container runs a scanned image, then lift the quarantine (checking again
    once the lift's start is done, and putting the quarantine back if that
    start moved a container onto an unscanned image). Returns 0, or 1 with
    the failure reported (the quarantine stays)."""
    def recheck() -> None:
        try:
            verify_started(paths, clearance, component)
        except QuarantineError:
            keep_quarantined(paths, project)
            raise

    try:
        policies = _release_policies(paths, project,
                                     _verify_running(paths, clearance, component))
        site = paths.project_caddy_site(project).read_text()
        lift_quarantine(project, paths, project_caddy_site_content=site,
                        compose_files=["compose.yml", "compose.boxmunge.yml"],
                        restore=policies, txn=txn, component=component, after_start=recheck)
    except (QuarantineError, DockerError, ComposeResolveError, OSError) as e:
        print(f"ERROR: {ref} is deployed, but lifting the quarantine ({clearance.cve_id}) "
              f"failed: {e}. The quarantine stays in place and the next scan re-asserts it; "
              f"run `boxmunge security resume {project}` once the cause is fixed.",
              file=sys.stderr)
        log_error(component, f"Lifting the quarantine after deploying {ref} failed: {e}",
                  paths, project=project)
        return 1
    message, detail = _lift_report(clearance, ref)
    relaxed = bool(clearance.relaxed())
    unknown = detail.get("policy_baseline") == "unknown"
    # Both cases are higher priority: a relaxation, or one that cannot be ruled out.
    caveat = (" by relaxing the security policy" if relaxed
              else " (policy at quarantine time unknown)" if unknown else "")
    print(f"  {message}")
    log_operation(component, f"CVE quarantine ({clearance.cve_id}) lifted by deploying {ref}"
                  + caveat, paths, project=project, detail=detail)
    notify(paths, f"{project}: quarantine lifted by deploying {ref}" + caveat,
           f"{project}: {message}",
           component=component, project=project, priority=1 if relaxed or unknown else 0)
    return 0
