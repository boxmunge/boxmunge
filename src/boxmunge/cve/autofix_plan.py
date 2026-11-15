# SPDX-License-Identifier: Apache-2.0
"""What one autofix patches, and whether the images it built are fixed.

The findings an autofix is asked to fix name CVEs, not images, so the
images production runs are scanned first, the way the deploy guard scans
a release (quarantine_gate.scan_release_images: the project's posture,
hardening and suppressions, the fresh known-exploited lists, the scan
cache by image ID). Every service whose image carries one of the CVEs is
patched, for every OS package the CVE is found in: a CVE left in one of
its packages would still be there after the patch.

A service that already runs a patched image is patched again from the
image its patch was built from (the record's base), with the packages of
both patches, so the new patch keeps the old one's fixes; a patch is
never built on another patch (cve.autofix_build).

The patched images are then scanned the same way. A patch fails when a
CVE it was for is still in its image, or a finding that is quarantine-level
under the project's posture is in it that was not quarantine-level in the
image it replaces.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from boxmunge.commands.quarantine_gate import StartImage, scan_release_images
from boxmunge.compose_resolve import ComposeResolveError
from boxmunge.container_recreate import managed
from boxmunge.container_update import UpdateError, running_images
from boxmunge.cve.kev import load_kev
from boxmunge.cve.policy_types import Disposition
from boxmunge.cve.scanner import PkgClass, ScannerError
from boxmunge.deployed_inventory import DeployedService, InventoryError, load_deployed_inventory
from boxmunge.docker_run import DockerError
from boxmunge.release_target import production_target
from boxmunge.state import StateError

if TYPE_CHECKING:
    from collections.abc import Collection, Mapping

    from boxmunge.commands.security_scan_inputs import ProjectMeta
    from boxmunge.cve.autofix_record import PatchRecord
    from boxmunge.cve.policy_types import ProjectDecision
    from boxmunge.docker_containers import ProjectContainer
    from boxmunge.image_pins import ImagePin
    from boxmunge.paths import BoxPaths

Step = Literal["probe", "build", "scan", "swap", "health", "budget"]
PROD = ["compose.yml", "compose.boxmunge.yml"]


class StepFailed(Exception):
    """An autofix step failed; `step` is the one, the message why."""

    def __init__(self, step: Step, reason: str) -> None:
        super().__init__(reason)
        self.step: Step = step


@dataclass(frozen=True)
class ServicePlan:
    """One service's patch: built FROM `base` (an image ID or exact digest;
    `base_ref` is how the record names it), upgrading each package of
    `floors` to at least every fixed version it lists (the CVEs' fixes can
    differ, and only the distro's own ordering in the image can compare
    them), from `before` (name: version in the base), for `cves`."""
    service: str
    base_ref: str
    base: str
    floors: Mapping[str, tuple[str, ...]]
    before: Mapping[str, str]
    cves: tuple[str, ...]

    @property
    def packages(self) -> dict[str, str]:
        """{package: a fixed version} for the build; check_floors checks the rest."""
        return {name: versions[0] for name, versions in self.floors.items()}

    def check_floors(self) -> list[dict[str, str]]:
        """The other fixed versions, as package maps for check_versions."""
        depth = max(len(v) for v in self.floors.values())
        return [{n: v[i] for n, v in self.floors.items() if len(v) > i}
                for i in range(1, depth)]


@dataclass(frozen=True)
class Running:
    """What production runs: {service: a container of it} and the scan of
    those images, {service: its decision}."""
    containers: dict[str, ProjectContainer]
    services: dict[str, DeployedService]
    decisions: dict[str, ProjectDecision]


def scan_images(paths: BoxPaths, project: str, meta: ProjectMeta,
                images: Mapping[str, str], label: str) -> dict[str, ProjectDecision]:
    """{service: decision} of an audit-only scan of `images` ({service:
    local image ref or ID}; `label` names them in a failure). Raises
    StepFailed("scan") when the scan fails or does not cover every image."""
    try:
        scan, _ids, targets, _profile = scan_release_images(
            paths, production_target(paths, project), meta,
            {svc: StartImage(ref, ref) for svc, ref in images.items()}, {}, load_kev(paths))
    except (ScannerError, StateError, OSError, RuntimeError, ComposeResolveError,
            DockerError) as e:   # what the deploy guard's scan of a release raises
        raise StepFailed("scan", f"the scan of {label} failed: {type(e).__name__}: {e}") from e
    if not scan.complete:
        raise StepFailed("scan", f"the scan of {label} did not cover every image: "
                         + "; ".join(scan.incomplete_reasons()))
    by_ref = {d.image_ref: d for d in scan.decisions}
    return {t.service: by_ref[t.image_ref] for t in targets}


def running(paths: BoxPaths, project: str, meta: ProjectMeta) -> Running:
    """Production's containers, one per service that has any, and the scan
    of their images. Raises StepFailed("scan")."""
    try:
        inventory = load_deployed_inventory(paths.project_dir(project), PROD, project)
        services = {n: s for n, s in inventory.services.items()
                    if managed(s.containers) or s.expected}
        containers = running_images(services)
    except (InventoryError, UpdateError) as e:
        raise StepFailed("scan", f"cannot tell what production runs: {e}") from e
    decisions = scan_images(paths, project, meta,
                            {svc: c.image_id for svc, c in containers.items()},
                            "the running images")
    return Running(containers, services, decisions)


def _fixes(decision: ProjectDecision, cves: Collection[str],
           service: str) -> tuple[dict[str, set[str]], dict[str, str], set[str]]:
    """({package: fixed versions}, {package: installed}, CVEs found) for every finding
    of `cves` in the image. Raises StepFailed("probe") for one autofix cannot
    patch: not an OS package, or no fixed version."""
    fixed: dict[str, set[str]] = {}
    before: dict[str, str] = {}
    found: set[str] = set()
    for fd in decision.findings:
        f = fd.finding
        if f.cve_id not in cves:
            continue
        if f.pkg_class is not PkgClass.OS or f.fixed_version is None:
            why = ("no fixed version is published" if f.fixed_version is None
                   else f"{f.package} is not an OS package ({f.pkg_class.value})")
            raise StepFailed("probe", f"{f.cve_id} in service {service} cannot be patched: "
                             f"{why}")
        found.add(f.cve_id)
        fixed.setdefault(f.package, set()).add(f.fixed_version)
        before[f.package] = f.installed_version
    return fixed, before, found


def plan(now: Running, cves: Collection[str], pins: Collection[ImagePin],
         records: Collection[PatchRecord]) -> tuple[ServicePlan, ...]:
    """The services to patch, by name. Raises StepFailed: "scan" when no
    running image carries any of `cves`, "probe" for one that cannot be
    patched or a pinned service with no patch record."""
    pinned = {p.service for p in pins}
    recorded = {r.service: r for r in records}
    plans = []
    for service in sorted(now.decisions):
        packages, before, found = _fixes(now.decisions[service], cves, service)
        if not found:
            continue
        base_ref, base = now.containers[service].image_ref, now.containers[service].image_id
        if service in pinned:
            prior = recorded.get(service)
            if prior is None:
                raise StepFailed("probe", f"service {service} runs a pinned patched image "
                                 f"with no patch record, so the image it was built from is "
                                 f"unknown")
            base_ref, base = prior.base_ref, prior.base_digest
            for change in prior.packages:
                packages.setdefault(change.name, set()).add(change.after)
                before[change.name] = change.before
            found |= set(prior.cves)
        plans.append(ServicePlan(service, base_ref, base,
                                 {n: tuple(sorted(v)) for n, v in packages.items()}, before,
                                 tuple(sorted(found))))
    if not plans:
        raise StepFailed("scan", f"no image production runs carries {', '.join(sorted(cves))} "
                         f"any more, so there is nothing to patch")
    return tuple(plans)


def judge_patched(plans: Collection[ServicePlan], before: Mapping[str, ProjectDecision],
                  after: Mapping[str, ProjectDecision]) -> None:
    """Raises StepFailed("scan") naming each CVE a patched image still
    carries and each quarantine-level finding it brought in."""
    problems = []
    for p in plans:
        was = {(fd.finding.cve_id, fd.finding.package) for fd in before[p.service].findings
               if fd.disposition is Disposition.QUARANTINE}
        for fd in after[p.service].findings:
            key = (fd.finding.cve_id, fd.finding.package)
            if fd.finding.cve_id in p.cves:
                problems.append(f"{key[0]} is still in {key[1]} "
                                f"{fd.finding.installed_version} in service {p.service}")
            elif fd.disposition is Disposition.QUARANTINE and key not in was:
                problems.append(f"the patch brought {key[0]} in {key[1]} "
                                f"{fd.finding.installed_version} into service {p.service}, "
                                f"quarantine-level under the project's posture")
    if problems:
        raise StepFailed("scan", "the patched image is not fixed: " + "; ".join(problems))
