# SPDX-License-Identifier: Apache-2.0
"""Upstream catch-up: a patched image gives way to upstream (CVE autofix
design, "When upstream catches up"; flowcharts, chart 4).

Container update leaves a pinned service alone: the overlay runs its
patched image, which no registry serves. The nightly autofix of a project
container update has just updated or found unchanged
(commands.autofix_nightly) catches each pinned image service up with its
upstream first, under the same project lock, while a patch could still
start in the maintenance window (reconcile_upstream):

- the image the release itself names for the service (its overlay rendered
  without the pins) is pulled, as container update pulls image services,
  and held back the same way when the new image changes the user the
  service runs as (user_drift);
- that image is still the one the patch was built from: the patch is kept,
  and nothing is said;
- a new image is scanned the way the deploy guard scans a release (the
  project's posture, the fresh known-exploited lists, the scan cache by
  image ID). Clean of every CVE of the service's patch record, and with no
  quarantine-level finding the patched image does not have: the pin and
  the record go, production is recreated on the upstream image and must
  come back healthy. When it does not, the pin and the record are put back
  and production recreated on the patch (rolled back);
- a new image that still needs any of that patched: the patch is built
  again FROM the new image (cve.autofix_run.repatch_on_upstream_locked),
  never from the old patched image, and replaces the old one; a failed
  patch keeps the old one.

A build service is not caught up here: the base of its patch is an image
this box built, and only a deploy brings a new build (and forgets the pins
of the release it replaces). A project with `security.autofix: false`
keeps its patch until its next deploy.
"""
from __future__ import annotations

import tempfile
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from boxmunge.commands.security_scan_inputs import load_project_meta
from boxmunge.compose import load_user_compose, render_compose_override
from boxmunge.compose_images import is_platform_image
from boxmunge.container_recreate import managed, recreate_project, start_refusal, wait_healthy
from boxmunge.container_update import one_shot_services
from boxmunge.cve import autofix_plan
from boxmunge.cve.autofix_build import PatchBuildError, remove_patched
from boxmunge.cve.autofix_plan import PROD, StepFailed
from boxmunge.cve.autofix_policy import AUTOFIX_NIGHTLY_BUDGET
from boxmunge.cve.autofix_record import read_records, write_records
from boxmunge.cve.autofix_run import repatch_on_upstream_locked, require_lock_held
from boxmunge.cve.policy_types import Disposition
from boxmunge.deployed_inventory import load_deployed_inventory
from boxmunge.docker import compose_pull
from boxmunge.docker_containers import local_image
from boxmunge.docker_run import DockerError
from boxmunge.image_pins import clear_pins, read_pins, write_pins
from boxmunge.lifecycle import is_blocked
from boxmunge.log import log_error, log_operation
from boxmunge.manifest import load_manifest
from boxmunge.release_target import production_target, resolved_services
from boxmunge.user_drift import guard_pull

if TYPE_CHECKING:
    from boxmunge.cve.autofix_record import PatchRecord
    from boxmunge.cve.policy_types import FindingDisposition, ProjectDecision
    from boxmunge.deployed_inventory import DeployedService
    from boxmunge.image_pins import ImagePin
    from boxmunge.paths import BoxPaths
    from boxmunge.release_target import ReleaseTarget

_COMPONENT = "autofix"
Reconciled = Literal["kept", "switched", "repatched"]


class UpstreamFailed(Exception):
    """Catching a pinned service up with upstream failed; whatever it changed
    was rolled back, except `rollback_problems` (one line each)."""

    def __init__(self, reason: str, rollback_problems: Sequence[str] = ()) -> None:
        super().__init__(reason)
        self.rollback_problems = tuple(rollback_problems)


@dataclass(frozen=True)
class UpstreamResult:
    """One pinned service caught up: `outcome`, or None when it failed
    (`reason`, and what its rollback could not undo). `service` None: the
    project's pins could not be read. `cves`: its patch record's."""
    project: str
    service: str | None
    outcome: Reconciled | None
    cves: tuple[str, ...] = ()
    reason: str = ""
    rollback_problems: tuple[str, ...] = ()


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class _Release:
    """The release as it runs without its pins: the scratch target, and
    {service: the image it names} (None: a build, or a build of the
    project's another service runs)."""
    target: ReleaseTarget
    images: dict[str, str | None]


@contextmanager
def _release_images(paths: BoxPaths, project: str) -> Iterator[_Release]:
    """The release with its overlay rendered as a release switch renders
    it, without the pins (`installing`), in a scratch file that lasts as
    long as the context."""
    manifest = load_manifest(paths.project_manifest(project))
    user_compose = load_user_compose(paths.project_dir(project) / "compose.yml", project)
    with tempfile.TemporaryDirectory(prefix="boxmunge-upstream-") as scratch:
        overlay = Path(scratch) / "compose.boxmunge.yml"
        overlay.write_text(render_compose_override(paths, manifest, user_compose,
                                                   installing=True))
        target = production_target(paths, project, overlay)
        _model, services = resolved_services(target)
        images: dict[str, str | None] = {}
        for name, svc in services.items():
            ref = svc.get("image")
            images[name] = (ref if isinstance(ref, str) and ref and "build" not in svc
                            and not is_platform_image(ref) else None)
        yield _Release(target, images)


def _pull_upstream(paths: BoxPaths, project: str, target: ReleaseTarget, service: str,
                   ref: str) -> str:
    """Pull `ref` for `service`, as container update pulls; the image ID it
    names now. Raises UpstreamFailed for a new image that changes the
    service's user (held back: its tag points back), DockerError."""
    before = local_image(ref)
    c = target.compose
    compose_pull(c.cwd, list(c.files), project_name=project, services=[service])
    pulled = local_image(ref)
    if pulled is None:
        raise UpstreamFailed(f"{ref} is not in the local image store after the pull")
    drift = guard_pull(paths, project, {service: ref},
                       {service: before.image_id if before is not None else None},
                       component=_COMPONENT)
    if drift:
        raise UpstreamFailed(f"the new upstream image is held back: {drift[service]}")
    return pulled.image_id


def reconcile_upstream(paths: BoxPaths, project: str, *,
                       start_by: datetime) -> tuple[UpstreamResult, ...]:
    """Catch each pinned image service of `project` up with its upstream,
    one by one, none started after `start_by` (the rest wait for the next
    window), on a project nothing keeps down. The caller holds the project
    lock. A failure is logged and is one of the results; nothing is raised."""
    try:
        pins = read_pins(paths, project)
        if not pins or is_blocked(project, paths) is not None \
                or not load_project_meta(paths, project).autofix:
            return ()
        records = {r.service: r.cves for r in read_records(paths, project)}
    except Exception as e:  # noqa: BLE001 — reported as the project's result
        return (_failed(paths, project, None, (), e),)
    results: list[UpstreamResult] = []
    try:
        with _release_images(paths, project) as release:
            for pin in pins:
                if _now() > start_by:
                    log_operation(_COMPONENT, f"{project}: upstream catch-up of the rest "
                                  f"waits for the next maintenance window", paths,
                                  project=project)
                    break
                result = _catch_up(paths, project, release, pin.service,
                                   records.get(pin.service, ()))
                if result is not None:
                    results.append(result)
    except Exception as e:  # noqa: BLE001 — the release could not be resolved
        done = {r.service for r in results}
        results += [_failed(paths, project, p.service, records.get(p.service, ()), e)
                    for p in pins if p.service not in done]
    return tuple(results)


def _catch_up(paths: BoxPaths, project: str, release: _Release, service: str,
              cves: tuple[str, ...]) -> UpstreamResult | None:
    ref = release.images.get(service)
    if ref is None:
        log_operation(_COMPONENT, f"{project}/{service}: not caught up with upstream: it "
                      f"is a build, which a deploy brings anew", paths, project=project)
        return None
    try:
        digest = _pull_upstream(paths, project, release.target, service, ref)
        outcome = reconcile_pinned_service(paths, project, service, digest)
    except Exception as e:  # noqa: BLE001 — rolled back; one result of the run
        return _failed(paths, project, service, cves, e)
    return UpstreamResult(project, service, outcome, cves)


def _failed(paths: BoxPaths, project: str, service: str | None, cves: tuple[str, ...],
            e: Exception) -> UpstreamResult:
    problems = (e.rollback_problems if isinstance(e, UpstreamFailed)
                else tuple(getattr(e, "__notes__", ())))
    reason = str(e) if isinstance(e, UpstreamFailed) else f"{type(e).__name__}: {e}"
    log_error(_COMPONENT, f"{project}/{service or '*'}: upstream catch-up failed: {reason}",
              paths, project=project, detail={"rollback": list(problems)})
    return UpstreamResult(project, service, None, cves, reason, problems)


def reconcile_pinned_service(paths: BoxPaths, project: str, service: str,
                             upstream_digest: str) -> Reconciled:
    """Chart 4 for one pinned `service`, whose release's image now names
    `upstream_digest`: "kept" when that is the image its patch was built
    from, "switched" to it when it is clean, else "repatched" from it. The
    caller holds the project lock (RuntimeError otherwise). Raises
    UpstreamFailed, its changes rolled back; ValueError for a service that
    is not pinned."""
    require_lock_held(paths, project)
    pins = read_pins(paths, project)
    pin = next((p for p in pins if p.service == service), None)
    if pin is None:
        raise ValueError(f"service {service} of {project} is not pinned")
    records = read_records(paths, project)
    record = next((r for r in records if r.service == service), None)
    if record is None:
        raise UpstreamFailed(f"service {service} runs a pinned patched image with no patch "
                             f"record, so the image it was built from is unknown")
    if upstream_digest == record.base_digest:
        return "kept"
    meta = load_project_meta(paths, project)
    try:
        upstream = autofix_plan.scan_images(paths, project, meta, {service: upstream_digest},
                                            "the new upstream image")[service]
        patched = autofix_plan.scan_images(paths, project, meta, {service: pin.image_id},
                                           "the patched image")[service]
    except StepFailed as e:
        raise UpstreamFailed(str(e)) from e
    still = _still_to_patch(upstream, patched, record.cves)
    if not still:
        _switch(paths, project, pin, pins, records)
        return "switched"
    image = local_image(upstream_digest)
    if image is None:
        raise UpstreamFailed(f"the new upstream image {upstream_digest[:19]} is gone")
    outcome = repatch_on_upstream_locked(paths, project, still, upstream={service: image},
                                         deadline=_now() + AUTOFIX_NIGHTLY_BUDGET)
    if not outcome.ok:
        raise UpstreamFailed(f"patching the new upstream image failed at "
                             f"{outcome.failed_step or 'an unexpected error'}: "
                             f"{outcome.reason}", outcome.rollback_problems)
    return "repatched"


def _still_to_patch(upstream: ProjectDecision, patched: ProjectDecision,
                    cves: Sequence[str]) -> list[FindingDisposition]:
    """The findings of the new upstream image that keep it from replacing the
    patch: a CVE the patch fixed, or a quarantine-level one the patched
    image does not have."""
    had = {(fd.finding.cve_id, fd.finding.package) for fd in patched.findings
           if fd.disposition is Disposition.QUARANTINE}
    return [fd for fd in upstream.findings if fd.finding.cve_id in cves
            or (fd.disposition is Disposition.QUARANTINE
                and (fd.finding.cve_id, fd.finding.package) not in had)]


class _Unhealthy(Exception):
    pass


def _services(paths: BoxPaths, project: str) -> dict[str, DeployedService]:
    inventory = load_deployed_inventory(paths.project_dir(project), PROD, project)
    return {n: s for n, s in inventory.services.items() if managed(s.containers) or s.expected}


def _healthy(project: str, services: dict[str, DeployedService], images: str) -> None:
    healthy, unhealthy = wait_healthy(project, list(services), one_shot_services(services))
    if not healthy:
        raise _Unhealthy(f"not healthy on {images}: {', '.join(unhealthy)}")


def _set_pins(paths: BoxPaths, project: str, pins: Sequence[ImagePin]) -> None:
    if pins:
        write_pins(paths, project, pins)
    else:
        clear_pins(paths, project)


def _switch(paths: BoxPaths, project: str, pin: ImagePin, pins: Sequence[ImagePin],
            records: Sequence[PatchRecord]) -> None:
    """Unpin `pin`'s service, drop its record, recreate production on
    upstream and see it healthy; on failure put both back and recreate."""
    refusal = start_refusal(paths, project)
    if refusal is not None:
        raise UpstreamFailed(f"not switched to upstream: {refusal}")
    try:
        services = _services(paths, project)
    except Exception as e:  # noqa: BLE001 — nothing changed yet
        raise UpstreamFailed(f"cannot tell what production runs: {e}") from e
    try:
        _set_pins(paths, project, [p for p in pins if p.service != pin.service])
        write_records(paths, project, [r for r in records if r.service != pin.service])
        recreate_project(paths, project, PROD, component=_COMPONENT)
        _healthy(project, services, "the new upstream image")
    except Exception as e:  # noqa: BLE001 — every failure rolls back
        problems = _restore(paths, project, pins, records, services)
        raise UpstreamFailed(f"switching {pin.service} to upstream failed: "
                             f"{type(e).__name__}: {e}", problems) from e
    except BaseException as e:
        for problem in _restore(paths, project, pins, records, services):
            e.add_note(problem)
        raise
    log_operation(_COMPONENT, f"{project}/{pin.service} switched to upstream; its patch "
                  f"record is cleared", paths, project=project)
    try:
        remove_patched(pin)
    except (PatchBuildError, DockerError) as e:
        log_error(_COMPONENT, f"{project}: could not remove the replaced patched image "
                  f"{pin.ref}: {e}", paths, project=project)


def _restore(paths: BoxPaths, project: str, pins: Sequence[ImagePin],
             records: Sequence[PatchRecord],
             services: dict[str, DeployedService]) -> list[str]:
    """Put the pins and records back and recreate production on them; what
    could not be undone, one line each (logged)."""
    problems: list[str] = []

    def attempt(what: str, step: Callable[[], object]) -> bool:
        try:
            step()
            return True
        except Exception as e:   # every undo step runs; each failure is reported
            problems.append(f"rollback could not {what}: {type(e).__name__}: {e}")
            return False

    if attempt("restore the image pins", lambda: _set_pins(paths, project, pins)) \
            and attempt("restore the patch records",
                        lambda: write_records(paths, project, records)) \
            and attempt("recreate the patched containers",
                        lambda: recreate_project(paths, project, PROD, component=_COMPONENT)):
        attempt("see the patched containers healthy",
                lambda: _healthy(project, services, "the patched images"))
    for problem in problems:
        log_error(_COMPONENT, f"{project}: upstream catch-up: {problem}", paths,
                  project=project)
    return problems
