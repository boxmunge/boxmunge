# SPDX-License-Identifier: Apache-2.0
"""Run one autofix on one project, under its project lock.

The steps, each a `failed_step` of the outcome when it fails:

- scan: the images production runs are scanned to find the services that
  carry the CVEs, and the packages to upgrade (cve.autofix_plan); later,
  the patched images are scanned and judged;
- probe, then build, per service: the base image is probed and the
  patched image built from it (cve.autofix_build);
- swap: every patched service of the project is pinned at once
  (image_pins.write_pins renders the overlay with all of them), and the
  project's containers recreated through the start checks;
- health: every service the project runs must come back healthy
  (container_recreate.wait_healthy);
- budget: the `deadline` passed. It is checked between steps; a step that
  is running when it passes finishes, then the run rolls back.

The patch records are written only once the services are healthy.

Just before the swap the run writes its journal (cve.autofix_record: the
pins and patch records it found, the images it built). Once the patched
images are healthy and their records written, it removes it, and only then
the images they replace; when that removal fails, the replaced images are
kept (logged), so the journal's pins still name images that exist. A failed run removes it once rolled back. A journal left behind
means the run was killed; recover_interrupted undoes it the way a rollback
would, records included.

On any failure the run rolls back, whatever the project's container-update
`strategy` (a patch that failed is never left running): once the swap has
begun, the pins the project had are restored exactly (or cleared when it
had none) and its containers recreated and waited for; then every image
this run built is removed, by the name it was given. A rollback failure
is added to the outcome's reason and logged; it never replaces the step
that failed. An exception no step expects rolls back the same way and is
raised, with the rollback's failures as notes on it.

The swap and the rollback start the project's containers whatever had
stopped them: a flow that patches a project it quarantined lifts the
quarantine on success, and re-asserts it on failure.

The runner alerts nobody (the urgent and nightly flows do), and leaves the
autofixing marker to them; it writes an oplog entry when it starts and one
with its outcome, naming the project, the services, the CVEs, the step
and the reason.
"""
from __future__ import annotations

from collections.abc import Callable, Collection, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from boxmunge.compose_guard import ComposeRefused
from boxmunge.container_recreate import recreate_project, start_refusal, wait_healthy
from boxmunge.container_update import one_shot_services
from boxmunge.commands.security_scan_inputs import load_project_meta
from boxmunge.cve import autofix_plan
from boxmunge.cve.autofix_build import (
    NotPatchable, Patchable, PatchBuildError, PatchedImage, build_patched, check_versions,
    probe, remove_patched,
)
from boxmunge.cve.autofix_plan import PROD, ServicePlan, Step, StepFailed
from boxmunge.cve.autofix_record import (
    AutofixJournal, PackageChange, PatchRecord, Trigger, read_journal, read_records,
    remove_journal, write_journal, write_records,
)
from boxmunge.docker_run import DockerError
from boxmunge.fileutil import LockError, project_lock
from boxmunge.image_pins import ImagePin, clear_pins, read_pins, write_pins
from boxmunge.log import log_error, log_operation
from boxmunge.state import StateError

if TYPE_CHECKING:
    from boxmunge.cve.policy_types import FindingDisposition
    from boxmunge.deployed_inventory import DeployedService
    from boxmunge.paths import BoxPaths

_COMPONENT = "autofix"


@dataclass(frozen=True)
class AutofixOutcome:
    """`rollback_problems`: what a failed run's rollback could not undo, one
    line each (also in `reason`); empty when it was undone cleanly. When it
    is not empty the project may be left mixed (pins restored, containers
    still on a patched image): the flows alert it. `detected_at` and
    `started_at`: when the findings were found and the attempt began, set
    by the flow that queued them (None from the runner itself)."""
    ok: bool
    failed_step: Step | None
    reason: str
    records: tuple[PatchRecord, ...]
    rollback_problems: tuple[str, ...] = ()
    detected_at: datetime | None = None
    started_at: datetime | None = None


@dataclass
class _Run:
    """What this run changed, for the rollback."""
    project: str
    pins_before: tuple[ImagePin, ...]
    # The services being patched, and every service production runs.
    patching: list[str] = field(default_factory=list)
    deployed: dict[str, DeployedService] = field(default_factory=dict)
    built: list[tuple[str, PatchedImage]] = field(default_factory=list)
    swapped: bool = False
    # The CVEs of the patch the caller quarantined the project for; () when
    # it did not (container_recreate.start_refusal).
    patch_cves: tuple[str, ...] = ()
    records_before: tuple[PatchRecord, ...] = ()


def _require_lock_held(paths: BoxPaths, project: str) -> None:
    """The caller holds the project lock: taking it here must fail."""
    try:
        with project_lock(project, paths):
            pass
    except LockError:
        return
    raise RuntimeError(f"autofix of {project} runs under its project lock, which the "
                       f"caller does not hold")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _check_deadline(deadline: datetime) -> None:
    if _now() >= deadline:
        raise StepFailed("budget", f"the time budget ran out at {deadline.isoformat()}")


def autofix_project_locked(paths: BoxPaths, project: str,
                           findings: Sequence[FindingDisposition], *, trigger: Trigger,
                           deadline: datetime, quarantined_for_patch: bool) -> AutofixOutcome:
    """Patch the CVEs of `findings` in every image of `project` that carries
    them, swap the patched images in and wait for the project to be
    healthy, by `deadline` (timezone-aware). The caller holds the project
    lock for the whole run (RuntimeError otherwise). A project the platform
    keeps down is refused at the swap, nothing started, unless
    `quarantined_for_patch` (the caller quarantined it for this patch: the
    dark patch), the quarantine is for one of the patch's CVEs, and it is
    all that keeps the project down. Returns the
    outcome; a failed one has been rolled back."""
    if deadline.tzinfo is None:
        raise ValueError(f"deadline {deadline.isoformat()} has no timezone")
    cves = tuple(sorted({fd.finding.cve_id for fd in findings}))
    if not cves:
        raise ValueError("autofix needs at least one finding to fix")
    _require_lock_held(paths, project)
    run = _Run(project, read_pins(paths, project),
               patch_cves=cves if quarantined_for_patch else ())
    log_operation(_COMPONENT, f"Autofix of {project} started for {', '.join(cves)}", paths,
                  project=project, detail={"cves": list(cves), "trigger": trigger,
                                           "deadline": deadline.isoformat()})
    try:
        records = _steps(paths, run, cves, trigger, deadline)
    except StepFailed as e:
        problems = tuple(_rollback(paths, run))
        _finish(paths, project)
        reason = "; ".join([str(e), *problems])
        return _outcome(paths, run, cves, AutofixOutcome(False, e.step, reason, (), problems))
    except BaseException as e:
        problems = _rollback(paths, run)
        _finish(paths, project)
        for problem in problems:
            e.add_note(problem)
        log_error(_COMPONENT, f"Autofix of {project} failed unexpectedly and was rolled back: "
                  f"{type(e).__name__}: {e}", paths, project=project,
                  detail={"cves": list(cves), "services": run.patching, "rollback": problems})
        raise
    return _outcome(paths, run, cves, AutofixOutcome(
        True, None, f"patched {', '.join(run.patching)}", records))


def _finish(paths: BoxPaths, project: str) -> bool:
    """The journal goes: the patched images are healthy, or the run was
    rolled back. Logged, not raised (a journal left makes the next run undo
    the run); returns whether it went."""
    try:
        remove_journal(paths, project)
    except StateError as e:
        log_error(_COMPONENT, f"Autofix of {project}: {e}; the next autofix of it will roll "
                  f"back to the journal", paths, project=project)
        return False
    return True


def recover_interrupted(paths: BoxPaths, project: str, *,
                        patch_cves: Collection[str]) -> tuple[str, ...] | None:
    """Undo an autofix run that was killed before it finished, from its
    journal: restore the pins it found, recreate the containers, remove the
    images it built (`patch_cves`: the CVEs of the queued patch the project
    was quarantined for, else empty).
    None when there is no journal; else what could not be undone, one line
    each. The caller holds the project lock. Raises
    StateError for a journal it cannot read."""
    _require_lock_held(paths, project)
    journal = read_journal(paths, project)
    if journal is None:
        return None
    run = _Run(project, journal.pins_before, swapped=True,
               patch_cves=tuple(patch_cves),
               built=[(p.service, PatchedImage(p.ref, p.image_id, {})) for p in journal.built])
    problems = _rollback(paths, run)
    try:
        write_records(paths, project, journal.records_before)
    except StateError as e:
        problems.append(f"rollback could not restore the patch records: {e}")
        log_error(_COMPONENT, f"Autofix of {project}: {problems[-1]}", paths, project=project)
    remove_journal(paths, project)
    problems = tuple(problems)
    log_error(_COMPONENT, f"Autofix of {project} started {journal.started_at.isoformat()} was "
              f"interrupted and has been rolled back"
              + (f"; {'; '.join(problems)}" if problems else ""), paths, project=project,
              detail={"rollback": list(problems)})
    return problems


def _steps(paths: BoxPaths, run: _Run, cves: tuple[str, ...], trigger: Trigger,
           deadline: datetime) -> tuple[PatchRecord, ...]:
    project = run.project
    _check_deadline(deadline)
    meta = load_project_meta(paths, project)
    now = autofix_plan.running(paths, project, meta)
    run.deployed = now.services
    run.records_before = read_records(paths, project)
    plans = autofix_plan.plan(now, cves, run.pins_before, run.records_before)
    run.patching = [p.service for p in plans]
    for p in plans:
        _check_deadline(deadline)
        patchability = _probe(p)
        _check_deadline(deadline)
        _build(run, p, patchability)
    _check_deadline(deadline)
    patched = dict(run.built)
    after = autofix_plan.scan_images(paths, project, meta,
                                     {svc: img.ref for svc, img in patched.items()},
                                     "the patched images")
    autofix_plan.judge_patched(plans, now.decisions, after)
    _check_deadline(deadline)
    _swap(paths, run, patched)
    _check_deadline(deadline)
    _health(project, now.services, "the patched images")
    _check_deadline(deadline)
    records = _record(paths, project, plans, patched, trigger)
    # Recorded: a recovery from here would restore the pins and records alike.
    if _finish(paths, project):
        _remove_replaced(paths, run, patched)
    else:   # the journal's pins_before must still name images that exist
        log_error(_COMPONENT, f"Autofix of {project}: the images the patch replaced are kept, "
                  f"since its journal is still there", paths, project=project)
    return records


def _probe(p: ServicePlan) -> Patchable:
    try:
        found = probe(p.base)
    except DockerError as e:
        raise StepFailed("probe", f"probing {p.service}'s image failed: {e}") from e
    if isinstance(found, NotPatchable):
        raise StepFailed("probe", f"{p.service}'s image cannot be patched: {found.reason}")
    return found


def _build(run: _Run, p: ServicePlan, patchability: Patchable) -> None:
    """Build the patch (into run.built, for the rollback), then check every
    other fixed version a package has against the image's own ordering."""
    try:
        image = build_patched(run.project, p.service, p.base, p.packages, patchability)
        run.built.append((p.service, image))
        for floors in p.check_floors():
            check_versions(image.image_id, patchability, floors)
    except (PatchBuildError, DockerError) as e:
        raise StepFailed("build", f"building {p.service}'s patched image failed: {e}") from e


def _remove_replaced(paths: BoxPaths, run: _Run, patched: dict[str, PatchedImage]) -> None:
    """Remove the earlier patched image of each service patched again, by
    its pin's own ref. Logged, not raised: the patch is in place."""
    for pin in run.pins_before:
        if pin.service in patched and patched[pin.service].ref != pin.ref:
            try:
                remove_patched(pin)
            except (PatchBuildError, DockerError) as e:
                log_error(_COMPONENT, f"Autofix of {run.project}: could not remove the "
                          f"replaced patched image {pin.ref}: {e}", paths, project=run.project)


def _swap(paths: BoxPaths, run: _Run, patched: dict[str, PatchedImage]) -> None:
    kept = [pin for pin in run.pins_before if pin.service not in patched]
    pins = kept + [ImagePin(svc, img.ref, img.image_id, "autofix")
                   for svc, img in patched.items()]
    # Asked before anything changes, so a refusal starts and swaps nothing;
    # recreate_project asks again (the state may change under a bug).
    refusal = start_refusal(paths, run.project, patch_cves=run.patch_cves)
    if refusal is not None:
        raise StepFailed("swap", f"the patched images were not swapped in: {refusal}")
    try:
        write_journal(paths, run.project, AutofixJournal(
            _now(), run.pins_before, run.records_before,
            tuple(ImagePin(svc, img.ref, img.image_id, "autofix") for svc, img in run.built)))
    except StateError as e:
        raise StepFailed("swap", f"the autofix journal could not be written: {e}") from e
    run.swapped = True   # from here the rollback restores the pins and recreates
    try:
        write_pins(paths, run.project, pins)
        recreate_project(paths, run.project, PROD, component=_COMPONENT,
                         patch_cves=run.patch_cves)
    except (ValueError, StateError, OSError, ComposeRefused, DockerError) as e:
        raise StepFailed("swap", f"swapping the patched images in failed: {e}") from e


def _health(project: str, services: dict[str, DeployedService], images: str) -> None:
    try:
        healthy, unhealthy = wait_healthy(project, list(services), one_shot_services(services))
    except DockerError as e:
        raise StepFailed("health", f"the health check could not read the containers: "
                         f"{e}") from e
    if not healthy:
        raise StepFailed("health", f"not healthy on {images}: {', '.join(unhealthy)}")


def _record(paths: BoxPaths, project: str, plans: Sequence[ServicePlan],
            patched: dict[str, PatchedImage], trigger: Trigger) -> tuple[PatchRecord, ...]:
    when = _now()
    new = tuple(PatchRecord(
        project=project, service=p.service, base_ref=p.base_ref, base_digest=p.base,
        patched_ref=patched[p.service].ref, patched_image_id=patched[p.service].image_id,
        packages=tuple(PackageChange(name, p.before[name], patched[p.service].versions[name])
                       for name in sorted(p.packages)),
        cves=p.cves, created_at=when, trigger=trigger) for p in plans)
    try:
        kept = [r for r in read_records(paths, project) if r.service not in patched]
        write_records(paths, project, [*kept, *new])
    except StateError as e:
        raise StepFailed("swap", f"the patch could not be recorded: {e}") from e
    return new


def _rollback(paths: BoxPaths, run: _Run) -> list[str]:
    """Undo what the run changed; what could not be undone, one line each."""
    problems: list[str] = []
    project = run.project

    def attempt(what: str, step: Callable[[], object]) -> bool:
        try:
            step()
            return True
        except Exception as e:   # every undo step runs; each failure is reported
            problems.append(f"rollback could not {what}: {type(e).__name__}: {e}")
            return False

    if run.swapped:
        restore = ((lambda: write_pins(paths, project, run.pins_before)) if run.pins_before
                   else (lambda: clear_pins(paths, project)))
        if attempt("restore the previous image pins", restore) and attempt(
                "recreate the previous containers",
                lambda: recreate_project(paths, project, PROD, component=_COMPONENT,
                                         patch_cves=run.patch_cves)):
            attempt("see the previous containers healthy",
                    lambda: _health(project, run.deployed, "the previous images"))
    keep = {pin.ref for pin in run.pins_before}
    for service, image in run.built:
        if image.ref not in keep:
            attempt(f"remove the patched image {image.ref}", lambda s=service, i=image:
                    remove_patched(ImagePin(s, i.ref, i.image_id, "autofix")))
    for problem in problems:
        log_error(_COMPONENT, f"Autofix of {project}: {problem}", paths, project=project)
    return problems


def _outcome(paths: BoxPaths, run: _Run, cves: tuple[str, ...],
             outcome: AutofixOutcome) -> AutofixOutcome:
    project, services = run.project, run.patching
    detail = {"cves": list(cves), "services": services, "ok": outcome.ok,
              "step": outcome.failed_step, "reason": outcome.reason,
              "rollback_problems": list(outcome.rollback_problems)}
    if outcome.ok:
        log_operation(_COMPONENT, f"Autofix of {project} patched {', '.join(services)} for "
                      f"{', '.join(cves)}", paths, project=project, detail=detail)
    else:
        log_error(_COMPONENT, f"Autofix of {project} failed at {outcome.failed_step}, rolled "
                  f"back: {outcome.reason}", paths, project=project, detail=detail)
    return outcome
