# SPDX-License-Identifier: Apache-2.0
"""Per-project CVE scan body — evaluate each image, persist, act.

Runs under the per-project lock. Inputs (manifest meta, image
identification, suppressions) come from security_scan_inputs.py; fleet
orchestration (grace heads-up, exit codes, lock-skip handling) lives in
security_actions.py.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import date, datetime, timezone

from boxmunge.commands.security_scan_inputs import (
    ProjectMeta,
    ScanTarget,
    hardening_profile,
    identify_images,
    load_all_suppressions,
    load_project_meta,
)
from boxmunge.cve.alerting import emit_scan_alerts
from boxmunge.cve.grace import GraceError, init_grace_if_missing
from boxmunge.cve.kev import KevCatalog, load_kev
from boxmunge.cve.policy import (
    Disposition,
    FindingDisposition,
    Posture,
    ProjectDecision,
    evaluate_finding,
    evaluate_project,
)
from boxmunge.cve.quarantine import (
    QuarantineError,
    is_quarantined,
    quarantine_project,
    reassert_quarantine,
)
from boxmunge.cve.relevance import (
    ecosystem_for_package,
    effective_runtimes,
    unrecognised_lang_types,
)
from boxmunge.cve.scan_state import (
    decisions_from_scan_state,
    read_scan_state,
    write_scan_state,
)
from boxmunge.cve.scanner import (
    _DEFAULT_TIMEOUT,
    PkgClass,
    ScanResult,
    ScannerError,
    TrivyNotInstalledError,
    scan_image,
)
from boxmunge.fileutil import project_lock
from boxmunge.log import log_warning
from boxmunge.paths import BoxPaths


# Per-project aggregate scan budget.
#
# Trivy's per-image timeout (cve.scanner._DEFAULT_TIMEOUT = 300s) bounds a
# single scan; this budget bounds the *sum* across all images of one project.
# Without it, a project with N images each timing out would consume
# N * 300s of the systemd unit's TimeoutStartSec — starving every project
# that hasn't been scanned yet. With it, a single hung image consumes at
# most 600s of wall time and the next project gets its fair share.
#
# Companion to systemd/boxmunge-cve-scan.service's TimeoutStartSec=60m:
# the per-project budget is the inner cap, the unit timeout is the outer.
_PROJECT_BUDGET_SECONDS = 600


@dataclass(frozen=True)
class ProjectScan:
    """Everything one project scan learned.

    ``failed_images`` errored in Trivy, ``skipped_images`` were cut by the
    per-project budget, and ``unidentified_services`` had no image that
    could be resolved. Any of the three means the scan is incomplete: the
    decisions cover only part of what the project runs.
    """

    project: str
    posture: str
    dangerously: bool
    decisions: tuple[ProjectDecision, ...]
    warnings: tuple[str, ...]
    failed_images: tuple[str, ...] = ()
    skipped_images: tuple[str, ...] = ()
    unidentified_services: tuple[str, ...] = ()
    headline: tuple[ProjectDecision, FindingDisposition] | None = None

    @property
    def complete(self) -> bool:
        return not (
            self.failed_images or self.skipped_images or self.unidentified_services
        )

    def incomplete_reasons(self) -> list[str]:
        """One human line per unscanned image or service."""
        out = [f"image {ref}: scan failed" for ref in self.failed_images]
        out += [f"image {ref}: skipped (scan budget exhausted)"
                for ref in self.skipped_images]
        out += [f"service {svc!r}: no image could be identified (no container "
                f"digest and no image: in compose.yml)"
                for svc in self.unidentified_services]
        return out


def _today() -> date:
    return datetime.now(timezone.utc).date()


def scan_one_project(
    paths: BoxPaths, project: str, *,
    in_grace: bool | None = None,
    audit_only: bool = False,
    kev: KevCatalog | None = None,
) -> ProjectScan:
    """Scan a single project, persist state, take quarantine action.

    ``ProjectScan.headline`` is the first (decision, finding) pair that
    requires quarantine, or None if nothing quarantines.

    When ``in_grace`` is True, both quarantine actions and per-project
    transition alerts are suppressed. The scan_state is still written
    so subsequent scans see correct prior state. When ``in_grace`` is
    None (the default for direct callers), this function lazily
    bootstraps grace state if missing and derives ``in_grace`` from the
    persisted state (audit F-2). The fleet scan entry-point
    (``cmd_security_scan``) already does its own bootstrap and passes
    the resolved value through explicitly.

    When ``audit_only`` is True, the function evaluates findings for the
    caller (so it can decide e.g. whether to lift quarantine) but does
    NOT mutate persisted state: scan_state.json is not written, no
    transition alerts are emitted, and no quarantine action fires. Used
    by `cmd_security_resume` so a re-scan during the resume flow does
    not clobber the prior scan_state context (audit A-3). Audit-only
    callers DO NOT lazy-bootstrap grace either.

    Concurrency: holds the per-project lock for its full body.

    Raises:
        LockError: when another operation holds the project lock.
        TrivyNotInstalledError: when the Trivy binary is missing.
        RuntimeError: on irrecoverable failures (manifest unreadable, all
            images failed to scan, quarantine action raised, grace state
            corrupt).
    """
    if in_grace is None:
        if audit_only:
            in_grace = False
        else:
            try:
                grace = init_grace_if_missing(
                    paths, now=datetime.now(timezone.utc),
                )
            except GraceError as e:
                raise RuntimeError(
                    f"CVE migration grace state is corrupt: {e}"
                ) from e
            in_grace = grace.is_active(now=datetime.now(timezone.utc))
    # Direct callers use the cached catalog without a refresh (no network).
    if kev is None:
        kev = load_kev(paths)
    with project_lock(project, paths):
        return _scan_one_project_locked(
            paths, project, in_grace=in_grace, audit_only=audit_only, kev=kev,
        )


def _prior_decisions(paths: BoxPaths, project: str) -> tuple[ProjectDecision, ...]:
    """The previous scan's decisions, for transition detection."""
    try:
        prior_state = read_scan_state(paths.project_scan_state(project))
        if prior_state is None:
            return ()
        return decisions_from_scan_state(prior_state, project_name=project)
    except (ValueError, KeyError, TypeError, AttributeError) as e:
        # Audit B-12: a truncated or hand-mangled file (JSON errors are
        # ValueErrors) must not stop this project's scan, let alone the
        # fleet's; this scan overwrites it.
        # A malformed prior state shouldn't block the scan; log and treat
        # as "no prior" (alerts will be emitted as if first scan).
        log_warning(
            "cve-scan",
            f"ignoring unreadable prior scan state for {project}: {e}",
            paths, project=project,
        )
        return ()


def _scan_targets(
    paths: BoxPaths, project: str, targets: list[ScanTarget],
) -> tuple[list[ScanResult], list[str], list[str], list[str]]:
    """Scan each target within the project budget.

    Returns (results, failed image refs, budget-skipped image refs, warnings).
    """
    results: list[ScanResult] = []
    failed: list[str] = []
    skipped: list[str] = []
    warnings: list[str] = []
    project_start = time.monotonic()
    for index, target in enumerate(targets):
        # The systemd unit timeout (60m) is the outer cap — without this
        # inner cap, one slow project could starve every project after it.
        elapsed = time.monotonic() - project_start
        remaining = _PROJECT_BUDGET_SECONDS - elapsed
        if remaining <= 0:
            skipped = [t.image_ref for t in targets[index:]]
            log_warning(
                "cve-scan",
                f"project {project} exceeded scan budget after "
                f"{elapsed:.0f}s — skipping remaining {len(skipped)} image(s)",
                paths, project=project,
                detail={
                    "elapsed_s": round(elapsed, 1),
                    "budget_s": _PROJECT_BUDGET_SECONDS,
                    "skipped_images": skipped,
                },
            )
            warnings.append(
                f"project budget exceeded after {elapsed:.0f}s — "
                f"skipped {len(skipped)} image(s)"
            )
            break
        # Cap the per-image timeout so one scan can't blow the budget alone.
        per_image_timeout = min(_DEFAULT_TIMEOUT, max(1, int(remaining)))
        try:
            results.append(scan_image(target.image_ref, timeout=per_image_timeout))
        except TrivyNotInstalledError:
            raise
        except ScannerError as e:
            log_warning(
                "cve-scan",
                f"scan failed for {project} image {target.image_ref}: {e}",
                paths, project=project,
                detail={"image_ref": target.image_ref, "error": str(e)},
            )
            failed.append(target.image_ref)
            warnings.append(f"image {target.image_ref}: scan failed ({e})")
    return results, failed, skipped, warnings


def _scan_one_project_locked(
    paths: BoxPaths, project: str, *,
    in_grace: bool,
    kev: KevCatalog,
    audit_only: bool = False,
) -> ProjectScan:
    """Inner scan body. Caller MUST hold the per-project lock."""
    meta = load_project_meta(paths, project)
    posture = meta.posture
    dangerously = meta.dangerously
    # `declared` is loop-invariant (one manifest, many images), so validate
    # it once before any Trivy scan runs: a malformed security.runtimes then
    # fails in milliseconds, and no early return below can skip validation
    # (load_manifest does not validate the security: block).
    declared = meta.declared_runtimes
    if declared is not None:
        try:
            effective_runtimes((), declared=declared)
        except (ValueError, TypeError) as e:
            raise RuntimeError(
                f"project {project!r}: invalid security.runtimes in "
                f"manifest: {e}"
            ) from e
    profile = hardening_profile(meta)
    # Host-scoped suppressions are for reviewed, accepted-risk findings; the
    # relevance gate handles "base-image package the project never invokes".
    supps = load_all_suppressions(paths, project)

    # Load the prior scan_state BEFORE we overwrite it (transition alerts).
    scan_state_path = paths.project_scan_state(project)
    prior_decisions = _prior_decisions(paths, project)

    targets, unidentified = identify_images(meta.manifest, meta.compose, project)
    warnings = [
        f"service {svc!r}: no running container and no image declared "
        f"in compose (build-only) — skipping"
        for svc in unidentified
    ]
    if not targets:
        # Persist an empty scan-state so we don't wedge the per-project view.
        # Audit-only (resume re-scan, audit A-3) leaves the prior alone.
        if not audit_only:
            enforce_error = _enforce(paths, project, meta, None, in_grace=in_grace)
            write_scan_state(scan_state_path, decisions=())
            _raise_enforce_error(project, enforce_error)
        return ProjectScan(
            project=project, posture=meta.posture_str, dangerously=dangerously,
            decisions=(), warnings=tuple(warnings),
            unidentified_services=tuple(unidentified),
        )

    results, failed, skipped, scan_warnings = _scan_targets(paths, project, targets)
    warnings.extend(scan_warnings)
    decisions: list[ProjectDecision] = []
    today = _today()

    def kev_lookup(cid: str) -> bool:
        return kev.is_known_exploited(cid, today=today)

    # Collected across every image but logged at most once per project scan.
    dropped_lang_types: set[str] = set()
    empty_runtime_exempted: set[str] = set()
    for sr in results:
        # `declared` was validated above; this only infers from lang_types.
        runtimes = effective_runtimes(sr.lang_types, declared=declared)
        if declared is None:
            # An unmapped Trivy lang-pkgs Type is dropped by infer_runtimes,
            # which biases toward OVER-exemption; surface it.
            dropped_lang_types |= unrecognised_lang_types(sr.lang_types)
        decision = evaluate_project(
            project, sr,
            posture=posture,
            hardening_profile=profile,
            dangerously_disable_quarantine=dangerously,
            suppressions=supps,
            today=today,
            kev_lookup=kev_lookup,
            runtimes=runtimes,
        )
        decisions.append(decision)
        if declared is None and not runtimes and posture in (
            Posture.BALANCED, Posture.STRICT,
        ):
            empty_runtime_exempted |= _gate_exempted_packages(
                decision, posture=posture, dangerously=dangerously,
                suppressions=supps, today=today, kev_lookup=kev_lookup,
            )

    _log_relevance_gaps(paths, project, dropped_lang_types, empty_runtime_exempted)

    headline = _headline(decisions)
    # Audit-only callers (resume re-scan, audit A-3) are the lift flow
    # itself and never act. Everyone else enforces: an existing quarantine
    # is re-asserted on every scan (B-03), a new one fires outside grace.
    enforce_error = None
    if not audit_only:
        enforce_error = _enforce(paths, project, meta, headline, in_grace=in_grace)

    if failed and not decisions:
        detail = f"; {enforce_error}" if enforce_error else ""
        raise RuntimeError(
            f"All images failed to scan for project {project!r}{detail}"
        )

    if not audit_only:
        write_scan_state(scan_state_path, decisions=tuple(decisions))

    # Transition alerts are best-effort; during grace the operator gets the
    # single fleet-level heads-up instead, and audit-only callers (resume)
    # must not push alerts.
    if not in_grace and not audit_only:
        _emit_transition_alerts(paths, project, decisions, prior_decisions, supps)
    _raise_enforce_error(project, enforce_error)

    return ProjectScan(
        project=project,
        posture=meta.posture_str,
        dangerously=dangerously,
        decisions=tuple(decisions),
        warnings=tuple(warnings),
        failed_images=tuple(failed),
        skipped_images=tuple(skipped),
        unidentified_services=tuple(unidentified),
        headline=headline,
    )


def _enforce(
    paths: BoxPaths, project: str, meta: ProjectMeta,
    headline: tuple[ProjectDecision, FindingDisposition] | None,
    *, in_grace: bool,
) -> str | None:
    """Take or re-assert the quarantine action. Returns an error or None.

    An existing quarantine record is re-asserted whatever this scan found,
    so a partially failed action converges (audit B-03). During grace no
    NEW quarantine fires; the heads-up alert summarises what would.
    """
    project_dir = paths.project_dir(project)
    try:
        if is_quarantined(project, paths):
            reassert_quarantine(
                project, paths, project_dir=project_dir,
                hosts=meta.hosts, compose_files=meta.compose_files,
            )
        elif headline is not None and not in_grace:
            quarantine_project(
                project, paths, project_dir=project_dir,
                hosts=meta.hosts, compose_files=meta.compose_files,
                headline=headline[1], image_ref=headline[0].image_ref,
            )
    except QuarantineError as e:
        return f"quarantine action failed for {project!r}: {e}"
    return None


def _raise_enforce_error(project: str, error: str | None) -> None:
    """Fail the project scan loudly once its state has been persisted."""
    if error is not None:
        raise RuntimeError(f"{error} (the next scan retries it)")


def _headline(
    decisions: list[ProjectDecision],
) -> tuple[ProjectDecision, FindingDisposition] | None:
    """The first QUARANTINE finding (findings are sorted most-severe first)."""
    for decision in decisions:
        for disp in decision.findings:
            if disp.disposition == Disposition.QUARANTINE:
                return decision, disp
    return None


def _gate_exempted_packages(
    decision: ProjectDecision, *, posture: Posture, dangerously: bool,
    suppressions: tuple, today: date, kev_lookup,
) -> set[str]:
    """OS runtime packages the relevance gate de-escalated with an EMPTY
    inferred runtime set.

    An empty inferred set is legitimate for a static site, but it's
    indistinguishable from "the image installs its runtime without a
    Trivy-visible lang-pkgs manifest" (apt-only Python, conda, PHP without
    composer.lock), in which case the gate exempts the project's OWN
    runtime. Only a disposition that actually DIFFERS with the gate off
    (runtimes=None) proves the gate was the cause: steps 8-11 also yield
    INFORMATIONAL. evaluate_finding is pure, so re-running it is safe.
    """
    out: set[str] = set()
    for disp in decision.findings:
        f = disp.finding
        if (
            disp.disposition != Disposition.INFORMATIONAL
            or f.pkg_class is not PkgClass.OS
            or ecosystem_for_package(f.package) is None
        ):
            continue
        but_for = evaluate_finding(
            f,
            posture=posture,
            hardening_penalty=disp.hardening_penalty,
            dangerously_disable_quarantine=dangerously,
            suppressions=suppressions,
            today=today,
            kev_lookup=kev_lookup,
            runtimes=None,
        )
        if but_for.disposition != disp.disposition:
            out.add(f.package)
    return out


def _log_relevance_gaps(
    paths: BoxPaths, project: str,
    dropped_lang_types: set[str], empty_runtime_exempted: set[str],
) -> None:
    """Log the relevance-gate visibility warnings, once per project scan."""
    if dropped_lang_types:
        log_warning(
            "cve-scan",
            f"project {project}: unrecognised Trivy lang-pkgs type(s) "
            f"{sorted(dropped_lang_types)} were ignored during runtime "
            f"inference (they contribute no ecosystem); this can shrink the "
            f"inferred runtime set and make more findings look foreign — "
            f"extend relevance._TRIVY_TYPE_TO_ECOSYSTEM or declare "
            f"security.runtimes to compensate",
            paths, project=project,
            detail={"lang_types": sorted(dropped_lang_types)},
        )
    if empty_runtime_exempted:
        log_warning(
            "cve-scan",
            f"project {project}: relevance gate de-escalated OS package(s) "
            f"{sorted(empty_runtime_exempted)} because no runtime was "
            f"declared and none was inferred from a Trivy lang-pkgs "
            f"manifest — if this image installs its runtime without one "
            f"(apt-installed python3, conda, PHP without composer.lock), "
            f"the gate is exempting the project's OWN runtime; declare "
            f"security.runtimes to fix",
            paths, project=project,
            detail={"packages": sorted(empty_runtime_exempted)},
        )


def _emit_transition_alerts(
    paths: BoxPaths, project: str,
    decisions: list[ProjectDecision],
    prior_decisions: tuple[ProjectDecision, ...],
    supps: tuple,
) -> None:
    """Best-effort transition alerts — failures never fail the scan."""
    prior_by_image = {pd.image_ref: pd for pd in prior_decisions}
    for current_decision in decisions:
        try:
            emit_scan_alerts(
                project_name=project,
                current=current_decision,
                prior=prior_by_image.get(current_decision.image_ref),
                suppressions=supps,
                paths=paths,
            )
        except Exception as e:  # noqa: BLE001 — alerting must never block scan
            log_warning(
                "cve-scan",
                f"alert emission failed for {project} "
                f"({current_decision.image_ref}): {e}",
                paths, project=project,
                detail={"image_ref": current_decision.image_ref, "error": str(e)},
            )
