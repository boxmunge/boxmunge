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

from boxmunge.commands.security_scan_relevance import (
    gate_exempted_packages,
    log_relevance_gaps,
)
from boxmunge.commands.security_scan_inputs import (
    ProjectHardening,
    ProjectMeta,
    ScanTarget,
    hardening_profile,
    identify,
    load_all_suppressions,
    load_project_meta,
    load_user_model,
)
from boxmunge.commands.security_enforce import (
    Enforcement,
    announce_quarantine,
    enforce,
    headline_of,
    raise_enforcement_error,
)
from boxmunge.cve.alerting import emit_scan_alerts
from boxmunge.cve.grace import GraceError, init_grace_if_missing
from boxmunge.cve.kev import KevCatalog, load_kev
from boxmunge.cve.policy import (
    FindingDisposition,
    Posture,
    ProjectDecision,
    evaluate_project,
)
from boxmunge.cve.relevance import (
    effective_runtimes,
    unrecognised_lang_types,
)
from boxmunge.cve.scan_state import (
    BASIS_CONTAINERS,
    decisions_from_scan_state,
    read_scan_state,
    ScanStateWriteError,
    write_scan_state,
)
from boxmunge.cve.suppressions import Suppression
from boxmunge.cve.scanner import (
    _DEFAULT_TIMEOUT,
    ScanResult,
    ScannerError,
    TrivyNotInstalledError,
    scan_image,
)
from boxmunge.fileutil import project_lock
from boxmunge.log import log_warning
from boxmunge.paths import BoxPaths
from boxmunge.state import StateError


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
    per-project budget, and ``unidentified`` maps each service whose image
    could not be identified to why. Any of the three means the scan is
    incomplete: the decisions cover only part of what the project runs.

    ``basis`` says what was scanned: the images of the project's containers,
    or, while the platform has it stopped (``stopped_reason``), the images
    `compose up` would start.
    """

    project: str
    posture: str
    dangerously: bool
    decisions: tuple[ProjectDecision, ...]
    warnings: tuple[str, ...]
    failed_images: tuple[str, ...] = ()
    skipped_images: tuple[str, ...] = ()
    unidentified: tuple[tuple[str, str], ...] = ()
    basis: str = BASIS_CONTAINERS
    stopped_reason: str | None = None
    headline: tuple[ProjectDecision, FindingDisposition] | None = None
    # Host-scope suppressions that expired since the last scan; the fleet
    # run alerts them once rather than once per project (audit B-14).
    host_expired: tuple[Suppression, ...] = ()
    # Set when the scan ran and was acted on but its result could not be
    # written (ScanStateWriteError); the fleet run fails and alerts on it.
    record_error: str | None = None

    @property
    def unidentified_services(self) -> tuple[str, ...]:
        return tuple(svc for svc, _ in self.unidentified)

    @property
    def complete(self) -> bool:
        return not (
            self.failed_images or self.skipped_images or self.unidentified_services
        )

    def incomplete_reasons(self) -> list[str]:
        """One human line per unscanned image or service."""
        return _unscanned(self.failed_images, self.skipped_images,
                          dict(self.unidentified))


def _unscanned(
    failed=(), skipped=(), unidentified: dict[str, str] | None = None,
) -> list[str]:
    """One human line per image or service a scan did not cover."""
    out = [f"image {ref}: scan failed" for ref in failed]
    out += [f"image {ref}: skipped (scan budget exhausted)" for ref in skipped]
    out += [f"service {svc!r}: {why}" for svc, why in (unidentified or {}).items()]
    return out


def _today() -> date:
    return datetime.now(timezone.utc).date()


def scan_one_project(
    paths: BoxPaths, project: str, *,
    in_grace: bool | None = None,
    audit_only: bool = False,
    kev: KevCatalog | None = None,
    defer_new: bool = False,
) -> ProjectScan:
    """Scan a single project, persist state, take quarantine action.

    ``ProjectScan.headline`` is the first (decision, finding) pair that
    requires quarantine, or None if nothing quarantines.

    ``in_grace=True`` suppresses new quarantines and transition alerts but
    still writes scan_state; ``None`` (direct callers) lazily bootstraps
    the grace state and derives it (audit F-2).

    ``audit_only=True`` (the resume re-scan, audit A-3) only evaluates: no
    scan_state write, no alerts, no action, no grace bootstrap.

    When ``defer_new`` is True, an existing quarantine is still re-asserted
    but a NEW quarantine is not taken here: the fleet scan decides it for
    the whole run, through the circuit breaker (security_enforce).

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
        return scan_one_project_locked(
            paths, project, in_grace=in_grace, audit_only=audit_only, kev=kev,
            defer_new=defer_new,
        )


def _prior_decisions(paths: BoxPaths, project: str) -> tuple[ProjectDecision, ...]:
    """The previous scan's decisions, for transition detection."""
    try:
        prior_state = read_scan_state(paths.project_scan_state(project))
        if prior_state is None:
            return ()
        return decisions_from_scan_state(prior_state, project_name=project)
    except (StateError, ValueError, KeyError, TypeError, AttributeError) as e:
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


def _check_declared_runtimes(project: str, meta: ProjectMeta) -> None:
    """`declared` is loop-invariant (one manifest, many images), so it is
    validated once before any Trivy scan runs: a malformed
    security.runtimes then fails in milliseconds, and no early return can
    skip validation (load_manifest does not validate the security: block)."""
    if meta.declared_runtimes is None:
        return
    try:
        effective_runtimes((), declared=meta.declared_runtimes)
    except (ValueError, TypeError) as e:
        raise RuntimeError(
            f"project {project!r}: invalid security.runtimes in manifest: {e}"
        ) from e


def _evaluate(
    paths: BoxPaths, project: str, meta: ProjectMeta, profile: ProjectHardening,
    supps: tuple[Suppression, ...], results: list[ScanResult], kev: KevCatalog,
) -> list[ProjectDecision]:
    """One decision per scanned image, under the project's policy."""
    posture, dangerously, declared = meta.posture, meta.dangerously, meta.declared_runtimes
    decisions: list[ProjectDecision] = []
    today = _today()

    def kev_lookup(cid: str) -> bool:
        return kev.is_known_exploited(cid, today=today)

    # Collected across every image but logged at most once per project scan.
    dropped_lang_types: set[str] = set()
    empty_runtime_exempted: set[str] = set()
    for sr in results:
        # `declared` was validated first; this only infers from lang_types.
        runtimes = effective_runtimes(sr.lang_types, declared=declared)
        if declared is None:
            # An unmapped Trivy lang-pkgs Type is dropped by infer_runtimes,
            # which biases toward OVER-exemption; surface it.
            dropped_lang_types |= unrecognised_lang_types(sr.lang_types)
        decision = evaluate_project(
            project, sr,
            posture=posture,
            hardening_profile=profile.applied,
            upcoming=profile.upcoming,
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
            empty_runtime_exempted |= gate_exempted_packages(
                decision, posture=posture, dangerously=dangerously,
                suppressions=supps, today=today, kev_lookup=kev_lookup,
            )

    log_relevance_gaps(paths, project, dropped_lang_types, empty_runtime_exempted)
    return decisions


def audit_targets(
    paths: BoxPaths, project: str, *, meta: ProjectMeta, profile: ProjectHardening,
    supps: tuple[Suppression, ...], targets: list[ScanTarget],
    unidentified: dict[str, str], kev: KevCatalog, basis: str,
) -> ProjectScan:
    """An audit-only scan of exactly ``targets`` under the given policy:
    nothing is written, alerted or enforced. A release not yet deployed is
    judged by its own manifest and compose, with the project's suppressions
    (quarantine_gate)."""
    _check_declared_runtimes(project, meta)
    results, failed, skipped, warnings = _scan_targets(paths, project, targets)
    decisions = _evaluate(paths, project, meta, profile, supps, results, kev)
    return ProjectScan(
        project=project, posture=meta.posture_str, dangerously=meta.dangerously,
        decisions=tuple(decisions),
        warnings=tuple(_unscanned(unidentified=unidentified) + warnings),
        failed_images=tuple(failed), skipped_images=tuple(skipped),
        unidentified=tuple(unidentified.items()), basis=basis,
        headline=headline_of(decisions),
    )


def scan_one_project_locked(
    paths: BoxPaths, project: str, *,
    in_grace: bool,
    kev: KevCatalog,
    audit_only: bool = False,
    defer_new: bool = False,
) -> ProjectScan:
    """Inner scan body. Caller MUST hold the per-project lock."""
    meta = load_project_meta(paths, project)
    dangerously = meta.dangerously
    _check_declared_runtimes(project, meta)
    profile = hardening_profile(meta, load_user_model(paths, project))
    # Host-scoped suppressions are for reviewed, accepted-risk findings; the
    # relevance gate handles "base-image package the project never invokes".
    supps = load_all_suppressions(paths, project)

    # Load the prior scan_state BEFORE we overwrite it (transition alerts).
    scan_state_path = paths.project_scan_state(project)
    prior_decisions = _prior_decisions(paths, project)

    inventory = identify(paths, project, meta)
    targets, unidentified = inventory.targets, inventory.unidentified
    basis = {"basis": inventory.basis, "stopped_reason": inventory.stopped_reason}
    warnings = _unscanned(unidentified=unidentified) + [
        f"service {svc!r}: not started by `compose up` (inactive profile or "
        f"zero replicas) and has no container — nothing to scan"
        for svc in inventory.not_started
    ]
    if not targets:
        # Persist an empty scan-state so we don't wedge the per-project view.
        # Audit-only (resume re-scan, audit A-3) leaves the prior alone.
        record_error = None
        if not audit_only:
            outcome = _enforce(paths, project, meta, None, in_grace=in_grace)
            record_error = _record(
                scan_state_path, decisions=(),
                unscanned=tuple(_unscanned(unidentified=unidentified)), **basis,
            )
            raise_enforcement_error(outcome.error, record_error)
        return ProjectScan(
            project=project, posture=meta.posture_str, dangerously=dangerously,
            decisions=(), warnings=tuple(warnings),
            unidentified=tuple(unidentified.items()), record_error=record_error,
            **basis,
        )

    results, failed, skipped, scan_warnings = _scan_targets(paths, project, targets)
    warnings.extend(scan_warnings)
    decisions = _evaluate(paths, project, meta, profile, supps, results, kev)

    headline = headline_of(decisions)
    # Audit-only callers (resume re-scan, audit A-3) are the lift flow
    # itself and never act. Everyone else enforces: an existing quarantine
    # is re-asserted on every scan (B-03), a new one fires outside grace.
    outcome = Enforcement()
    if not audit_only:
        outcome = _enforce(
            paths, project, meta, headline, in_grace=in_grace or defer_new,
        )

    if failed and not decisions:
        detail = f"; {outcome.error}" if outcome.error else ""
        raise RuntimeError(
            f"All images failed to scan for project {project!r}{detail}"
        )

    # A write failure must not discard the scan: enforcement has run, and the
    # alerts below still have to fire; the failure is reported with the result.
    record_error = None
    if not audit_only:
        record_error = _record(
            scan_state_path, decisions=tuple(decisions),
            unscanned=tuple(_unscanned(failed, skipped, unidentified)), **basis,
        )

    # Transition alerts are best-effort; during grace the operator gets the
    # single fleet-level heads-up instead, and audit-only callers (resume)
    # must not push alerts.
    host_expired: tuple[Suppression, ...] = ()
    if not in_grace and not audit_only:
        if outcome.landed:
            announce_quarantine(paths, project, decisions)
        host_expired = _emit_transition_alerts(
            paths, project, decisions, prior_decisions, supps,
        )
    raise_enforcement_error(outcome.error, record_error)

    return ProjectScan(
        project=project,
        posture=meta.posture_str,
        dangerously=dangerously,
        record_error=record_error,
        decisions=tuple(decisions),
        warnings=tuple(warnings),
        failed_images=tuple(failed),
        skipped_images=tuple(skipped),
        unidentified=tuple(unidentified.items()),
        **basis,
        headline=headline,
        host_expired=host_expired,
    )


def _record(path, **kwargs) -> str | None:
    """write_scan_state; the error text when the result could not be
    written, so the caller finishes enforcing and alerting first."""
    try:
        write_scan_state(path, **kwargs)
    except ScanStateWriteError as e:
        return str(e)
    return None


def _enforce(
    paths: BoxPaths, project: str, meta: ProjectMeta,
    headline: tuple[ProjectDecision, FindingDisposition] | None,
    *, in_grace: bool,
) -> Enforcement:
    return enforce(
        paths, project, hosts=meta.hosts, compose_files=meta.compose_files,
        policy=meta.policy(), headline=headline, in_grace=in_grace,
    )


def _emit_transition_alerts(
    paths: BoxPaths, project: str,
    decisions: list[ProjectDecision],
    prior_decisions: tuple[ProjectDecision, ...],
    supps: tuple[Suppression, ...],
) -> tuple[Suppression, ...]:
    """Best-effort transition alerts — failures never fail the scan.

    Returns the expired host-scope suppressions for the fleet to alert once.
    """
    try:
        return emit_scan_alerts(
            project_name=project,
            current=decisions,
            prior=prior_decisions,
            suppressions=supps,
            paths=paths,
        )
    except Exception as e:  # noqa: BLE001 — alerting must never block scan
        log_warning(
            "cve-scan", f"alert emission failed for {project}: {e}",
            paths, project=project, detail={"error": str(e)},
        )
        return ()
