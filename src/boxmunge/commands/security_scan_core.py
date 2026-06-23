# SPDX-License-Identifier: Apache-2.0
"""Per-project CVE scan mechanics — image identification, evaluate, persist.

Extracted from security_actions.py to keep that file under the 500/650 LoC
budget. Contains the scan body that runs under the per-project lock plus
the small helpers (project meta, image identification, compose loader)
that feed it. Action handlers (cmd_security_scan / cmd_security_resume)
remain in security_actions.py and orchestrate fleet-wide concerns
(grace heads-up, exit codes, locking).
"""
from __future__ import annotations

import time
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from boxmunge.cve.alerting import emit_scan_alerts
from boxmunge.cve.grace import GraceError, init_grace_if_missing
from boxmunge.cve.policy import (
    Disposition,
    ProjectDecision,
    evaluate_project,
    hardening_profile_from_compose,
    parse_posture,
)
from boxmunge.cve.quarantine import (
    QuarantineError,
    is_quarantined,
    quarantine_project,
)
from boxmunge.cve.scan_state import (
    decisions_from_scan_state,
    read_scan_state,
    write_scan_state,
)
from boxmunge.cve.scanner import (
    _DEFAULT_TIMEOUT,
    ScanResult,
    ScannerError,
    TrivyNotInstalledError,
    scan_image,
)
from boxmunge.cve.suppressions import SuppressionsError, load_suppressions
from boxmunge.docker import container_image_digest
from boxmunge.fileutil import project_lock
from boxmunge.log import log_warning
from boxmunge.manifest import load_manifest
from boxmunge.paths import BoxPaths
from boxmunge.security_overlay import services_with_off_profile


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


def project_suppressions_path(paths: BoxPaths, project: str) -> Path:
    return paths.project_dir(project) / "security" / "suppressions.yml"


def _container_name(project: str, service: str) -> str:
    """Replicate the convention used in commands/check.py."""
    return f"{project}-{service}-1"


def _today() -> date:
    return datetime.now(timezone.utc).date()


def _load_compose(project_dir: Path) -> dict[str, Any]:
    """Load the user compose.yml as a parsed dict."""
    path = project_dir / "compose.yml"
    if not path.exists():
        return {}
    try:
        data = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as e:
        raise RuntimeError(f"Failed to parse compose.yml: {e}") from e
    if not isinstance(data, dict):
        return {}
    return data


def _identify_images(
    manifest: dict[str, Any], compose: dict[str, Any], project: str,
) -> tuple[list[str], list[str]]:
    """Return (images, warnings).

    For each service: prefer the running container's image digest; fall back
    to the compose-declared image. Build-only services are skipped with a
    warning.
    """
    images: list[str] = []
    warnings: list[str] = []
    services = manifest.get("services") or {}
    compose_services = compose.get("services") or {}

    for svc_name in services.keys():
        cname = _container_name(project, svc_name)
        digest = container_image_digest(cname)
        if digest:
            # digest already includes "sha256:..." prefix — qualify with image
            # ref if available so the scan target is unambiguous.
            svc_compose = compose_services.get(svc_name, {})
            base_ref = svc_compose.get("image") if isinstance(svc_compose, dict) else None
            if base_ref and "@" not in base_ref:
                # Strip any tag and pin to digest.
                short = base_ref.split(":", 1)[0]
                images.append(f"{short}@{digest}")
            else:
                images.append(digest)
            continue

        # Container not running: fall back to compose image.
        svc_compose = compose_services.get(svc_name, {})
        if isinstance(svc_compose, dict):
            image_ref = svc_compose.get("image")
            if image_ref:
                images.append(image_ref)
                continue
        warnings.append(
            f"service {svc_name!r}: no running container and no image declared "
            f"in compose (build-only) — skipping"
        )

    return images, warnings


def _project_meta(
    paths: BoxPaths, project: str,
) -> tuple[dict[str, Any], dict[str, Any], str, bool]:
    """Load manifest + compose, derive posture and dangerously_disable flag."""
    manifest = load_manifest(paths.project_manifest(project))
    compose = _load_compose(paths.project_dir(project))
    sec_block = manifest.get("security") or {}
    posture = sec_block.get("posture") or "balanced"
    dangerously = bool(sec_block.get("dangerously_disable_quarantine", False))
    return manifest, compose, posture, dangerously


def scan_one_project(
    paths: BoxPaths, project: str, *,
    in_grace: bool | None = None,
    audit_only: bool = False,
) -> tuple[
    ProjectDecision | None,
    list[ProjectDecision],
    list[str],
    str,
    bool,
]:
    """Scan a single project, persist state, take quarantine action.

    Returns (headline_decision, all_decisions, warnings, posture_str,
    dangerously). ``headline_decision`` is the first decision that
    requires quarantine (used to trigger the action), or None if no
    decision quarantines.

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
    callers DO NOT lazy-bootstrap grace either — the resume flow
    inspects current findings and is not a scan-entry-point.

    Concurrency: this function holds the per-project lock for its full
    body — scan + quarantine action + scan_state write must be atomic
    relative to deploy/promote/container-update.

    Raises:
        LockError: when another operation holds the project lock. Caller
            decides whether to skip-and-warn (fleet scan) or fail (resume).
        TrivyNotInstalledError: when the Trivy binary is missing.
        RuntimeError: on irrecoverable failures (manifest unreadable, all
            images failed to scan, quarantine action raised, grace state
            corrupt).
    """
    if in_grace is None:
        # Audit F-2: any direct caller of scan_one_project lazily
        # bootstraps grace. audit_only callers (resume) deliberately
        # skip the bootstrap — they observe findings without scanning.
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
    with project_lock(project, paths):
        return _scan_one_project_locked(
            paths, project, in_grace=in_grace, audit_only=audit_only,
        )


def _scan_one_project_locked(
    paths: BoxPaths, project: str, *, in_grace: bool, audit_only: bool = False,
) -> tuple[
    ProjectDecision | None,
    list[ProjectDecision],
    list[str],
    str,
    bool,
]:
    """Inner scan body. Caller MUST hold the per-project lock."""
    manifest, compose, posture_str, dangerously = _project_meta(paths, project)
    posture = parse_posture(posture_str)
    # Services with profile != off get boxmunge's hardening overlay applied
    # at runtime. Pass the overlay set through so the policy doesn't penalise
    # a project for relying on overlay defaults (e.g. no-new-privileges) it
    # didn't redeclare in its own compose.yml.
    off_services = {svc for svc, _ in services_with_off_profile(manifest)}
    overlay_services = (
        set((compose.get("services") or {}).keys()) - off_services
    )
    profile = hardening_profile_from_compose(
        compose, services_with_overlay=overlay_services,
    )
    suppressions_path = project_suppressions_path(paths, project)
    try:
        project_supps = load_suppressions(suppressions_path)
    except SuppressionsError as e:
        raise RuntimeError(
            f"Failed to load suppressions for {project!r}: {e}"
        ) from e
    # Host-scoped suppressions apply to every project on this box. Used to
    # silence base-image CVEs whose vulnerable code path is never loaded by
    # any deployed service (e.g. perl-base when no project runs Perl).
    # Project entries are listed FIRST so they win precedence on collision —
    # find_active_suppression returns the first match, and a project-level
    # suppression is more specific than a host-level one.
    try:
        host_supps = load_suppressions(paths.host_suppressions, scope="host")
    except SuppressionsError as e:
        raise RuntimeError(
            f"Failed to load host-scoped suppressions: {e}"
        ) from e
    supps = project_supps + host_supps

    # Load the prior scan_state BEFORE we overwrite it. Used by the alerting
    # path to detect transitions (new quarantine, expired suppression, ...).
    scan_state_path = paths.project_scan_state(project)
    prior_state = read_scan_state(scan_state_path)
    prior_decisions: tuple[ProjectDecision, ...] = ()
    if prior_state is not None:
        try:
            prior_decisions = decisions_from_scan_state(
                prior_state, project_name=project,
            )
        except (ValueError, KeyError) as e:
            # A malformed prior state file shouldn't block the scan; log and
            # treat as "no prior" (alerts will be emitted as if first scan).
            log_warning(
                "cve-scan",
                f"ignoring unreadable prior scan state for {project}: {e}",
                paths, project=project,
            )

    images, warnings = _identify_images(manifest, compose, project)
    if not images:
        # Persist an empty scan-state so we don't wedge the per-project view.
        # In audit-only mode (resume re-scan, audit A-3), leave the prior
        # scan_state alone — the caller is just inspecting current findings.
        if not audit_only:
            write_scan_state(scan_state_path, decisions=())
        return None, [], warnings, posture_str, dangerously

    decisions: list[ProjectDecision] = []
    failed: list[str] = []
    today = _today()
    project_start = time.monotonic()
    for index, image_ref in enumerate(images):
        # Per-project aggregate budget: if the cumulative elapsed time for
        # this project's scans has eaten the budget, skip the rest. The
        # systemd unit timeout (60m) is the outer cap — without this inner
        # cap, one slow project could starve every project after it.
        elapsed = time.monotonic() - project_start
        remaining = _PROJECT_BUDGET_SECONDS - elapsed
        if remaining <= 0:
            skipped = len(images) - index
            log_warning(
                "cve-scan",
                f"project {project} exceeded scan budget after "
                f"{elapsed:.0f}s — skipping remaining {skipped} image(s)",
                paths, project=project,
                detail={
                    "elapsed_s": round(elapsed, 1),
                    "budget_s": _PROJECT_BUDGET_SECONDS,
                    "skipped_images": images[index:],
                },
            )
            warnings.append(
                f"project budget exceeded after {elapsed:.0f}s — "
                f"skipped {skipped} image(s)"
            )
            break
        # Cap the per-image timeout at the smaller of Trivy's default and
        # the remaining project budget so an individual scan can't blow
        # past the budget on its own.
        per_image_timeout = min(_DEFAULT_TIMEOUT, max(1, int(remaining)))
        try:
            sr: ScanResult = scan_image(image_ref, timeout=per_image_timeout)
        except TrivyNotInstalledError:
            raise
        except ScannerError as e:
            log_warning(
                "cve-scan",
                f"scan failed for {project} image {image_ref}: {e}",
                paths, project=project,
                detail={"image_ref": image_ref, "error": str(e)},
            )
            failed.append(image_ref)
            warnings.append(f"image {image_ref}: scan failed ({e})")
            continue
        decision = evaluate_project(
            project, sr,
            posture=posture,
            hardening_profile=profile,
            dangerously_disable_quarantine=dangerously,
            suppressions=supps,
            today=today,
        )
        decisions.append(decision)

    if failed and not decisions:
        raise RuntimeError(
            f"All images failed to scan for project {project!r}"
        )

    # Decide whether quarantine action fires. The headline decision is
    # computed BEFORE the scan_state write so a quarantine_project failure
    # leaves the prior scan_state untouched — next scan converges rather
    # than recording a false "fresh scan complete" against an unstopped
    # project (audit E-2).
    headline_decision = None
    headline_disp = None
    for decision in decisions:
        for disp in decision.findings:
            if disp.disposition == Disposition.QUARANTINE:
                headline_decision = decision
                headline_disp = disp
                break
        if headline_decision is not None:
            break

    # During grace we still compute the headline decision (so the heads-up
    # alert can summarise it) but never fire the quarantine action.
    # In audit-only mode (resume re-scan, audit A-3) the caller is the
    # quarantine-lift flow itself — firing a fresh quarantine on top of
    # an in-progress resume would deadlock the operator path.
    if (
        not in_grace
        and not audit_only
        and headline_decision
        and headline_disp
        and not is_quarantined(project, paths)
    ):
        compose_files = ["compose.yml"]
        if paths.project_compose_override(project).exists():
            compose_files.append("compose.boxmunge.yml")
        # Fail noisily if quarantine_project raises: scan_state stays
        # untouched, the operator sees the error, and the next scan
        # converges (Golden Rule: no fallbacks).
        try:
            quarantine_project(
                project, paths,
                project_dir=paths.project_dir(project),
                hosts=manifest.get("hosts") or [],
                compose_files=compose_files,
                headline=headline_disp,
                image_ref=headline_decision.image_ref,
            )
        except QuarantineError as e:
            raise RuntimeError(
                f"quarantine action failed for {project!r}: {e}"
            ) from e

    # Persist scan_state AFTER the quarantine action succeeded. If the
    # quarantine raised above, this write does not happen and the prior
    # scan_state stays in place — next scan re-fires the action (audit E-2).
    #
    # Audit A-3: in audit-only mode (resume re-scan) we deliberately
    # skip the write. The caller is verifying whether quarantine-level
    # findings remain; mutating persisted scan_state on a read-only
    # operation would create surprise deltas in the next normal scan.
    if not audit_only:
        write_scan_state(scan_state_path, decisions=tuple(decisions))

    # Emit Pushover alerts for state transitions (new quarantine, newly
    # at-risk-running, suppression expired, new sub-threshold finding).
    # Best-effort — failures here do NOT fail the scan; the durable record
    # is the scan_state file just written.
    #
    # During the migration grace window, transition alerts are suppressed:
    # the operator gets the single fleet-level heads-up alert instead.
    # Audit A-3: audit-only callers (resume) likewise must not push
    # transition alerts — the resume flow has its own success/failure
    # signalling and operators don't expect "boxmunge security resume X"
    # to push alerts about X.
    if not in_grace and not audit_only:
        prior_by_image = {pd.image_ref: pd for pd in prior_decisions}
        for current_decision in decisions:
            prior_decision = prior_by_image.get(current_decision.image_ref)
            try:
                emit_scan_alerts(
                    project_name=project,
                    posture=posture_str,
                    current=current_decision,
                    prior=prior_decision,
                    suppressions=supps,
                    paths=paths,
                )
            except Exception as e:  # noqa: BLE001 — alerting must never block scan
                log_warning(
                    "cve-scan",
                    f"alert emission failed for {project} "
                    f"({current_decision.image_ref}): {e}",
                    paths, project=project,
                    detail={
                        "image_ref": current_decision.image_ref,
                        "error": str(e),
                    },
                )

    return headline_decision, decisions, warnings, posture_str, dangerously
