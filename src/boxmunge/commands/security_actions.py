# SPDX-License-Identifier: Apache-2.0
"""Action handlers for `boxmunge security` subcommands: scan and resume.

The suppress/unsuppress handlers live in security_suppress.py — they share
no internals beyond the suppressions-path helper.
"""
from __future__ import annotations

import logging
import sys
import time
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from boxmunge.cve.alerting import (
    emit_scan_alerts,
    format_grace_heads_up_alert,
    send_alerts,
)
from boxmunge.cve.grace import (
    GraceError,
    GraceState,
    init_grace_if_missing,
    mark_heads_up_sent,
)
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
    lift_quarantine,
    quarantine_project,
)
from boxmunge.cve.scan_state import (
    decisions_from_scan_state,
    read_scan_state,
    write_scan_state,
)
from boxmunge.cve.scanner import (
    ScanResult,
    ScannerError,
    TrivyNotInstalledError,
    refresh_db,
    scan_image,
)
from boxmunge.cve.suppressions import SuppressionsError, load_suppressions
from boxmunge.docker import container_image_digest
from boxmunge.manifest import ManifestError, load_manifest
from boxmunge.paths import BoxPaths, validate_project_name
from boxmunge.project_registry import is_registered, load_registered_projects

_LOGGER = logging.getLogger("boxmunge")


# ---------- helpers ----------


def _project_suppressions_path(paths: BoxPaths, project: str) -> Path:
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


def _scan_one_project(
    paths: BoxPaths, project: str, *, in_grace: bool = False,
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
    so subsequent scans see correct prior state.

    Raises:
        TrivyNotInstalledError: when the Trivy binary is missing.
        RuntimeError: on irrecoverable failures (manifest unreadable, all
            images failed to scan).
    """
    manifest, compose, posture_str, dangerously = _project_meta(paths, project)
    posture = parse_posture(posture_str)
    profile = hardening_profile_from_compose(compose)
    suppressions_path = _project_suppressions_path(paths, project)
    try:
        supps = load_suppressions(suppressions_path)
    except SuppressionsError as e:
        raise RuntimeError(
            f"Failed to load suppressions for {project!r}: {e}"
        ) from e

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
            _LOGGER.warning(
                "ignoring unreadable prior scan state for %s: %s", project, e,
            )

    images, warnings = _identify_images(manifest, compose, project)
    if not images:
        # Persist an empty scan-state so we don't wedge the per-project view.
        write_scan_state(scan_state_path, decisions=())
        return None, [], warnings, posture_str, dangerously

    decisions: list[ProjectDecision] = []
    failed: list[str] = []
    today = _today()
    for image_ref in images:
        try:
            sr: ScanResult = scan_image(image_ref)
        except TrivyNotInstalledError:
            raise
        except ScannerError as e:
            _LOGGER.warning(
                "scan failed for %s image %s: %s", project, image_ref, e,
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

    write_scan_state(scan_state_path, decisions=tuple(decisions))

    # Emit Pushover alerts for state transitions (new quarantine, newly
    # at-risk-running, suppression expired, new sub-threshold finding).
    # Best-effort — failures here do NOT fail the scan; the durable record
    # is the scan_state file just written.
    #
    # During the migration grace window, transition alerts are suppressed:
    # the operator gets the single fleet-level heads-up alert instead.
    if not in_grace:
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
                _LOGGER.warning(
                    "alert emission failed for %s (%s): %s",
                    project, current_decision.image_ref, e,
                )

    # Decide whether quarantine action fires.
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
    if (
        not in_grace
        and headline_decision
        and headline_disp
        and not is_quarantined(project, paths)
    ):
        compose_files = ["compose.yml"]
        if paths.project_compose_override(project).exists():
            compose_files.append("compose.boxmunge.yml")
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
            warnings.append(f"quarantine action failed: {e}")

    return headline_decision, decisions, warnings, posture_str, dangerously


def _summarise_decisions(decisions: list[ProjectDecision]) -> str:
    """One-line counts of dispositions across all decisions."""
    counts: dict[str, int] = {}
    total = 0
    for d in decisions:
        for f in d.findings:
            total += 1
            counts[f.disposition.value] = counts.get(f.disposition.value, 0) + 1
    if total == 0:
        return "0 findings"
    parts = []
    for tag in (
        Disposition.QUARANTINE.value,
        Disposition.SUPPRESSED.value,
        Disposition.STILL_RUNNING_AT_RISK.value,
        Disposition.INFORMATIONAL.value,
        Disposition.IGNORED_FIXED.value,
    ):
        c = counts.get(tag, 0)
        if c:
            parts.append(f"{c} {tag.replace('_', '-')}")
    return f"{total} findings ({', '.join(parts)})"


# ---------- subcommand: scan ----------


def cmd_security_scan(args: list[str], paths: BoxPaths) -> int:
    """boxmunge security scan [project] — scan one or all projects."""
    project: str | None = None
    if args:
        if args[0].startswith("--"):
            print(f"ERROR: unknown argument: {args[0]}", file=sys.stderr)
            return 2
        project = args[0]
        try:
            validate_project_name(project)
        except ValueError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 2

    if project is not None:
        if not is_registered(project, paths):
            print(
                f"ERROR: project '{project}' is not registered.",
                file=sys.stderr,
            )
            return 1
        targets = [project]
    else:
        targets = sorted(load_registered_projects(paths))

    if not targets:
        print("No projects registered.")
        return 0

    try:
        refresh_db()
    except TrivyNotInstalledError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    # Migration grace window — bootstrap lazily on first scan after upgrade.
    # If grace state is corrupt we abort the scan rather than silently
    # proceeding with full enforcement: the operator might believe they
    # are in grace when they are not. (Per-project scans use the same
    # bootstrap so the in_grace flag is consistent across entry-points.)
    now = datetime.now(timezone.utc)
    is_fleet_scan = project is None
    try:
        grace = init_grace_if_missing(paths, now=now)
    except GraceError as e:
        print(
            f"ERROR: CVE migration grace state is corrupt: {e}\n"
            f"  Inspect {paths.cve_grace_state} and resolve before scanning.",
            file=sys.stderr,
        )
        return 1
    in_grace = grace.is_active(now=now)

    start = time.monotonic()
    failures = 0
    decisions_by_project: dict[str, ProjectDecision] = {}
    posture_by_project: dict[str, str] = {}
    dangerously_by_project: dict[str, bool] = {}

    for name in targets:
        try:
            headline, decisions, warnings, posture_str, dangerously = (
                _scan_one_project(paths, name, in_grace=in_grace)
            )
        except TrivyNotInstalledError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1
        except (RuntimeError, ManifestError) as e:
            print(f"{name}: ERROR — {e}")
            failures += 1
            continue
        for w in warnings:
            print(f"{name}: WARN — {w}")
        print(f"{name}: {_summarise_decisions(decisions)}")

        # Capture per-project state for the heads-up summary. We pick the
        # first decision (one image per project for typical deployments;
        # multi-image projects surface the most-severe via findings sort).
        if decisions:
            decisions_by_project[name] = decisions[0]
            posture_by_project[name] = posture_str
            dangerously_by_project[name] = dangerously

    # Fire the one-time heads-up alert if we're still in grace AND it
    # hasn't already gone out. Fleet scans only — per-project scans never
    # have the full fleet state needed to populate the alert lists.
    if (
        is_fleet_scan
        and in_grace
        and not grace.heads_up_sent
        and decisions_by_project
    ):
        alert = format_grace_heads_up_alert(
            expires_at=grace.expires_at,
            decisions_by_project=decisions_by_project,
            posture_by_project=posture_by_project,
            dangerously_by_project=dangerously_by_project,
        )
        try:
            send_alerts((alert,), paths)
        except Exception as e:  # noqa: BLE001 — alerting must never block scan
            _LOGGER.warning("heads-up alert send raised: %s", e)
        # Persist the sent flag regardless of delivery success: the
        # operator can see grace state in `boxmunge security` and we
        # don't want repeated sends if Pushover is down.
        try:
            mark_heads_up_sent(paths, grace)
        except OSError as e:
            _LOGGER.warning("failed to persist heads_up_sent flag: %s", e)

    elapsed = time.monotonic() - start
    print(f"Scanned {len(targets)} projects in {elapsed:.1f}s.")
    if in_grace:
        print(
            f"Migration grace ACTIVE — full enforcement begins "
            f"{grace.expires_at.astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M')} UTC",
        )
    return 0 if failures == 0 else 1


# ---------- subcommand: resume ----------


def cmd_security_resume(args: list[str], paths: BoxPaths) -> int:
    if not args:
        print(
            "Usage: boxmunge security resume <project>", file=sys.stderr,
        )
        return 2
    project = args[0]
    try:
        validate_project_name(project)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    if not is_quarantined(project, paths):
        print(
            f"ERROR: project '{project}' is not quarantined.",
            file=sys.stderr,
        )
        return 1

    print(f"Resuming {project}...")
    try:
        refresh_db()
    except TrivyNotInstalledError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    try:
        _, decisions, _, _, _ = _scan_one_project(paths, project)
    except TrivyNotInstalledError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    except (RuntimeError, ManifestError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    blocking = []
    for d in decisions:
        for f in d.findings:
            if f.disposition == Disposition.QUARANTINE:
                blocking.append(f)

    if blocking:
        h = blocking[0]
        print(
            f"ERROR: Cannot resume — {h.finding.cve_id} "
            f"({h.effective_severity.value}) would still quarantine.",
            file=sys.stderr,
        )
        print(
            "  Either suppress it (boxmunge security suppress) or wait for "
            "upstream fix.",
            file=sys.stderr,
        )
        return 1

    print("  Re-scan: clear (no quarantine-level findings)")

    # Render normal Caddy site config + compose override using the
    # deploy helpers (the resume_cmd flow does the same).
    from boxmunge.commands.deploy import (
        prepare_caddy_config,
        prepare_compose_override,
    )
    try:
        manifest = load_manifest(paths.project_manifest(project))
    except ManifestError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    try:
        prepare_caddy_config(paths, manifest)
        prepare_compose_override(paths, manifest, component="security-resume")
    except (OSError, ValueError) as e:
        print(f"ERROR: Failed to render Caddy/compose: {e}", file=sys.stderr)
        return 1
    print("  Caddy config restored.")

    site_path = paths.project_caddy_site(project)
    site_content = site_path.read_text() if site_path.exists() else ""
    compose_files = ["compose.yml"]
    if paths.project_compose_override(project).exists():
        compose_files.append("compose.boxmunge.yml")
    try:
        lift_quarantine(
            project, paths,
            project_dir=paths.project_dir(project),
            project_caddy_site_content=site_content,
            compose_files=compose_files,
        )
    except QuarantineError as e:
        print(f"ERROR: lift_quarantine failed: {e}", file=sys.stderr)
        return 1
    print("  Containers started.")

    # Smoke test (lazy import to ease tests).
    from boxmunge.commands.resume_cmd import run_smoke
    smoke_ok, smoke_msg = run_smoke(project, paths)
    if smoke_ok:
        print("  Smoke test: OK")
    else:
        print(f"  Smoke test: FAIL — {smoke_msg}")

    print(f"Project '{project}' resumed.")
    return 0
