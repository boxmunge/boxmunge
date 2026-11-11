# SPDX-License-Identifier: Apache-2.0
"""Per-project scan state persistence.

The CVE policy CLI persists each scan's decisions so subsequent
``boxmunge security <project>`` invocations can render the prior state
without re-running Trivy. The on-disk format is JSON, written atomically.
"""
from __future__ import annotations

import errno
import json
import os
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, TypeVar

from boxmunge.cve.policy import (
    Disposition,
    FindingDisposition,
    ProjectDecision,
)
from boxmunge.cve.scanner import AttackVector, Finding, PkgClass, Severity, VulnStatus
from boxmunge.fileutil import atomic_write_text
from boxmunge.state import StateError, read_state
from boxmunge.fs_nofollow import read_text_nofollow_or_none

E = TypeVar("E", bound=Enum)

# The scan runs daily (03:00-03:30); 36h tolerates one late or missed run's
# worth of jitter without crying wolf, and catches a second missed night.
SCAN_MAX_AGE = timedelta(hours=36)


class ScanStateWriteError(OSError):
    """The scan itself ran; its result could not be recorded."""

    def __init__(self, path: Path, cause: OSError) -> None:
        if cause.errno in (errno.EACCES, errno.EPERM):
            remedy = (f"deploy cannot write {path.parent}. As the supervisor: "
                      f"sudo chown -R deploy:deploy {path.parent} (or re-run the "
                      f"scan as root)")
        else:
            remedy = f"check the filesystem holding {path.parent}"
        super().__init__(f"scanned, but could not record the result in {path}: "
                         f"{cause}. {remedy}")


def _serialize_disposition(d: Any) -> dict[str, Any]:
    """Serialise a FindingDisposition to a JSON-friendly dict.

    Strips the Suppression detail (we keep the full audit-trail in the
    suppressions.yml file; the scan state needs only the disposition tag).
    """
    f = d.finding
    return {
        "cve_id": f.cve_id,
        "base_severity": d.base_severity.value,
        "effective_severity": d.effective_severity.value,
        "hardening_penalty": d.hardening_penalty,
        "disposition": d.disposition.value,
        "explanation": d.explanation,
        "fix_available": f.fix_available,
        "fixed_version": f.fixed_version,
        "package": f.package,
        "primary_url": f.primary_url,
        "title": f.title,
        "installed_version": f.installed_version,
        "attack_vector": f.attack_vector.value if f.attack_vector else None,
        "status": f.status.value,
        "pkg_class": f.pkg_class.value,
        "pkg_type": f.pkg_type,
        "kev_listed": d.kev_listed,
        "fix_would_quarantine": d.fix_would_quarantine,
        "hardening_would_quarantine": d.hardening_would_quarantine,
    }


def _serialize_decision(decision: ProjectDecision) -> dict[str, Any]:
    return {
        "image_ref": decision.image_ref,
        "findings": [_serialize_disposition(d) for d in decision.findings],
    }


# What a scan's targets were: the images the project's containers run, or,
# for a project the platform stopped on purpose, the images `compose up`
# would start when it comes back.
BASIS_CONTAINERS = "containers"
BASIS_STARTUP_IMAGES = "startup_images"


def write_scan_state(
    path: Path,
    *,
    decisions: tuple[ProjectDecision, ...],
    scanned_at: datetime | None = None,
    unscanned: tuple[str, ...] = (),
    basis: str = BASIS_CONTAINERS,
    stopped_reason: str | None = None,
) -> None:
    """Persist the result of a project scan.

    `decisions` is one ProjectDecision per scanned image (most projects have
    one image, multi-service projects can have several). `scanned_at`
    defaults to "now" when omitted. `unscanned` names each image or service
    the scan did not cover, for the scan-freshness health check. `basis`
    records what was scanned (`stopped_reason` says why a project scanned
    by BASIS_STARTUP_IMAGES is stopped).
    """
    when = scanned_at or datetime.now(timezone.utc)
    data: dict[str, Any] = {
        "scanned_at": when.isoformat(),
        "basis": basis,
        "stopped_reason": stopped_reason,
        "decisions": [_serialize_decision(d) for d in decisions],
        "unscanned": list(unscanned),
    }
    try:
        atomic_write_text(path, json.dumps(data, indent=2) + "\n")
    except OSError as e:
        raise ScanStateWriteError(path, e) from e


def last_scanned_at(path: Path) -> str | None:
    """When the last recorded scan result was made (ISO text), or None when
    there is none. Raises StateError, naming the file, when it is unreadable."""
    state = read_scan_state(path)
    if state is None:
        return None
    when = state.get("scanned_at")
    if not isinstance(when, str):
        raise StateError(f"{path}: no scanned_at in the scan state")
    return when


def scan_problem(path: Path, project: str, now: datetime) -> str | None:
    """Why the project has no current, complete scan result at ``path``, or
    None when it has one: recorded within SCAN_MAX_AGE, nothing unscanned."""
    try:
        raw = read_text_nofollow_or_none(path)
        if raw is None:
            return f"{project}: never scanned"
        state = json.loads(raw)
        scanned_at = datetime.fromisoformat(state["scanned_at"])
    except (OSError, ValueError, KeyError, TypeError) as e:
        return f"{project}: scan state unreadable ({e})"
    if scanned_at.tzinfo is None:
        scanned_at = scanned_at.replace(tzinfo=timezone.utc)
    age = now - scanned_at
    if age > SCAN_MAX_AGE:
        return f"{project}: last scanned {age.days}d {age.seconds // 3600}h ago"
    unscanned = state.get("unscanned") or []
    if unscanned:
        return f"{project}: last scan incomplete ({'; '.join(unscanned)})"
    return None


def read_scan_state(path: Path) -> dict[str, Any] | None:
    """Read a previously-written scan state file.

    Returns None when the file does not exist (the "no scan ever ran"
    signal). Raises StateError, naming the file, when it is unreadable or
    not a JSON object — fail loud.
    """
    if not os.path.lexists(path):
        return None
    return read_state(path)


def stored_enum(cls: type[E], value: Any, field: str) -> E:
    """A stored enum value read back; StateError naming the field when it is
    missing or not one of ``cls``'s values (a corrupted or hand-edited file
    is unreadable, never "unknown")."""
    try:
        return cls(value)
    except ValueError:
        raise StateError(
            f"stored {field!r} is {value!r}, not a {cls.__name__} value") from None


def stored_severities(raw: dict[str, Any]) -> tuple[Severity, Severity]:
    """A stored finding's (base, effective) severities."""
    return (stored_enum(Severity, raw.get("base_severity"), "base_severity"),
            stored_enum(Severity, raw.get("effective_severity"), "effective_severity"))


def decisions_from_scan_state(
    state: dict[str, Any], *, project_name: str,
) -> tuple[ProjectDecision, ...]:
    """Reconstruct ProjectDecisions from a previously-written scan_state dict.

    Used by alert-transition logic that needs the prior scan's
    cve_id → disposition mapping plus the prior scan timestamp. Detail not
    needed for transition detection (suppression metadata, raw scanner
    package version) is reconstructed best-effort from what was persisted.

    Each top-level "decision" in the state file becomes one ProjectDecision.
    """
    when_iso = state.get("scanned_at")
    if not when_iso:
        raise ValueError("scan state is missing 'scanned_at'")
    scanned_at = datetime.fromisoformat(when_iso)
    if scanned_at.tzinfo is None:
        scanned_at = scanned_at.replace(tzinfo=timezone.utc)

    decisions: list[ProjectDecision] = []
    for raw_decision in state.get("decisions", []) or []:
        image_ref = raw_decision.get("image_ref", "")
        findings: list[FindingDisposition] = []
        quarantine_required = False
        at_risk_running = False
        for raw in raw_decision.get("findings", []) or []:
            base, effective = stored_severities(raw)
            disposition = stored_enum(Disposition, raw.get("disposition"), "disposition")
            finding = Finding(
                cve_id=raw.get("cve_id", ""),
                severity=base,
                package=raw.get("package", "") or "",
                installed_version=raw.get("installed_version", "") or "",
                fixed_version=raw.get("fixed_version"),
                title=raw.get("title", "") or "",
                primary_url=raw.get("primary_url"),
                # None when Trivy gave no CVSS vector.
                attack_vector=None if raw.get("attack_vector") is None else stored_enum(
                    AttackVector, raw["attack_vector"], "attack_vector"),
                status=stored_enum(VulnStatus, raw.get("status"), "status"),
                pkg_class=stored_enum(PkgClass, raw.get("pkg_class"), "pkg_class"),
                pkg_type=raw.get("pkg_type"),
            )
            findings.append(
                FindingDisposition(
                    finding=finding,
                    base_severity=base,
                    hardening_penalty=int(raw.get("hardening_penalty", 0) or 0),
                    effective_severity=effective,
                    disposition=disposition,
                    suppression=None,
                    explanation=raw.get("explanation", "") or "",
                    kev_listed=raw.get("kev_listed") is True,
                    fix_would_quarantine=raw.get("fix_would_quarantine") is True,
                    hardening_would_quarantine=raw.get("hardening_would_quarantine") is True,
                ),
            )
            if disposition == Disposition.QUARANTINE:
                quarantine_required = True
            if disposition == Disposition.STILL_RUNNING_AT_RISK:
                at_risk_running = True
        decisions.append(
            ProjectDecision(
                project_name=project_name,
                image_ref=image_ref,
                findings=tuple(findings),
                quarantine_required=quarantine_required,
                at_risk_running=at_risk_running,
                scanned_at=scanned_at,
            ),
        )
    return tuple(decisions)
