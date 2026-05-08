# SPDX-License-Identifier: Apache-2.0
"""Per-project scan state persistence.

The CVE policy CLI persists each scan's decisions so subsequent
``boxmunge security <project>`` invocations can render the prior state
without re-running Trivy. The on-disk format is JSON, written atomically.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from boxmunge.cve.policy import (
    Disposition,
    FindingDisposition,
    ProjectDecision,
)
from boxmunge.cve.scanner import AttackVector, Finding, Severity
from boxmunge.fileutil import atomic_write_text


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
    }


def _serialize_decision(decision: ProjectDecision) -> dict[str, Any]:
    return {
        "image_ref": decision.image_ref,
        "findings": [_serialize_disposition(d) for d in decision.findings],
    }


def write_scan_state(
    path: Path,
    *,
    decisions: tuple[ProjectDecision, ...],
    scanned_at: datetime | None = None,
) -> None:
    """Persist the result of a project scan.

    `decisions` is one ProjectDecision per scanned image (most projects have
    one image, multi-service projects can have several). `scanned_at`
    defaults to "now" when omitted.
    """
    when = scanned_at or datetime.now(timezone.utc)
    data: dict[str, Any] = {
        "scanned_at": when.isoformat(),
        "decisions": [_serialize_decision(d) for d in decisions],
    }
    atomic_write_text(path, json.dumps(data, indent=2) + "\n")


def read_scan_state(path: Path) -> dict[str, Any] | None:
    """Read a previously-written scan state file.

    Returns None when the file does not exist (the "no scan ever ran"
    signal). Raises on malformed JSON — fail loud.
    """
    if not path.exists():
        return None
    return json.loads(path.read_text())


def headline_from_scan_state(state: dict[str, Any]) -> dict[str, Any] | None:
    """Pick the most-severe quarantine-disposition finding across all decisions.

    Returns None if no quarantine-level finding exists. Useful for fleet
    summaries and per-project text output.
    """
    _RANK = {
        Severity.CRITICAL.value: 4,
        Severity.HIGH.value: 3,
        Severity.MEDIUM.value: 2,
        Severity.LOW.value: 1,
        Severity.UNKNOWN.value: 0,
    }
    headline: dict[str, Any] | None = None
    for decision in state.get("decisions", []):
        for f in decision.get("findings", []):
            if f.get("disposition") != Disposition.QUARANTINE.value:
                continue
            if headline is None:
                headline = f
                continue
            if _RANK.get(f.get("effective_severity"), 0) > _RANK.get(
                headline.get("effective_severity"), 0,
            ):
                headline = f
    return headline


def _deserialize_severity(value: str) -> Severity:
    """Map a stored severity string back to the enum. Unknown → UNKNOWN."""
    for sev in Severity:
        if sev.value == value:
            return sev
    return Severity.UNKNOWN


def _deserialize_attack_vector(value: Any) -> AttackVector | None:
    """Map a stored attack_vector string back to the enum.

    Accepts None or missing field for backward compatibility with scan_state
    files written before v0.7.1 introduced the attack_vector field. Anything
    else unrecognized also falls back to None — failing here would block the
    operator from reading legacy state, and the caller treats None as
    "AV unknown" already.
    """
    if value is None:
        return None
    for av in AttackVector:
        if av.value == value:
            return av
    return None


def _deserialize_disposition(value: str) -> Disposition:
    """Map a stored disposition tag back to the enum.

    Raises ValueError on an unknown tag — fail loud rather than silently
    coercing (we can't reason about a state-file we don't recognize).
    """
    for d in Disposition:
        if d.value == value:
            return d
    raise ValueError(f"unknown disposition tag in scan state: {value!r}")


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
            base = _deserialize_severity(raw.get("base_severity", "Unknown"))
            effective = _deserialize_severity(
                raw.get("effective_severity", "Unknown"),
            )
            disposition = _deserialize_disposition(raw["disposition"])
            finding = Finding(
                cve_id=raw.get("cve_id", ""),
                severity=base,
                package=raw.get("package", "") or "",
                installed_version=raw.get("installed_version", "") or "",
                fixed_version=raw.get("fixed_version"),
                title=raw.get("title", "") or "",
                primary_url=raw.get("primary_url"),
                attack_vector=_deserialize_attack_vector(
                    raw.get("attack_vector"),
                ),
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
