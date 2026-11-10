# SPDX-License-Identifier: Apache-2.0
"""Value types and constants of the CVE policy engine.

Split from policy.py (the decision engine) to keep it under the file-size
budget. Consumers import these names from ``boxmunge.cve.policy``.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from boxmunge.cve.scanner import SEVERITY_ORDER, Finding, Severity
from boxmunge.cve.suppressions import Suppression


# ---------- enums and constants ----------


class Posture(Enum):
    """Operator-chosen security posture for a project."""

    RELAXED = "relaxed"
    BALANCED = "balanced"
    STRICT = "strict"
    PARANOID = "paranoid"


class Disposition(Enum):
    """Per-finding decision outcome."""

    IGNORED_FIXED = "ignored_fixed"
    SUPPRESSED = "suppressed"
    INFORMATIONAL = "informational"
    QUARANTINE = "quarantine"
    STILL_RUNNING_AT_RISK = "still_running_at_risk"
    # Meets a severity gate that alerts rather than quarantines (balanced):
    # no fix exists yet, not known to be exploited. Alerted once.
    AWAITING_FIX = "awaiting_fix"


# Posture → the severity gate: the minimum effective (distro, below paranoid)
# severity that meets it, and what meeting it does. At-or-above meets it.
# Relaxed has no severity gate (KEV only). Balanced's gate never takes a site
# down: only an actively exploited (KEV) finding does, so a finding there is
# alerted as AWAITING_FIX. PARANOID matches STRICT's Medium threshold but also
# bypasses the distro trust and Attack Vector filter (see evaluate_finding).
_SEVERITY_GATES: dict[Posture, tuple[Severity, Disposition]] = {
    Posture.BALANCED: (Severity.HIGH, Disposition.AWAITING_FIX),
    Posture.STRICT: (Severity.MEDIUM, Disposition.QUARANTINE),
    Posture.PARANOID: (Severity.MEDIUM, Disposition.QUARANTINE),
}

# The release from which balanced quarantines only on KEV: named when a
# quarantine taken under the earlier rule is lifted.
BALANCED_KEV_ONLY_SINCE = "0.11.2"


def severity_gate_quarantines(posture: Posture) -> bool:
    """True iff a non-KEV finding can quarantine under ``posture`` — the
    hardening penalty, which raises severity, can then decide a quarantine."""
    gate = _SEVERITY_GATES.get(posture)
    return gate is not None and gate[1] is Disposition.QUARANTINE


# Human label for posture in explanation strings — lowercase for prose flow.
_POSTURE_LABEL: dict[Posture, str] = {
    Posture.RELAXED: "relaxed",
    Posture.BALANCED: "balanced",
    Posture.STRICT: "strict",
    Posture.PARANOID: "paranoid",
}


# ---------- exceptions ----------


# Inherits ValueError so callers that catch ValueError on bad config
# (the conventional Python boundary error) also catch this.
class PolicyError(ValueError):
    """Policy input is invalid (typically a bad posture string)."""


# ---------- value types ----------


@dataclass(frozen=True)
class FindingDisposition:
    """Per-finding decision."""

    finding: Finding
    base_severity: Severity
    hardening_penalty: int
    effective_severity: Severity
    disposition: Disposition
    suppression: Suppression | None
    explanation: str
    # The CVE was on a fresh CISA KEV catalog when this finding was judged.
    kev_listed: bool = False
    # IGNORED_FIXED only: without the (not yet running) fix, this finding
    # would meet the posture's gate: quarantine, run at risk, or (balanced)
    # be alerted as AWAITING_FIX. The name predates balanced's alert-only gate.
    fix_would_quarantine: bool = False
    # Not quarantine-level under the penalty applied today, but it is under
    # the stricter hardening rule that takes full effect in 0.12: a warning
    # in 0.11.0, never a quarantine.
    hardening_would_quarantine: bool = False


@dataclass(frozen=True)
class ProjectDecision:
    """Project-wide decision aggregated from per-finding dispositions."""

    project_name: str
    image_ref: str
    findings: tuple[FindingDisposition, ...]
    quarantine_required: bool
    at_risk_running: bool
    scanned_at: datetime


# ---------- pure helpers ----------


def elevate_severity(base: Severity, penalty: int) -> Severity:
    """Apply `penalty` steps of elevation to `base`, capped at CRITICAL.

    UNKNOWN is a no-op: the engine has no confident floor to elevate from.
    """
    if base == Severity.UNKNOWN:
        return Severity.UNKNOWN
    return SEVERITY_ORDER[min(base.rank + penalty, Severity.CRITICAL.rank)]


def parse_posture(value: str | None) -> Posture:
    """Parse a posture string (case-insensitive). None → BALANCED.

    This is a defensive boundary: schema validation has already happened
    upstream by the time policy.py sees the value. Internal callers
    construct Posture enums directly.

    Raises PolicyError (a ValueError subclass) on unrecognized values.
    """
    if value is None:
        return Posture.BALANCED
    if not isinstance(value, str) or not value.strip():
        raise PolicyError(f"posture must be a non-empty string, got {value!r}")
    normalized = value.strip().lower()
    for posture in Posture:
        if posture.value == normalized:
            return posture
    valid = ", ".join(p.value for p in Posture)
    raise PolicyError(f"unknown posture {value!r}; expected one of: {valid}")
