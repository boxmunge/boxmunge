# SPDX-License-Identifier: Apache-2.0
"""Value types and constants of the CVE policy engine.

Split from policy.py (the decision engine) to keep it under the file-size
budget. Consumers import these names from ``boxmunge.cve.policy``.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from boxmunge.cve.exploited import ExploitedSource, is_full_kev
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
# Relaxed has no severity gate (KEV only). Balanced's and strict's gates never
# take a site down at scan time: only an actively exploited (KEV) finding
# does, so a finding with no fix there is alerted as AWAITING_FIX (a fixable
# one is patched; strict also has the fix deadline). PARANOID matches STRICT's
# Medium threshold, quarantines on it, and bypasses the distro trust and
# Attack Vector filter (see evaluate_finding).
_SEVERITY_GATES: dict[Posture, tuple[Severity, Disposition]] = {
    Posture.BALANCED: (Severity.HIGH, Disposition.AWAITING_FIX),
    Posture.STRICT: (Severity.MEDIUM, Disposition.AWAITING_FIX),
    Posture.PARANOID: (Severity.MEDIUM, Disposition.QUARANTINE),
}

# What a finding judged as if it had no fix must come to for it to meet the
# posture's gate (quarantine, run at risk, or be alerted as awaiting a fix).
GATE_MET: frozenset[Disposition] = frozenset({
    Disposition.QUARANTINE, Disposition.STILL_RUNNING_AT_RISK, Disposition.AWAITING_FIX,
})

# The release from which balanced quarantines only on KEV: named when a
# quarantine taken under the earlier rule is lifted.
BALANCED_KEV_ONLY_SINCE = "0.11.2"


def penalty_can_decide_downtime(posture: Posture) -> bool:
    """True iff the hardening penalty, which raises severity, can decide
    downtime for a non-KEV finding under ``posture``: paranoid's gate
    quarantines; strict's alerts and patches, and a fix not deployed in time
    quarantines. Under relaxed and balanced only KEV takes a site down."""
    return posture in (Posture.STRICT, Posture.PARANOID)


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


_SOURCE_LABEL = {
    ExploitedSource.CISA: "CISA KEV",
    ExploitedSource.EU: "EU KEV",
    ExploitedSource.VULNCHECK: "VulnCheck KEV",
}


def listing_label(sources: frozenset[ExploitedSource]) -> str:
    """The lists that name a CVE, as an operator reads them: "CISA KEV, EU KEV"."""
    return ", ".join(_SOURCE_LABEL[s] for s in ExploitedSource if s in sources)


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
    # The fresh known-exploited sources that listed the CVE when this finding
    # was judged (CISA, EU, VulnCheck); empty when none did.
    exploited_by: frozenset[ExploitedSource] = frozenset()
    # IGNORED_FIXED only: without the (not yet running) fix, this finding
    # would meet the posture's gate: run at risk, or (balanced, strict) be
    # alerted as AWAITING_FIX. The name predates the alert-only gates.
    fix_would_quarantine: bool = False
    # Fix available, not known exploited, and without the fix the finding
    # would meet the gate autofix patches at: the posture's own, balanced's
    # under relaxed. Set only by the policy's non-KEV fix branch.
    fix_meets_patch_gate: bool = False
    # Not quarantine-level under the penalty applied today, but it is under
    # the stricter hardening rule that takes full effect in 0.12: a warning
    # in 0.11.0, never a quarantine.
    hardening_would_quarantine: bool = False
    # The KEV override decided this disposition (not persisted: it only
    # shapes the alert of the scan that made the decision).
    kev_override: bool = False

    @property
    def full_kev(self) -> bool:
        """Listed by CISA or the EU: the KEV override applies."""
        return is_full_kev(self.exploited_by)

    @property
    def exploited_label(self) -> str:
        return listing_label(self.exploited_by)


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
