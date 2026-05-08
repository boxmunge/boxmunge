# SPDX-License-Identifier: Apache-2.0
"""Trivy CLI wrapper — scan a container image and parse findings.

This module is intentionally thin and deterministic: it shells out to the
Trivy binary, parses its JSON output, and returns a structured ScanResult.
Policy decisions (what severity to gate on, what to do about findings) and
side effects (quarantine, alerts) live in modules layered on top of this one.

Failure mode philosophy:
- scan_image fails noisily — Trivy missing, subprocess failure, malformed JSON
  all raise ScannerError (or its TrivyNotInstalledError subclass).
- refresh_db is the sole best-effort path: a stale DB is preferable to no
  scan at all, so a download failure is logged and swallowed.
"""

from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

_LOGGER = logging.getLogger("boxmunge")
_DEFAULT_TIMEOUT = 300
_DB_REFRESH_TIMEOUT = 120
_TRIVY_INSTALL_URL = (
    "https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
)
_TRIVY_NOT_FOUND_MSG = (
    f"trivy not found on PATH. Install: {_TRIVY_INSTALL_URL}"
)


def _extra(detail: dict[str, Any] | None = None) -> dict[str, Any]:
    """Structured-extras helper: the scanner is fleet-level, project=None."""
    return {"component": "cve-scan", "project": None, "detail": detail}


class Severity(Enum):
    """CVE severity classes. Ordering used for deterministic sort."""

    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"
    UNKNOWN = "Unknown"

    @classmethod
    def from_trivy_string(cls, raw: str | None) -> "Severity":
        """Map a Trivy severity string to the Severity enum.

        Case-insensitive: "CRITICAL", "Critical", "critical" all map to
        Severity.CRITICAL. Anything else (including None or empty) maps
        to UNKNOWN. Audit F-4: defensive against schema drift — if Trivy
        ever emits mixed-case strings, every finding stays correctly
        classified rather than silently downgrading to UNKNOWN.
        """
        if not raw:
            return cls.UNKNOWN
        return _TRIVY_SEVERITY_MAP.get(raw.upper(), cls.UNKNOWN)


class AttackVector(Enum):
    """CVSS Attack Vector — where the attacker must be to exploit.

    Reflects the AV: token in a CVSS v3/v4 vector string. v0.7.1 quarantine
    decisions gate on AV:N (Network) under non-paranoid postures: AV:L/A/P
    findings are reported as informational because they aren't reachable
    from the network surface a hardened web container exposes.
    """

    NETWORK = "Network"
    ADJACENT = "Adjacent"
    LOCAL = "Local"
    PHYSICAL = "Physical"


# CVSS AV: token → AttackVector. Trivy reports the canonical single-letter
# tokens; we tolerate the value being inside a longer vector string.
_AV_TOKEN_MAP: dict[str, AttackVector] = {
    "N": AttackVector.NETWORK,
    "A": AttackVector.ADJACENT,
    "L": AttackVector.LOCAL,
    "P": AttackVector.PHYSICAL,
}


# Source priority for resolving disagreements when multiple feeds report a
# CVE. NVD is preferred where present (most-curated), then redhat (good distro
# coverage), then ghsa (active for ecosystem packages). Anything else is taken
# in alphabetical order for determinism.
_CVSS_SOURCE_PRIORITY: tuple[str, ...] = ("nvd", "redhat", "ghsa")


# Sort priority: higher number = sorts earlier in descending sort.
# UNKNOWN sorts last so unclassified findings don't crowd out real ones.
_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.UNKNOWN: 0,
}

# Internal map keyed by upper-case Trivy severity. Use
# Severity.from_trivy_string() rather than indexing this directly so
# case-normalization stays at one boundary.
_TRIVY_SEVERITY_MAP: dict[str, Severity] = {
    "LOW": Severity.LOW,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
    "UNKNOWN": Severity.UNKNOWN,
}


@dataclass(frozen=True)
class Finding:
    """A single CVE entry parsed from Trivy output."""

    cve_id: str
    severity: Severity
    package: str
    installed_version: str
    fixed_version: str | None
    title: str
    primary_url: str | None
    attack_vector: AttackVector | None = None

    @property
    def fix_available(self) -> bool:
        return self.fixed_version is not None


@dataclass(frozen=True)
class ScanResult:
    """Result of a single Trivy scan against an image reference."""

    image_ref: str
    findings: tuple[Finding, ...]
    scanned_at: datetime
    db_version: str | None


class ScannerError(Exception):
    """Trivy invocation or parsing failed."""


class TrivyNotInstalledError(ScannerError):
    """Trivy CLI not on PATH."""


def refresh_db() -> None:
    """Download the latest Trivy vulnerability DB. Best-effort.

    A failed refresh is logged at WARNING and swallowed: a stale DB still
    permits a scan, and we'd rather scan with old data than skip the scan
    entirely. The operator sees the warning in the boxmunge log if it
    becomes a recurring problem.
    """
    cmd = ["trivy", "image", "--download-db-only"]
    try:
        subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            timeout=_DB_REFRESH_TIMEOUT,
        )
    except FileNotFoundError:
        _LOGGER.warning(
            "trivy DB refresh skipped: %s", _TRIVY_NOT_FOUND_MSG,
            extra=_extra(),
        )
    except subprocess.TimeoutExpired:
        _LOGGER.warning(
            "trivy DB refresh timed out after %ds — continuing with existing DB",
            _DB_REFRESH_TIMEOUT,
            extra=_extra(detail={"timeout_s": _DB_REFRESH_TIMEOUT}),
        )
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or "").strip()
        _LOGGER.warning(
            "trivy DB refresh failed (exit %d): %s — continuing with existing DB",
            e.returncode, stderr,
            extra=_extra(detail={"exit_code": e.returncode, "stderr": stderr}),
        )


def scan_image(image_ref: str, *, timeout: int = _DEFAULT_TIMEOUT) -> ScanResult:
    """Scan a container image with Trivy and return parsed findings.

    image_ref may be a tag (e.g. "myapp:1.2.3") or a digest pin
    (e.g. "myapp@sha256:..."). Returns a ScanResult with findings sorted
    by severity descending then CVE ID ascending for deterministic output.

    Raises:
        TrivyNotInstalledError: when the trivy binary is not on PATH.
        ScannerError: on subprocess failure, timeout, or unparseable output.
    """
    cmd = [
        "trivy", "image",
        "--format", "json",
        "--severity", "LOW,MEDIUM,HIGH,CRITICAL",
        "--no-progress",
        "--quiet",
        image_ref,
    ]
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            timeout=timeout,
        )
    except FileNotFoundError as e:
        raise TrivyNotInstalledError(_TRIVY_NOT_FOUND_MSG) from e
    except subprocess.TimeoutExpired as e:
        raise ScannerError(
            f"trivy scan timed out after {timeout}s for image {image_ref!r}"
        ) from e
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or "").strip()
        raise ScannerError(
            f"trivy scan failed for image {image_ref!r} (exit {e.returncode}): "
            f"{stderr}"
        ) from e

    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as e:
        raise ScannerError(
            f"trivy returned unparseable JSON for image {image_ref!r}: {e}"
        ) from e

    findings = _parse_findings(payload)
    db_version = _extract_db_version(payload)
    return ScanResult(
        image_ref=image_ref,
        findings=findings,
        scanned_at=datetime.now(timezone.utc),
        db_version=db_version,
    )


def _parse_findings(payload: dict[str, Any]) -> tuple[Finding, ...]:
    """Walk the Trivy JSON document and extract every vulnerability.

    Trivy structure: top-level dict with `Results` array; each result has
    optional `Vulnerabilities` array. Missing/empty `Results` is a valid
    zero-finding scan, not an error.
    """
    results = payload.get("Results") or []
    findings: list[Finding] = []
    unknown_severity_logged = False

    for result in results:
        for vuln in result.get("Vulnerabilities") or []:
            raw_sev = vuln.get("Severity")
            severity = Severity.from_trivy_string(raw_sev)
            if severity is Severity.UNKNOWN and (raw_sev or "").upper() != "UNKNOWN":
                # Trivy emitted a value we don't recognise — log once and
                # carry on with UNKNOWN. The empty/None case is handled
                # silently (treated as a vuln with no severity field).
                if not unknown_severity_logged:
                    _LOGGER.warning(
                        "trivy returned unrecognised severity %r — mapping to UNKNOWN",
                        raw_sev,
                        extra=_extra(detail={"raw_severity": raw_sev}),
                    )
                    unknown_severity_logged = True

            findings.append(Finding(
                cve_id=vuln.get("VulnerabilityID", ""),
                severity=severity,
                package=vuln.get("PkgName", ""),
                installed_version=vuln.get("InstalledVersion", ""),
                fixed_version=vuln.get("FixedVersion") or None,
                title=vuln.get("Title", ""),
                primary_url=vuln.get("PrimaryURL") or None,
                attack_vector=_parse_attack_vector(vuln.get("CVSS") or {}),
            ))

    findings.sort(key=lambda f: (-_SEVERITY_RANK[f.severity], f.cve_id))
    return tuple(findings)


def _parse_attack_vector(cvss: dict[str, Any]) -> AttackVector | None:
    """Extract the CVSS Attack Vector from a Trivy `CVSS` block.

    Trivy emits one entry per data source (nvd, redhat, ghsa, ...), each with
    optional V3Vector and/or V40Vector strings. We walk sources in a fixed
    priority order (nvd, redhat, ghsa, then any others alphabetically) and
    take the first parseable AV: token. V3 is preferred over V4 because the
    Trivy DB still has wider V3 coverage in 2026.

    Returns None when no source has a parseable vector — the caller treats
    that as "AV unknown", which under non-paranoid posture defaults to
    informational.
    """
    if not isinstance(cvss, dict) or not cvss:
        return None

    extras = sorted(k for k in cvss.keys() if k not in _CVSS_SOURCE_PRIORITY)
    ordered_sources = (*_CVSS_SOURCE_PRIORITY, *extras)

    for source in ordered_sources:
        entry = cvss.get(source)
        if not isinstance(entry, dict):
            continue
        for vector_key in ("V3Vector", "V40Vector"):
            vector = entry.get(vector_key)
            av = _extract_av_from_vector(vector)
            if av is not None:
                return av
    return None


def _extract_av_from_vector(vector: Any) -> AttackVector | None:
    """Pull the AV: token out of a CVSS vector string.

    Tolerant of either prefix (CVSS:3.1/, CVSS:4.0/) and any token order.
    Returns None for non-strings, missing AV: token, or unrecognized values.
    """
    if not isinstance(vector, str) or not vector:
        return None
    for token in vector.split("/"):
        if not token.startswith("AV:"):
            continue
        value = token[3:].strip().upper()
        return _AV_TOKEN_MAP.get(value)
    return None


def _extract_db_version(payload: dict[str, Any]) -> str | None:
    """Best-effort DB version extraction from Trivy's Metadata block.

    Trivy reports DB metadata under `Metadata.DB.UpdatedAt` (an ISO 8601
    timestamp) in recent releases. Older releases may not emit it. If the
    field is absent, return None — the caller can wire up `trivy version`
    parsing later if needed.
    """
    metadata = payload.get("Metadata") or {}
    db = metadata.get("DB") or {}
    updated_at = db.get("UpdatedAt")
    if isinstance(updated_at, str) and updated_at:
        return updated_at
    return None
