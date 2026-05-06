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


class Severity(Enum):
    """CVE severity classes. Ordering used for deterministic sort."""

    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"
    UNKNOWN = "Unknown"


# Sort priority: higher number = sorts earlier in descending sort.
# UNKNOWN sorts last so unclassified findings don't crowd out real ones.
_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.UNKNOWN: 0,
}

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
        )
    except subprocess.TimeoutExpired:
        _LOGGER.warning(
            "trivy DB refresh timed out after %ds — continuing with existing DB",
            _DB_REFRESH_TIMEOUT,
        )
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or "").strip()
        _LOGGER.warning(
            "trivy DB refresh failed (exit %d): %s — continuing with existing DB",
            e.returncode, stderr,
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
            raw_sev = (vuln.get("Severity") or "").upper()
            severity = _TRIVY_SEVERITY_MAP.get(raw_sev)
            if severity is None:
                if not unknown_severity_logged:
                    _LOGGER.warning(
                        "trivy returned unrecognised severity %r — mapping to UNKNOWN",
                        vuln.get("Severity"),
                    )
                    unknown_severity_logged = True
                severity = Severity.UNKNOWN

            findings.append(Finding(
                cve_id=vuln.get("VulnerabilityID", ""),
                severity=severity,
                package=vuln.get("PkgName", ""),
                installed_version=vuln.get("InstalledVersion", ""),
                fixed_version=vuln.get("FixedVersion") or None,
                title=vuln.get("Title", ""),
                primary_url=vuln.get("PrimaryURL") or None,
            ))

    findings.sort(key=lambda f: (-_SEVERITY_RANK[f.severity], f.cve_id))
    return tuple(findings)


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
