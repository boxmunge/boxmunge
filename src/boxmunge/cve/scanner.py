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
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from boxmunge.cve.scanner_cvss import (
    AttackVector,
    _parse_attack_vector,
    _parse_cvss_score,
)

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
    """CVE severity classes, ordered by ``rank`` (SEVERITY_ORDER)."""

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

    @property
    def rank(self) -> int:
        """0 (UNKNOWN) to 4 (CRITICAL): the order findings sort and gates
        compare in, and Trivy's VendorSeverity scale."""
        return SEVERITY_ORDER.index(self)


# Least to most severe. UNKNOWN is lowest, so unclassified findings never
# crowd out real ones and never pass a threshold.
SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.UNKNOWN, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL,
)


class VulnStatus(Enum):
    """Distro/vendor triage status for a CVE, from Trivy's `Status` field.

    The distro's own verdict on a finding. `will_not_fix` / `fix_deferred` /
    `not_affected` / `under_investigation` are the "not a big deal / not
    urgent" signals the quarantine policy trusts below paranoid posture.
    """

    AFFECTED = "affected"
    FIXED = "fixed"
    UNDER_INVESTIGATION = "under_investigation"
    WILL_NOT_FIX = "will_not_fix"
    FIX_DEFERRED = "fix_deferred"
    END_OF_LIFE = "end_of_life"
    NOT_AFFECTED = "not_affected"
    UNKNOWN = "unknown"

    @classmethod
    def from_trivy_string(cls, raw: str | None) -> "VulnStatus":
        if not raw:
            return cls.UNKNOWN
        return _TRIVY_STATUS_MAP.get(raw.strip().lower(), cls.UNKNOWN)


_TRIVY_STATUS_MAP: dict[str, VulnStatus] = {
    s.value: s for s in VulnStatus if s is not VulnStatus.UNKNOWN
}


class PkgClass(Enum):
    """Which layer of the image a finding's package came from.

    Trivy reports this per *result*, not per vulnerability: `os-pkgs` are
    base-image distro packages, `lang-pkgs` are the application's own
    dependencies. The relevance gate uses this to tell "the base image ships
    perl" from "this app depends on perl".
    """

    OS = "os-pkgs"
    LANG = "lang-pkgs"
    UNKNOWN = "unknown"

    @classmethod
    def from_trivy_string(cls, raw: str | None) -> "PkgClass":
        if not raw:
            return cls.UNKNOWN
        return _TRIVY_CLASS_MAP.get(raw.strip().lower(), cls.UNKNOWN)


_TRIVY_CLASS_MAP: dict[str, PkgClass] = {
    c.value: c for c in PkgClass if c is not PkgClass.UNKNOWN
}

# Trivy OS result `Type` -> the VendorSeverity keys of that distro's own
# security team (trivy-db source ids), in preference order. distro_severity()
# reads only the scanned image's own distro: another distro's rating (ubuntu
# or the redhat family on a Debian image) is not the verdict of the team that
# triaged the package, and counting it let a finding Debian triaged as minor
# quarantine a site. Types and keys checked against Trivy 0.58.0 output for
# real images: debian, ubuntu, alpine, amazon, rocky, oracle, sles (suse-cvrf),
# azurelinux (azure), cbl-mariner. Mapped from Trivy's names but not seen
# rating anything: alma, centos/redhat, photon, wolfi, chainguard, openSUSE.
_OS_TYPE_VENDOR: dict[str, tuple[str, ...]] = {
    "debian": ("debian",), "ubuntu": ("ubuntu",), "alpine": ("alpine",),
    "redhat": ("redhat",), "centos": ("redhat",), "rocky": ("rocky",),
    "alma": ("alma",), "amazon": ("amazon",), "oracle": ("oracle-oval",),
    "photon": ("photon",), "wolfi": ("wolfi",), "chainguard": ("chainguard",),
    "sles": ("suse-cvrf",), "opensuse-leap": ("suse-cvrf",),
    "opensuse-tumbleweed": ("suse-cvrf",),
    "azurelinux": ("azure",), "cbl-mariner": ("cbl-mariner", "azure"),
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
    status: VulnStatus = VulnStatus.UNKNOWN
    vendor_severities: dict[str, Severity] = field(default_factory=dict)
    severity_source: str | None = None
    pkg_class: PkgClass = PkgClass.UNKNOWN
    # Highest CVSS v3 base score across Trivy's sources (v2 when none has a
    # v3 score); None when Trivy gave no score.
    cvss_score: float | None = None
    # Trivy's raw `Type` (e.g. "debian", "python-pkg"). For OS packages it
    # names the distro whose own severity distro_severity() reads.
    pkg_type: str | None = None

    @property
    def fix_available(self) -> bool:
        return self.fixed_version is not None

    def downtime_score(self) -> float | None:
        """The score a "CVSS N or above" downtime rule compares against."""
        return self.cvss_score


@dataclass(frozen=True)
class ScanResult:
    """Result of a single Trivy scan against an image reference."""

    image_ref: str
    findings: tuple[Finding, ...]
    scanned_at: datetime
    db_version: str | None
    lang_types: frozenset[str] = frozenset()


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
        subprocess.run(cmd, capture_output=True, text=True, check=True,
                       timeout=_DB_REFRESH_TIMEOUT)
    except FileNotFoundError:
        _LOGGER.warning("trivy DB refresh skipped: %s", _TRIVY_NOT_FOUND_MSG, extra=_extra())
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


def trivy_db_version() -> str:
    """The vulnerability DB Trivy scans with now, as "<schema>:<built at>"
    (`trivy version`): a cached result is valid only for the same one
    (cve.scan_cache). Raises TrivyNotInstalledError, or ScannerError when
    Trivy fails or does not name its DB (none downloaded yet)."""
    cmd = ["trivy", "version", "--format", "json"]
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, check=True,
                                   timeout=_DB_REFRESH_TIMEOUT)
    except FileNotFoundError as e:
        raise TrivyNotInstalledError(_TRIVY_NOT_FOUND_MSG) from e
    except subprocess.TimeoutExpired as e:
        raise ScannerError(f"`trivy version` timed out after {_DB_REFRESH_TIMEOUT}s") from e
    except subprocess.CalledProcessError as e:
        raise ScannerError(f"`trivy version` failed (exit {e.returncode}): "
                           f"{(e.stderr or '').strip()}") from e
    try:
        db = json.loads(completed.stdout)["VulnerabilityDB"]
        schema, built = db["Version"], db["UpdatedAt"]
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        raise ScannerError(f"`trivy version` does not name its vulnerability DB ({e!r}); "
                           f"run `trivy image --download-db-only`") from e
    if not isinstance(built, str) or not built:
        raise ScannerError(f"`trivy version` gives the vulnerability DB no build time: {db!r}")
    return f"{schema}:{built}"


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
        # UNKNOWN too: a KEV CVE no source has rated yet must reach the KEV check.
        "--severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
        "--scanners", "vuln",
        "--skip-db-update",  # each command runs refresh_db once before scanning
        "--no-progress",
        "--quiet",
        "--", image_ref,
    ]
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, check=True,
                                   timeout=timeout)
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
    lang_types = _parse_lang_types(payload)
    db_version = _extract_db_version(payload)
    return ScanResult(
        image_ref=image_ref,
        findings=findings,
        scanned_at=datetime.now(timezone.utc),
        db_version=db_version,
        lang_types=lang_types,
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
    image = payload.get("ArtifactName") or "<unknown image>"
    warned_types: set[tuple[str, str | None]] = set()

    for result in results:
        pkg_class = PkgClass.from_trivy_string(result.get("Class"))
        pkg_type = result.get("Type") or None
        if (pkg_class is PkgClass.OS and pkg_type not in _OS_TYPE_VENDOR
                and (image, pkg_type) not in warned_types):
            warned_types.add((image, pkg_type))
            _LOGGER.warning(
                "scan of %s: OS type %r has no distro severity mapping; its "
                "findings get no distro verdict (informational below paranoid)",
                image, pkg_type,
                extra=_extra(detail={"image": image, "os_type": pkg_type}),
            )

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
                status=VulnStatus.from_trivy_string(vuln.get("Status")),
                vendor_severities=_parse_vendor_severities(
                    vuln.get("VendorSeverity") or {},
                ),
                severity_source=vuln.get("SeveritySource") or None,
                pkg_class=pkg_class,
                cvss_score=_parse_cvss_score(vuln.get("CVSS") or {}),
                pkg_type=pkg_type,
            ))

    findings.sort(key=lambda f: (-f.severity.rank, f.cve_id))
    return tuple(findings)


def _parse_lang_types(payload: dict[str, Any]) -> frozenset[str]:
    """Every distinct Trivy `Type` reported for a lang-pkgs result.

    Trivy only emits a `Vulnerabilities` entry for packages with a known
    CVE, so a project whose dependencies are fully patched produces zero
    lang-pkgs *findings* — but Trivy still emits the lang-pkgs *Result* row
    itself (Type set, Vulnerabilities empty or absent) whenever it detected
    a manifest for that ecosystem. That row, not the findings, is the
    signal that the project runs a given language runtime at all: relying
    on findings alone would mean patching your dependencies strips the
    relevance gate's protection for your own runtime.
    """
    results = payload.get("Results") or []
    return frozenset(
        result["Type"]
        for result in results
        if PkgClass.from_trivy_string(result.get("Class")) is PkgClass.LANG
        and result.get("Type")
    )


def _parse_vendor_severities(raw: Any) -> dict[str, Severity]:
    """Map Trivy's VendorSeverity {source: int} to {source: Severity}.

    Trivy emits integer levels 0-4 per source. Unrecognised keys/values are
    skipped rather than raising — a malformed entry shouldn't drop the scan.
    """
    if not isinstance(raw, dict):
        return {}
    out: dict[str, Severity] = {}
    for source, level in raw.items():
        if not isinstance(source, str):
            continue
        # Trivy VendorSeverity encodes severity as its rank, an int 0-4.
        if level in range(len(SEVERITY_ORDER)):
            out[source] = SEVERITY_ORDER[int(level)]
    return out


def distro_severity(finding: Finding) -> Severity | None:
    """Return the scanned image's own distro severity for this finding, or None.

    Only the vendor source matching the finding's OS type counts (Debian's
    urgency on a Debian image). None means "no distro verdict": the distro
    team rated nothing (a Debian no-DSA finding) or only other feeds rated
    it (NVD, GHSA, other distros), so the policy engine has no distro opinion
    to quarantine on below paranoid posture.
    """
    for vendor in _OS_TYPE_VENDOR.get(finding.pkg_type or "", ()):
        sev = finding.vendor_severities.get(vendor)
        if sev is not None and sev is not Severity.UNKNOWN:
            return sev
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
