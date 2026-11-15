# SPDX-License-Identifier: Apache-2.0
"""The Debian security team's triage verdict reaches the policy.

The fixture is trimmed output of a real Trivy 0.58.0 scan of
debian:bookworm-slim. How Trivy reports Debian's tracker verdicts:
  <ignored>              -> Status will_not_fix
  <postponed>            -> Status fix_deferred
  <unimportant>/low      -> Status affected, VendorSeverity debian = LOW
  <no-dsa> (no reason)   -> Status affected, NO debian VendorSeverity; other
                            distros (ubuntu, redhat family) still rate it.
The last row is the one that used to slip through: another distro's rating
was read as "the distro's" verdict.
"""
import json
from datetime import date
from pathlib import Path

import pytest

from boxmunge.cve.policy import Disposition, Posture, evaluate_finding
from boxmunge.cve.scanner import Severity, VulnStatus, _parse_findings, distro_severity

_FIXTURE = Path(__file__).parent.parent / "fixtures" / "trivy_debian_distro_verdict.json"
_FINDINGS = {f.cve_id: f for f in _parse_findings(json.loads(_FIXTURE.read_text()))}

_IGNORED = "CVE-2016-2781"
_POSTPONED = "CVE-2026-95619"
_NO_DSA_PLAIN = "CVE-2026-5435"        # network-reachable, Medium on ubuntu/redhat
_NO_DSA_PLAIN_LOW_ONLY = "CVE-2026-42250"
_UNIMPORTANT = "CVE-2017-18018"
_TRIAGED = (_IGNORED, _POSTPONED, _NO_DSA_PLAIN, _NO_DSA_PLAIN_LOW_ONLY,
            "CVE-2024-10041", "CVE-2026-3184", "CVE-2026-41991")


def _decide(cve: str, posture: Posture, penalty: int = 0) -> Disposition:
    return evaluate_finding(
        _FINDINGS[cve], posture=posture, hardening_penalty=penalty,
        dangerously_disable_quarantine=False, suppressions=(),
        today=date(2026, 11, 15),
    ).disposition


def test_trivy_reports_ignored_and_postponed_as_their_own_statuses() -> None:
    assert _FINDINGS[_IGNORED].status is VulnStatus.WILL_NOT_FIX
    assert _FINDINGS[_POSTPONED].status is VulnStatus.FIX_DEFERRED
    assert _FINDINGS[_NO_DSA_PLAIN].status is VulnStatus.AFFECTED


def test_another_distros_rating_is_not_the_distro_verdict() -> None:
    # Debian gave libc6's no-DSA finding no severity; ubuntu rated it Medium.
    assert "debian" not in _FINDINGS[_NO_DSA_PLAIN].vendor_severities
    assert distro_severity(_FINDINGS[_NO_DSA_PLAIN]) is None
    assert distro_severity(_FINDINGS[_NO_DSA_PLAIN_LOW_ONLY]) is None
    assert distro_severity(_FINDINGS[_UNIMPORTANT]) is Severity.LOW


@pytest.mark.parametrize("cve", _TRIAGED)
@pytest.mark.parametrize("posture", [Posture.RELAXED, Posture.BALANCED, Posture.STRICT])
@pytest.mark.parametrize("penalty", [0, 1, 2])
def test_no_dsa_finding_never_quarantines_below_paranoid(
    cve: str, posture: Posture, penalty: int,
) -> None:
    assert _decide(cve, posture, penalty) is not Disposition.QUARANTINE


def test_paranoid_still_quarantines_the_triaged_finding() -> None:
    assert _decide(_NO_DSA_PLAIN, Posture.PARANOID) is Disposition.QUARANTINE


def test_debian_low_urgency_below_strict_gate() -> None:
    f = _FINDINGS[_UNIMPORTANT]
    assert distro_severity(f) is Severity.LOW
    assert _decide(_UNIMPORTANT, Posture.STRICT) is Disposition.INFORMATIONAL


def _os_payload(os_type: str, image: str = "img:1") -> dict:
    vuln = {"VulnerabilityID": "CVE-2026-0001", "PkgName": "p", "Severity": "HIGH",
            "Status": "affected", "VendorSeverity": {"nvd": 3, "madeup": 3}}
    return {"ArtifactName": image, "Results": [
        {"Class": "os-pkgs", "Type": os_type, "Vulnerabilities": [vuln, vuln | {"VulnerabilityID": "CVE-2026-0002"}]},
    ]}


def test_unmapped_os_type_gets_no_verdict_and_one_warning(caplog) -> None:
    with caplog.at_level("WARNING", logger="boxmunge"):
        findings = _parse_findings(_os_payload("madeup"))
    assert all(distro_severity(f) is None for f in findings)
    warnings = [r for r in caplog.records if "no distro severity mapping" in r.getMessage()]
    assert len(warnings) == 1
    assert "'madeup'" in warnings[0].getMessage() and "img:1" in warnings[0].getMessage()


@pytest.mark.parametrize("os_type,vendor", [
    ("sles", "suse-cvrf"), ("opensuse-leap", "suse-cvrf"), ("azurelinux", "azure"),
    ("cbl-mariner", "cbl-mariner"), ("wolfi", "wolfi"), ("alpine", "alpine"),
    ("amazon", "amazon"), ("rocky", "rocky"), ("photon", "photon"),
])
def test_mapped_os_types_read_their_own_vendor_and_do_not_warn(
    os_type: str, vendor: str, caplog,
) -> None:
    payload = _os_payload(os_type)
    for v in payload["Results"][0]["Vulnerabilities"]:
        v["VendorSeverity"] = {vendor: 3, "ubuntu": 1}
    with caplog.at_level("WARNING", logger="boxmunge"):
        findings = _parse_findings(payload)
    assert [distro_severity(f) for f in findings] == [Severity.HIGH] * 2
    assert not caplog.records
