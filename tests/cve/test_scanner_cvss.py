# SPDX-License-Identifier: Apache-2.0
"""Numeric CVSS score parsed from Trivy's CVSS block."""

from boxmunge.cve.scanner import _parse_findings


def _score(cvss):
    payload = {"Results": [{"Class": "os-pkgs", "Type": "debian", "Vulnerabilities": [{
        "VulnerabilityID": "CVE-2026-1", "Severity": "HIGH", "PkgName": "libx",
        "InstalledVersion": "1", "CVSS": cvss,
    }]}]}
    [finding] = _parse_findings(payload)
    assert finding.downtime_score() == finding.cvss_score
    return finding.cvss_score


def test_cvss_takes_highest_v3_across_sources():
    assert _score({"nvd": {"V3Score": 7.5}, "redhat": {"V3Score": 9.8}}) == 9.8


def test_cvss_prefers_v3_even_when_v2_is_higher():
    assert _score({"nvd": {"V3Score": 5.0, "V2Score": 10.0}}) == 5.0


def test_cvss_falls_back_to_v2_only_when_no_v3():
    assert _score({"nvd": {"V2Score": 6.8}, "redhat": {"V2Score": 7.1}}) == 7.1


def test_cvss_none_when_trivy_gives_none():
    assert _score({}) is None
    assert _score({"nvd": {"V3Vector": "CVSS:3.1/AV:N"}}) is None
