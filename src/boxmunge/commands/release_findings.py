# SPDX-License-Identifier: Apache-2.0
"""One line per finding of a release's scan, as a refused deploy names it
(quarantine_gate, security_regression_guard)."""
from __future__ import annotations

from boxmunge.commands.security_scan_core import ProjectScan
from boxmunge.compose_images import describe_image
from boxmunge.cve.policy import Disposition, FindingDisposition


def _fix_advice(f: FindingDisposition) -> str:
    if f.finding.fixed_version:
        return (f"fixed in {f.finding.fixed_version}: update the package, or rebuild on a "
                f"base image that has it")
    return "no fixed version is published yet: remove the package or wait for a fix"


def finding_lines(scan: ProjectScan, services: dict[str, list[str]],
                  disposition: Disposition) -> list[str]:
    lines: dict[tuple[str, str, str], str] = {}
    for decision in scan.decisions:
        service = ", ".join(services[decision.image_ref])
        for f in decision.findings:
            if f.disposition != disposition:
                continue
            key = (f.finding.cve_id, f.finding.package, decision.image_ref)
            kev = f", {f.exploited_label}: actively exploited" if f.exploited_by else ""
            lines.setdefault(key, (
                f"{f.finding.cve_id} ({f.effective_severity.value}{kev}) in "
                f"{f.finding.package} {f.finding.installed_version}, service {service} "
                f"({describe_image(decision.image_ref)}): {_fix_advice(f)}"))
    return list(lines.values())


def upcoming_lines(scan: ProjectScan, services: dict[str, list[str]]) -> list[str]:
    """Findings that meet the gate from 0.12 but not now: warned, never refused."""
    lines: dict[tuple[str, str, str], str] = {}
    for decision in scan.decisions:
        service = ", ".join(services[decision.image_ref])
        for f in decision.findings:
            if f.hardening_would_quarantine:
                lines.setdefault((f.finding.cve_id, f.finding.package, decision.image_ref), (
                    f"{f.finding.cve_id} ({f.effective_severity.value}) in {f.finding.package} "
                    f"{f.finding.installed_version}, service {service} "
                    f"({describe_image(decision.image_ref)})"))
    return list(lines.values())
