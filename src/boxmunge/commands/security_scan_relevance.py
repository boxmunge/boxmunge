# SPDX-License-Identifier: Apache-2.0
"""Relevance-gate diagnostics for a project scan.

The runtime relevance gate can only de-escalate. These helpers find the
cases where its inference may be exempting a project's OWN runtime, and log
them once per project scan. Split from security_scan_core.py.
"""
from __future__ import annotations

from datetime import date

from boxmunge.cve.policy import Disposition, Posture, ProjectDecision, evaluate_finding
from boxmunge.cve.relevance import ecosystem_for_package
from boxmunge.cve.scanner import PkgClass
from boxmunge.log import log_warning
from boxmunge.paths import BoxPaths


def gate_exempted_packages(
    decision: ProjectDecision, *, posture: Posture, dangerously: bool,
    suppressions: tuple, today: date, kev_lookup,
) -> set[str]:
    """OS runtime packages the relevance gate de-escalated with an EMPTY
    inferred runtime set.

    An empty inferred set is legitimate for a static site, but it's
    indistinguishable from "the image installs its runtime without a
    Trivy-visible lang-pkgs manifest" (apt-only Python, conda, PHP without
    composer.lock), in which case the gate exempts the project's OWN
    runtime. Only a disposition that actually DIFFERS with the gate off
    (runtimes=None) proves the gate was the cause: steps 8-11 also yield
    INFORMATIONAL. evaluate_finding is pure, so re-running it is safe.
    """
    out: set[str] = set()
    for disp in decision.findings:
        f = disp.finding
        if (
            disp.disposition != Disposition.INFORMATIONAL
            or f.pkg_class is not PkgClass.OS
            or ecosystem_for_package(f.package) is None
        ):
            continue
        but_for = evaluate_finding(
            f,
            posture=posture,
            hardening_penalty=disp.hardening_penalty,
            dangerously_disable_quarantine=dangerously,
            suppressions=suppressions,
            today=today,
            kev_lookup=kev_lookup,
            runtimes=None,
        )
        if but_for.disposition != disp.disposition:
            out.add(f.package)
    return out


def log_relevance_gaps(
    paths: BoxPaths, project: str,
    dropped_lang_types: set[str], empty_runtime_exempted: set[str],
) -> None:
    """Log the relevance-gate visibility warnings, once per project scan."""
    if dropped_lang_types:
        log_warning(
            "cve-scan",
            f"project {project}: unrecognised Trivy lang-pkgs type(s) "
            f"{sorted(dropped_lang_types)} were ignored during runtime "
            f"inference (they contribute no ecosystem); this can shrink the "
            f"inferred runtime set and make more findings look foreign — "
            f"extend relevance._TRIVY_TYPE_TO_ECOSYSTEM or declare "
            f"security.runtimes to compensate",
            paths, project=project,
            detail={"lang_types": sorted(dropped_lang_types)},
        )
    if empty_runtime_exempted:
        log_warning(
            "cve-scan",
            f"project {project}: relevance gate de-escalated OS package(s) "
            f"{sorted(empty_runtime_exempted)} because no runtime was "
            f"declared and none was inferred from a Trivy lang-pkgs "
            f"manifest — if this image installs its runtime without one "
            f"(apt-installed python3, conda, PHP without composer.lock), "
            f"the gate is exempting the project's OWN runtime; declare "
            f"security.runtimes to fix",
            paths, project=project,
            detail={"packages": sorted(empty_runtime_exempted)},
        )
