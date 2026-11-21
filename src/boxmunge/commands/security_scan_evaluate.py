# SPDX-License-Identifier: Apache-2.0
"""Judging a project's scanned images under its policy.

``evaluate`` is the scan's own judgement. ``foresee`` re-judges the same
Trivy results with the suppression list as it will be when each suppression
in its warning window expires (cve.suppression_impact), through the same
policy and fix deadlines, so the advance warning says what the real policy
will do rather than a restatement of it. Both are pure apart from the fix
grace record, which ``foresee`` reads and never writes.
"""
from __future__ import annotations

from datetime import date, datetime

from boxmunge.commands.security_scan_inputs import ProjectHardening, ProjectMeta
from boxmunge.commands.security_scan_relevance import gate_exempted_packages, log_relevance_gaps
from boxmunge.cve.alerting import Alert
from boxmunge.cve.exploited import ExploitedIndex
from boxmunge.cve.fix_grace import graced_decisions
from boxmunge.cve.policy import Posture, ProjectDecision, evaluate_project
from boxmunge.cve.relevance import effective_runtimes, unrecognised_lang_types
from boxmunge.cve.scanner import ScanResult
from boxmunge.cve.suppression_impact import (
    Foreseen, foreseen_impact, in_warning_window, suppressions_at_expiry,
)
from boxmunge.cve.suppressions import Suppression
from boxmunge.paths import BoxPaths


def _judge(
    project: str, meta: ProjectMeta, profile: ProjectHardening,
    supps: tuple[Suppression, ...], results: list[ScanResult],
    exploited: ExploitedIndex, today: date,
) -> list[tuple[ScanResult, frozenset[str], ProjectDecision]]:
    """Each result with its effective runtimes and its decision."""
    out = []
    for sr in results:
        # `declared` was validated first; this only infers from lang_types.
        runtimes = effective_runtimes(sr.lang_types, declared=meta.declared_runtimes)
        out.append((sr, runtimes, evaluate_project(
            project, sr,
            posture=meta.posture,
            hardening_profile=profile.applied,
            upcoming=profile.upcoming,
            dangerously_disable_quarantine=meta.dangerously,
            suppressions=supps,
            today=today,
            exploited_lookup=exploited.lookup,
            runtimes=runtimes,
        )))
    return out


def evaluate(
    paths: BoxPaths, project: str, meta: ProjectMeta, profile: ProjectHardening,
    supps: tuple[Suppression, ...], results: list[ScanResult],
    exploited: ExploitedIndex, today: date, *, now: datetime, complete: bool,
    alerts: list[Alert] | None,
) -> list[ProjectDecision]:
    """One decision per scanned image, under the project's policy and strict's fix
    deadlines (cve.fix_grace). ``exploited``: the fresh sources (cve.exploited)."""
    posture, dangerously, declared = meta.posture, meta.dangerously, meta.declared_runtimes
    decisions: list[ProjectDecision] = []
    # Collected across every image but logged at most once per project scan.
    dropped_lang_types: set[str] = set()
    empty_runtime_exempted: set[str] = set()
    for sr, runtimes, decision in _judge(project, meta, profile, supps, results,
                                         exploited, today):
        if declared is None:
            # An unmapped Trivy lang-pkgs Type is dropped by infer_runtimes,
            # which biases toward OVER-exemption; surface it.
            dropped_lang_types |= unrecognised_lang_types(sr.lang_types)
        decisions.append(decision)
        if declared is None and not runtimes and posture in (
            Posture.BALANCED, Posture.STRICT,
        ):
            empty_runtime_exempted |= gate_exempted_packages(
                decision, posture=posture, dangerously=dangerously,
                suppressions=supps, today=today, exploited_lookup=exploited.lookup,
            )
    log_relevance_gaps(paths, project, dropped_lang_types, empty_runtime_exempted)
    return graced_decisions(paths, project, decisions, posture=posture, dangerously=dangerously,
                            now=now, complete=complete, alerts=alerts)


def foresee(
    paths: BoxPaths, project: str, meta: ProjectMeta, profile: ProjectHardening,
    supps: tuple[Suppression, ...], results: list[ScanResult],
    exploited: ExploitedIndex, today: date, *, now: datetime, complete: bool,
    current: list[ProjectDecision],
) -> tuple[Foreseen, ...]:
    """Each suppression in its warning window, with what its expiry will do
    here: the images re-judged with the suppressions that still apply on its
    ``until`` date. Everything else (KEV listings, fix deadlines, posture)
    is as of this scan. ``current`` is this scan's own decisions (a
    suppression they show not applying is reported so). Raises StateError
    like ``evaluate``."""
    window = [s for s in supps if in_warning_window(s, today=today, now=now)]
    out: list[Foreseen] = []
    for until in sorted({s.until for s in window}):
        judged = [d for _, _, d in _judge(project, meta, profile,
                                          suppressions_at_expiry(supps, until),
                                          results, exploited, today)]
        # alerts=None: the recorded deadlines apply, nothing is recorded.
        decisions = graced_decisions(paths, project, judged, posture=meta.posture,
                                     dangerously=meta.dangerously, now=now,
                                     complete=complete, alerts=None)
        out += [Foreseen(s, foreseen_impact(project, meta.posture.value, decisions,
                                            current, s.cve_id))
                for s in window if s.until == until]
    return tuple(out)
