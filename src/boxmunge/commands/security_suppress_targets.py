# SPDX-License-Identifier: Apache-2.0
"""Shared helpers for `security suppress` / `unsuppress`: flags, paths, and
which CVEs a `--current` request resolves to.

Split from security_suppress.py to keep it under the file-size budget.
"""
from __future__ import annotations

import sys
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from boxmunge.commands.security_scan_inputs import ProjectScanError, load_project_meta
from boxmunge.cve.exploited import (
    ENISA_TAGS, ExploitedSource, is_full_kev, read_enisa_cache, read_vulncheck_cache,
)
from boxmunge.cve.kev import load_kev
from boxmunge.cve.policy import Disposition, Posture
from boxmunge.cve.policy_types import listing_label
from boxmunge.cve.scan_state import read_scan_state, stored_enum
from boxmunge.cve.scanner import Severity
from boxmunge.project_inventory import Inventory, classify, damaged_detail
from boxmunge.manifest import ManifestError
from boxmunge.fleet import PROJECT_INPUT_ERRORS, report_project_failure
from boxmunge.log import log_error
from boxmunge.paths import BoxPaths
from boxmunge.state import StateError

def _rank(finding: dict[str, Any]) -> int:
    """A stored finding's effective-severity rank (StateError if unreadable)."""
    return stored_enum(Severity, finding.get("effective_severity"), "effective_severity").rank


def project_suppressions_path(paths: BoxPaths, project: str) -> Path:
    return paths.project_dir(project) / "security" / "suppressions.yml"


def extract_flag(args: list[str], flag: str) -> str | None:
    """Pull a `--flag value` pair out of args. Returns the value or None."""
    if flag not in args:
        return None
    i = args.index(flag)
    if i + 1 >= len(args):
        return None
    return args[i + 1]


def utc_today() -> date:
    return datetime.now(timezone.utc).date()


def current_quarantine_cves(
    paths: BoxPaths, project: str,
) -> list[dict[str, Any]]:
    """Return findings (deduped by CVE id) currently at QUARANTINE disposition.

    Reads scan_state for the project. Returns an empty list if no scan has
    run or no findings are at QUARANTINE disposition. Within a duplicate
    CVE id, the highest-severity entry wins (a CVE elevated in one image
    keeps that severity in the output). Result ordered Critical → Unknown,
    then by CVE id for stable display.

    Raises StateError naming the file, and the scan that rewrites it, when
    the scan state cannot be read.
    """
    path = paths.project_scan_state(project)
    state = read_scan_state(path)
    if not state:
        return []
    seen: dict[str, dict[str, Any]] = {}
    try:
        for decision in state.get("decisions", []) or []:
            for f in decision.get("findings", []) or []:
                if f.get("disposition") != Disposition.QUARANTINE.value:
                    continue
                cve = f.get("cve_id")
                if not cve:
                    continue
                existing = seen.get(cve)
                if existing is None or _rank(f) > _rank(existing):
                    seen[cve] = f
        return sorted(seen.values(), key=lambda f: (-_rank(f), f.get("cve_id", "")))
    except StateError as e:
        raise StateError(f"{path}: {e}; `security scan {project}` rewrites it") from e


def all_currently_quarantining_cves(paths: BoxPaths) -> tuple[list[str], list[str]]:
    """Union of QUARANTINE-disposition CVE ids across every project on the
    box, and the projects left out because their state cannot be read
    (each reported on stderr and in the log).

    Used by `--current --host` to suppress every CVE currently blocking any
    project in a single operation. Deduped by CVE id (a CVE quarantining
    multiple projects becomes one suppression). Order: severity rank
    descending, then CVE id ascending — matches per-project --current
    ordering for consistent operator UX.
    """
    if not paths.projects.exists():
        return [], []
    seen: dict[str, dict[str, Any]] = {}
    left_out: list[str] = []
    for proj_dir in sorted(paths.projects.iterdir()):
        if not proj_dir.is_dir() or classify(proj_dir.name, paths) is Inventory.AWAITING:
            continue
        try:
            if classify(proj_dir.name, paths) is Inventory.DAMAGED:
                raise ManifestError(f"{proj_dir.name}: {damaged_detail(proj_dir.name)}")
            findings = current_quarantine_cves(paths, proj_dir.name)
        except PROJECT_INPUT_ERRORS as e:
            report_project_failure("cve-suppress", proj_dir.name, e, paths)
            print(f"  {proj_dir.name}'s quarantine-level findings, if any, are left "
                  f"out of this suppression.", file=sys.stderr)
            left_out.append(proj_dir.name)
            continue
        for f in findings:
            cve = f["cve_id"]
            existing = seen.get(cve)
            if existing is None or _rank(f) > _rank(existing):
                seen[cve] = f
    ordered = sorted(seen.values(), key=lambda f: (-_rank(f), f.get("cve_id", "")))
    return [f["cve_id"] for f in ordered], left_out


def _listings(paths: BoxPaths, cve_ids: list[str]) -> dict[str, frozenset[ExploitedSource]]:
    """{CVE: the known-exploited lists whose cached copy names it}. Cached
    IDs decide even when a list is stale (CVE-04): staleness only stops new
    quarantines, and once the list is fresh again the suppression would not
    apply. Raises StateError for a cache that cannot be read."""
    found: dict[str, set[ExploitedSource]] = {c: set() for c in cve_ids}
    for cve in load_kev(paths).cve_ids & set(cve_ids):
        found[cve].add(ExploitedSource.CISA)
    enisa = read_enisa_cache(paths)
    for cve, tags in (enisa[1] if enisa else {}).items():
        if cve in found:
            found[cve].update(ENISA_TAGS[t] for t in tags if t in ENISA_TAGS)
    vulncheck = read_vulncheck_cache(paths)
    for cve in (vulncheck[1] if vulncheck else []):
        if cve in found:
            found[cve].add(ExploitedSource.VULNCHECK)
    return {c: frozenset(s) for c, s in found.items()}


def _paranoid(paths: BoxPaths, project: str | None) -> bool | None:
    """Whether the project's posture is paranoid; None when no posture can
    say (host scope, or a project awaiting its first deploy). Raises
    ManifestError or ProjectScanError for a manifest that cannot be used."""
    if project is None or not paths.project_manifest(project).exists():
        return None
    return load_project_meta(paths, project).posture is Posture.PARANOID


def drop_kev_listed(
    paths: BoxPaths, cve_ids: list[str], *, positional: bool, log_project: str,
    project: str | None,
) -> list[str]:
    """Remove the CVEs a suppression would not apply to, saying so loudly.

    A suppression never hides a full-KEV CVE (listed by CISA or the EU,
    audit B-07), nor, on a paranoid project, one VulnCheck lists, so writing
    one would record a review that has no effect. A named CVE is refused; a
    --current batch skips those and suppresses the rest. A VulnCheck-only
    CVE where no posture can say (``project`` None is host scope) is
    suppressed with a note that it does not apply to a paranoid project.
    Returns [] (said) when the lists or the project's manifest cannot be read.
    """
    try:
        listings = _listings(paths, cve_ids)
        paranoid = _paranoid(paths, project)
    except (*PROJECT_INPUT_ERRORS, ProjectScanError) as e:
        print(f"ERROR: cannot tell which CVEs a suppression would apply to: {e}. Nothing "
              f"was suppressed.", file=sys.stderr)
        return []
    stale = load_kev(paths).stale_reason(utc_today())
    refused: list[str] = []
    for cve, sources in listings.items():
        if is_full_kev(sources):
            where = ("on the CISA Known Exploited Vulnerabilities catalog"
                     + (f" (the cached catalog is stale: {stale})" if stale else "")
                     if ExploitedSource.CISA in sources else "on the EU's known-exploited list")
            others = listing_label(sources - {ExploitedSource.CISA})
            why = (f"{cve} is {where}" + (f" (also listed by {others})" if others and
                                          ExploitedSource.CISA in sources else "")
                   + ". Suppressions do not apply to KEV-listed CVEs")
        elif sources and paranoid:
            why = (f"{cve} is listed as actively exploited by VulnCheck KEV, and {project} "
                   f"is paranoid. Under paranoid a suppression does not apply to a CVE "
                   f"VulnCheck lists")
        else:
            if sources:
                print(f"NOTE: {cve} is listed as actively exploited by VulnCheck KEV: this "
                      f"suppression will not apply to a paranoid project.", file=sys.stderr)
            continue
        refused.append(cve)
        print(f"{'ERROR' if positional else 'NOTE'}: {why}; fix or rebuild the image "
              f"instead." + ("" if positional else " Skipping it."), file=sys.stderr)
        log_error("cve-suppress", f"Suppression rejected: {cve} is KEV-listed "
                  f"({listing_label(sources)})", paths, project=log_project,
                  detail={"cve_id": cve, "reason": "kev_listed",
                          "listed_by": sorted(s.value for s in sources)})
    remaining = [c for c in cve_ids if c not in refused]
    if not remaining and not positional:
        print(
            "ERROR: every current quarantine-level finding is KEV-listed; "
            "nothing to suppress.",
            file=sys.stderr,
        )
    return remaining
