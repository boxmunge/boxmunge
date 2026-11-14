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

from boxmunge.cve.kev import load_kev
from boxmunge.cve.policy import Disposition
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


def drop_kev_listed(
    paths: BoxPaths, cve_ids: list[str], *, positional: bool, log_project: str,
) -> list[str]:
    """Remove CVEs on the cached CISA KEV catalog, saying so loudly.

    A suppression never hides a KEV-listed CVE (audit B-07), so writing one
    would record a review that has no effect. A named CVE is refused; a
    --current batch skips the KEV entries and suppresses the rest. The
    cached IDs decide even when the catalog is stale (CVE-04): staleness
    only stops new KEV quarantines, and once the catalog is fresh again the
    suppression would not apply.
    """
    kev = load_kev(paths)
    stale = kev.stale_reason(utc_today())
    listed = [c for c in cve_ids if c in kev.cve_ids]
    for cve in listed:
        print(
            f"{'ERROR' if positional else 'NOTE'}: {cve} is on the CISA Known "
            f"Exploited Vulnerabilities catalog"
            + (f" (the cached catalog is stale: {stale})" if stale else "")
            + ". Suppressions do not apply to KEV-listed CVEs; fix or rebuild the image "
              "instead." + ("" if positional else " Skipping it."),
            file=sys.stderr,
        )
        log_error(
            "cve-suppress",
            f"Suppression rejected: {cve} is KEV-listed",
            paths, project=log_project,
            detail={"cve_id": cve, "reason": "kev_listed"},
        )
    remaining = [c for c in cve_ids if c not in listed]
    if not remaining and not positional:
        print(
            "ERROR: every current quarantine-level finding is KEV-listed; "
            "nothing to suppress.",
            file=sys.stderr,
        )
    return remaining
