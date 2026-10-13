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
from boxmunge.cve.scan_state import read_scan_state
from boxmunge.log import log_error
from boxmunge.paths import BoxPaths

# Severity rank for ordering --current suppression output (Critical first).
# Mirrors policy._SEVERITY_RANK but uses the stored string values from
# scan_state.json so we don't have to round-trip through the enum here.
_SEVERITY_RANK = {
    "Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0,
}


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
    """
    state = read_scan_state(paths.project_scan_state(project))
    if not state:
        return []
    seen: dict[str, dict[str, Any]] = {}
    for decision in state.get("decisions", []) or []:
        for f in decision.get("findings", []) or []:
            if f.get("disposition") != Disposition.QUARANTINE.value:
                continue
            cve = f.get("cve_id")
            if not cve:
                continue
            existing = seen.get(cve)
            rank_new = _SEVERITY_RANK.get(f.get("effective_severity"), 0)
            rank_old = _SEVERITY_RANK.get(
                existing.get("effective_severity") if existing else None, 0,
            )
            if existing is None or rank_new > rank_old:
                seen[cve] = f
    return sorted(
        seen.values(),
        key=lambda f: (
            -_SEVERITY_RANK.get(f.get("effective_severity"), 0),
            f.get("cve_id", ""),
        ),
    )


def all_currently_quarantining_cves(paths: BoxPaths) -> list[str]:
    """Union of QUARANTINE-disposition CVE ids across every project on the box.

    Used by `--current --host` to suppress every CVE currently blocking any
    project in a single operation. Deduped by CVE id (a CVE quarantining
    multiple projects becomes one suppression). Order: severity rank
    descending, then CVE id ascending — matches per-project --current
    ordering for consistent operator UX.
    """
    if not paths.projects.exists():
        return []
    seen: dict[str, dict[str, Any]] = {}
    for proj_dir in sorted(paths.projects.iterdir()):
        if not proj_dir.is_dir() or not (proj_dir / "manifest.yml").exists():
            continue
        for f in current_quarantine_cves(paths, proj_dir.name):
            cve = f["cve_id"]
            existing = seen.get(cve)
            sev_new = f.get("effective_severity") or ""
            sev_old = (
                existing.get("effective_severity") or "" if existing else ""
            )
            rank_new = _SEVERITY_RANK.get(sev_new, 0)
            rank_old = _SEVERITY_RANK.get(sev_old, 0)
            if existing is None or rank_new > rank_old:
                seen[cve] = f
    return [
        f["cve_id"]
        for f in sorted(
            seen.values(),
            key=lambda f: (
                -_SEVERITY_RANK.get(f.get("effective_severity") or "", 0),
                f.get("cve_id", ""),
            ),
        )
    ]


def drop_kev_listed(
    paths: BoxPaths, cve_ids: list[str], *, positional: bool, log_project: str,
) -> list[str]:
    """Remove CVEs on the cached CISA KEV catalog, saying so loudly.

    A suppression never hides a KEV-listed CVE (audit B-07), so writing one
    would record a review that has no effect. A named CVE is refused; a
    --current batch skips the KEV entries and suppresses the rest.
    """
    kev = load_kev(paths)
    today = utc_today()
    listed = [c for c in cve_ids if kev.is_known_exploited(c, today=today)]
    for cve in listed:
        print(
            f"{'ERROR' if positional else 'NOTE'}: {cve} is on the CISA Known "
            f"Exploited Vulnerabilities catalog. Suppressions do not apply to "
            f"KEV-listed CVEs; fix or rebuild the image instead."
            + ("" if positional else " Skipping it."),
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
