# SPDX-License-Identifier: Apache-2.0
"""Fleet blast-radius circuit breaker for CVE quarantines.

Base images are shared, so one CVE, one Trivy DB update, or one feed
change hits every project in the same scan run. Twice a single `perl-base`
CVE took most of a fleet down at once. The breaker looks at the fleet as a
whole before stopping anything: when one non-KEV CVE, or the run's total,
would newly quarantine at least ``trip_threshold(N)`` of the N projects
scanned, the new non-KEV quarantines are HELD — recorded, alerted once at
priority 1, and left running — until an operator applies them with
`boxmunge security scan --apply-held` or suppresses the CVE.

KEV-triggered quarantines are never held: active exploitation is exactly
when blast radius is acceptable. A bad KEV feed is caught earlier, by the
refresh sanity floor in kev.py.

Held state lives in ``state/cve-breaker.json`` so later scans — including
single-project scans, which see N=1 and can never trip — keep holding a
project whose quarantine-level CVEs are all held.

The decision is a pure function; only ``read_held`` / ``write_held`` do I/O.
"""
from __future__ import annotations

import json
import math
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from boxmunge.fileutil import atomic_write_text
from boxmunge.paths import BoxPaths

# Share of the scanned projects one CVE (or the run) may newly quarantine
# before the breaker trips. Never below 2: one project quarantining alone is
# the normal case and must never be held.
TRIP_SHARE = 0.34
MIN_TRIP = 2


class BreakerError(Exception):
    """The breaker state file is unreadable or malformed."""


@dataclass(frozen=True)
class Candidate:
    """A project this run would newly quarantine."""

    cves: frozenset[str]   # its quarantine-level CVEs
    kev: bool              # at least one of them is on CISA KEV


@dataclass(frozen=True)
class Verdict:
    apply: frozenset[str]                       # quarantine these now
    held: dict[str, frozenset[str]] = field(default_factory=dict)  # project → CVEs
    newly_held: frozenset[str] = frozenset()    # held for the first time this run
    tripped: bool = False                       # the thresholds tripped this run


def trip_threshold(projects_scanned: int) -> int:
    return max(MIN_TRIP, math.ceil(TRIP_SHARE * projects_scanned))


def decide(
    candidates: Mapping[str, Candidate], *,
    projects_scanned: int,
    already_held: Mapping[str, frozenset[str]],
) -> Verdict:
    """Split this run's new quarantines into apply-now and held.

    A non-KEV candidate whose CVEs are all already held stays held. The
    rest trip the breaker when any single CVE, or their total, reaches
    ``trip_threshold(projects_scanned)``; then every one of them is held.
    """
    held_cves = frozenset().union(*already_held.values()) if already_held else frozenset()
    apply = {p for p, c in candidates.items() if c.kev}
    still_held = {p: c.cves for p, c in candidates.items()
                  if not c.kev and c.cves <= held_cves}
    fresh = {p: c.cves for p, c in candidates.items()
             if not c.kev and p not in still_held}

    threshold = trip_threshold(projects_scanned)
    per_cve: dict[str, int] = {}
    for cves in fresh.values():
        for cve in cves:
            per_cve[cve] = per_cve.get(cve, 0) + 1
    tripped = bool(fresh) and (
        len(fresh) >= threshold or max(per_cve.values()) >= threshold
    )
    if tripped:
        held = {**still_held, **fresh}
        newly = frozenset(fresh)
    else:
        held = still_held
        apply |= set(fresh)
        newly = frozenset()
    return Verdict(apply=frozenset(apply), held=held, newly_held=newly, tripped=tripped)


def breaker_path(paths: BoxPaths) -> Path:
    return paths.state / "cve-breaker.json"


def read_held(paths: BoxPaths) -> dict[str, frozenset[str]]:
    """Held projects → CVEs. Missing file → nothing held. Corrupt → raise."""
    path = breaker_path(paths)
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
        held = data["held"]
        if not isinstance(held, dict):
            raise TypeError("'held' is not a mapping")
        return {str(p): frozenset(str(c) for c in cves) for p, cves in held.items()}
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise BreakerError(f"cannot read {path}: {e}") from e


def alert_pending(paths: BoxPaths) -> bool:
    """True when the held set changed but its alert was never delivered."""
    path = breaker_path(paths)
    if not path.exists():
        return False
    try:
        return json.loads(path.read_text()).get("alert_pending") is True
    except (OSError, ValueError, AttributeError) as e:
        raise BreakerError(f"cannot read {path}: {e}") from e


def write_held(
    paths: BoxPaths, held: Mapping[str, frozenset[str]], *, alert_pending: bool = False,
) -> None:
    """Persist the held set; an empty set removes the file.

    ``alert_pending`` marks a hold whose alert has not been delivered yet,
    so the next scan retries it.
    """
    path = breaker_path(paths)
    if not held:
        path.unlink(missing_ok=True)
        return
    doc = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "held": {p: sorted(cves) for p, cves in sorted(held.items())},
        "alert_pending": alert_pending,
    }
    atomic_write_text(path, json.dumps(doc, indent=2) + "\n")
