# SPDX-License-Identifier: Apache-2.0
"""Strict's fix grace: an available fix must be deployed within 7 days.

Under strict, a finding at the gate whose fix exists but is not running is
IGNORED_FIXED with ``fix_would_quarantine`` (policy.py): alerted, and
patched where autofix can. Not every such fix gets deployed (a patch can
fail, or the image cannot be patched), so the scan gives it a deadline:
``STRICT_FIX_WARN_BEFORE`` before it, one ``fix_deadline`` alert; at it
(``STRICT_FIX_GRACE`` after the scan that first found the finding so), the
finding becomes QUARANTINE (STILL_RUNNING_AT_RISK under
dangerously_disable_quarantine). Once the fix runs the finding is gone, its
entry is pruned, and the scan's own lift (security_enforce.clears_quarantine)
ends the quarantine.

A graced finding is one under strict, IGNORED_FIXED, at the gate without
its fix, not suppressed and not on a full KEV list (those quarantine
already), keyed per project by (CVE, package). One that stops being graced
is pruned when a complete scan no longer finds it so; if it comes back, its
grace starts again. Applying is idempotent, so any number of scans a day
(the KEV watch scans too) record one first sighting and send one warning.

policy.py stays pure: all state is here. File:
state/cve/fix_grace/<project>.json, {"entries": [{"cve_id", "package",
"first_seen", "warned_at"}]}, times as ISO 8601 UTC.
"""
from __future__ import annotations

import json
import os
from collections.abc import Sequence
from dataclasses import dataclass, replace
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

from boxmunge.cve.alerting import Alert, Hit, format_fix_deadline_alert
from boxmunge.cve.policy import Disposition, FindingDisposition, Posture, ProjectDecision
from boxmunge.cve.policy_explain import explain_fix_overdue
from boxmunge.fileutil import atomic_write_text
from boxmunge.fs_nofollow import read_text_nofollow_or_none
from boxmunge.paths import BoxPaths
from boxmunge.state import StateError

STRICT_FIX_GRACE = timedelta(days=7)
STRICT_FIX_WARN_BEFORE = timedelta(hours=48)
# How far ahead of the scan's clock a recorded first sighting may be before
# the record is refused: a future one would silently postpone the deadline.
_CLOCK_SKEW = timedelta(seconds=60)

Key = tuple[str, str]   # (CVE id, package)


@dataclass(frozen=True)
class GraceEntry:
    first_seen: datetime
    warned_at: datetime | None = None

    @property
    def deadline(self) -> datetime:
        return self.first_seen + STRICT_FIX_GRACE


def _aware(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{field} is {value!r}, not a time")
    when = datetime.fromisoformat(value)
    if when.tzinfo is None:
        raise ValueError(f"{field} {value!r} has no timezone")
    return when


def _parse(raw: str) -> dict[Key, GraceEntry]:
    entries: dict[Key, GraceEntry] = {}
    for item in json.loads(raw)["entries"]:
        cve, package = item["cve_id"], item["package"]
        if not isinstance(cve, str) or not cve or not isinstance(package, str):
            raise ValueError(f"an entry names no CVE and package: {item!r}")
        first_seen = _aware(item["first_seen"], "first_seen")
        warned = None if item["warned_at"] is None else _aware(item["warned_at"], "warned_at")
        if warned is not None and warned < first_seen:
            raise ValueError(f"{cve} in {package} was warned before it was first seen")
        entries[(cve, package)] = GraceEntry(first_seen=first_seen, warned_at=warned)
    return entries


class FixGrace:
    """One project's grace entries; ``save`` writes them back if changed."""

    def __init__(self, path: Path, entries: dict[Key, GraceEntry]) -> None:
        self.path = path
        self._entries = entries
        self._changed = False

    @classmethod
    def load(cls, paths: BoxPaths, project: str) -> FixGrace:
        """Raises StateError naming the file when it cannot be read."""
        path = paths.project_fix_grace(project)
        try:
            raw = read_text_nofollow_or_none(path)
            return cls(path, {} if raw is None else _parse(raw))
        except (OSError, ValueError, KeyError, TypeError) as e:
            raise StateError(f"cannot read the fix grace record {path}: {e!r}") from e

    def first_seen(self, key: Key) -> datetime | None:
        entry = self._entries.get(key)
        return None if entry is None else entry.first_seen

    def entry(self, key: Key) -> GraceEntry | None:
        return self._entries.get(key)

    def put(self, key: Key, entry: GraceEntry) -> None:
        if self._entries.get(key) != entry:
            self._entries[key] = entry
            self._changed = True

    def prune(self, keep: set[Key]) -> None:
        for key in [k for k in self._entries if k not in keep]:
            del self._entries[key]
            self._changed = True

    def save(self) -> None:
        """Write the entries atomically if anything changed; raises StateError."""
        if not self._changed or (not self._entries and not os.path.lexists(self.path)):
            return
        rows = [{"cve_id": cve, "package": pkg, "first_seen": e.first_seen.isoformat(),
                 "warned_at": None if e.warned_at is None else e.warned_at.isoformat()}
                for (cve, pkg), e in sorted(self._entries.items())]
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_text(self.path, json.dumps({"entries": rows}, indent=2) + "\n")
        except OSError as e:
            raise StateError(f"cannot write the fix grace record {self.path}: {e}") from e
        self._changed = False


def _graced(fd: FindingDisposition) -> bool:
    return (fd.disposition is Disposition.IGNORED_FIXED and fd.fix_would_quarantine
            and fd.suppression is None and not fd.full_kev)


def _key(fd: FindingDisposition) -> Key:
    return fd.finding.cve_id, fd.finding.package


def _overdue(fd: FindingDisposition, since: date, dangerously: bool) -> FindingDisposition:
    return replace(
        fd, fix_would_quarantine=False,
        disposition=(Disposition.STILL_RUNNING_AT_RISK if dangerously
                     else Disposition.QUARANTINE),
        explanation=explain_fix_overdue(fd.finding.fixed_version, since,
                                        STRICT_FIX_GRACE.days, dangerously_disabled=dangerously))


def _rejudged(decision: ProjectDecision, findings: tuple[FindingDisposition, ...]) -> ProjectDecision:
    return replace(
        decision, findings=findings,
        quarantine_required=any(f.disposition is Disposition.QUARANTINE for f in findings),
        at_risk_running=any(f.disposition is Disposition.STILL_RUNNING_AT_RISK
                            for f in findings))


def apply_fix_grace(
    decisions: Sequence[ProjectDecision], grace: FixGrace, now: datetime, posture: Posture,
    *, dangerously: bool, complete: bool,
) -> tuple[list[ProjectDecision], list[Alert]]:
    """``decisions`` with every overdue graced finding turned QUARANTINE (or
    STILL_RUNNING_AT_RISK), and the one ``fix_deadline`` alert for the
    findings whose warning fell due. Updates ``grace`` in place (the caller
    saves it, or not for an audit-only scan). An entry not seen graced is
    pruned only when ``complete``: an image a scan missed may still hold it."""
    seen: set[Key] = set()
    warn: list[tuple[Hit, date]] = []
    out: list[ProjectDecision] = []
    for decision in decisions:
        findings = []
        for fd in decision.findings:
            if posture is not Posture.STRICT or not _graced(fd):
                findings.append(fd)
                continue
            key = _key(fd)
            seen.add(key)
            entry = grace.entry(key) or GraceEntry(first_seen=now)
            if entry.first_seen > now + _CLOCK_SKEW:
                raise StateError(
                    f"the fix grace record {grace.path} says {key[0]} in {key[1]} was first "
                    f"seen at {entry.first_seen.isoformat()}, after this scan ({now.isoformat()})")
            if now >= entry.deadline:
                fd = _overdue(fd, entry.first_seen.date(), dangerously)
            elif entry.warned_at is None and now >= entry.deadline - STRICT_FIX_WARN_BEFORE:
                entry = replace(entry, warned_at=now)
                warn.append((Hit(fd, decision.image_ref), entry.deadline.date()))
            grace.put(key, entry)
            findings.append(fd)
        out.append(_rejudged(decision, tuple(findings)))
    if complete:
        grace.prune(seen)
    if not warn:
        return out, []
    return out, [format_fix_deadline_alert(decisions[0].project_name, warn,
                                           STRICT_FIX_GRACE.days, dangerously=dangerously)]


def graced_decisions(
    paths: BoxPaths, project: str, decisions: Sequence[ProjectDecision], *,
    posture: Posture, dangerously: bool, now: datetime, complete: bool,
    alerts: list[Alert] | None,
) -> list[ProjectDecision]:
    """``apply_fix_grace`` on the project's record: saved, and the warning
    appended to ``alerts``. ``alerts`` None (an audit-only scan: the resume
    re-scan, the deploy gate) applies the recorded deadlines but records and
    sends nothing. Raises StateError."""
    grace = FixGrace.load(paths, project)
    out, warned = apply_fix_grace(decisions, grace, now, posture,
                                  dangerously=dangerously, complete=complete)
    if alerts is not None:
        grace.save()
        alerts.extend(warned)
    return out
