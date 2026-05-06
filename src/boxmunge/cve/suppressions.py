# SPDX-License-Identifier: Apache-2.0
"""Per-project CVE suppression file I/O.

A suppression is an operator's signed-off declaration that a CVE present in
the project's image has been reviewed and judged not exploitable in the
deployed config. The suppression skips the CVE-quarantine policy gate until
its `until` date, at which point the entry expires and the operator must
revisit.

The file lives in the project's deploy bundle so the disposition trail
travels with the project (audit history, not platform state):

    <project_root>/security/suppressions.yml

This module is pure I/O + validation. Policy decisions (does this active
suppression cover this finding?) belong in the layer that joins scanner.py
and this module.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any

import yaml

from boxmunge.fileutil import atomic_write_text

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_ISO_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

_REQUIRED_FIELDS = ("cve", "until", "reason", "reviewed_by", "added")


class SuppressionsError(Exception):
    """Suppression file is malformed or schema-invalid."""


@dataclass(frozen=True)
class Suppression:
    """A single CVE suppression entry."""

    cve_id: str
    until: date
    reason: str
    reviewed_by: str
    added: date

    def is_active(self, *, today: date) -> bool:
        """Active iff today < until.

        A suppression with `until: 2026-08-01` is active through 2026-07-31
        and expired on 2026-08-01 onwards. This matches the conventional
        "X expires on date Y" reading: Y is the first day it does NOT apply.
        """
        return today < self.until


# ---------- parsing helpers ----------


def _coerce_date(value: Any, field: str, index: int) -> date:
    """Accept a date instance OR an ISO YYYY-MM-DD string. Reject anything else.

    PyYAML parses bare YYYY-MM-DD into a date object; quoted strings stay
    strings. Both must validate to ISO; we reject datetimes (granularity is
    the day, per spec) and any other shape.
    """
    # datetime is a subclass of date — check it first so a YAML datetime
    # ('2026-08-01T00:00:00') is rejected before the date branch swallows it.
    if isinstance(value, datetime):
        raise SuppressionsError(
            f"entry {index}: '{field}' must be a date (YYYY-MM-DD), not a "
            f"datetime: {value!r}"
        )
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        if not _ISO_DATE_RE.match(value):
            raise SuppressionsError(
                f"entry {index}: '{field}' must be ISO 8601 YYYY-MM-DD, "
                f"got {value!r}"
            )
        try:
            return date.fromisoformat(value)
        except ValueError as e:
            raise SuppressionsError(
                f"entry {index}: '{field}' is not a valid date: {value!r} ({e})"
            ) from e
    raise SuppressionsError(
        f"entry {index}: '{field}' must be a date string (YYYY-MM-DD), "
        f"got {type(value).__name__}"
    )


def _parse_entry(raw: Any, index: int) -> Suppression:
    """Parse and validate a single entry. Raises SuppressionsError on failure."""
    if not isinstance(raw, dict):
        raise SuppressionsError(
            f"entry {index} must be a mapping, got {type(raw).__name__}"
        )

    missing = [f for f in _REQUIRED_FIELDS if f not in raw]
    if missing:
        raise SuppressionsError(
            f"entry {index} is missing required field(s): {', '.join(missing)}"
        )

    cve_value = raw["cve"]
    if not isinstance(cve_value, str) or not _CVE_RE.match(cve_value):
        raise SuppressionsError(
            f"entry {index}: 'cve' must match pattern CVE-YYYY-NNNN+, "
            f"got {cve_value!r}"
        )

    reason = raw["reason"]
    if not isinstance(reason, str) or not reason.strip():
        raise SuppressionsError(
            f"entry {index}: 'reason' must be a non-empty string"
        )

    reviewed_by = raw["reviewed_by"]
    if not isinstance(reviewed_by, str) or not reviewed_by.strip():
        raise SuppressionsError(
            f"entry {index}: 'reviewed_by' must be a non-empty string"
        )

    until = _coerce_date(raw["until"], "until", index)
    added = _coerce_date(raw["added"], "added", index)

    return Suppression(
        cve_id=cve_value,
        until=until,
        reason=reason.strip(),
        reviewed_by=reviewed_by.strip(),
        added=added,
    )


# ---------- public API ----------


def load_suppressions(path: Path) -> tuple[Suppression, ...]:
    """Read and parse the suppressions file.

    Missing file → empty tuple (not an error: no suppressions yet is the
    common case for new projects).
    Malformed YAML / schema violation / bad CVE / bad date → SuppressionsError
    with the offending entry index or field named in the message.
    Returns suppressions sorted by cve_id ascending for stable downstream order.
    """
    if not path.exists():
        return ()

    try:
        text = path.read_text()
    except OSError as e:
        raise SuppressionsError(
            f"Cannot read suppressions file {path}: {e}"
        ) from e

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise SuppressionsError(
            f"Cannot parse YAML in {path}: {e}"
        ) from e

    if data is None:
        # Empty file. Treat as zero suppressions — but our spec is that
        # the schema requires the top-level key. Be strict.
        raise SuppressionsError(
            f"{path} is empty; expected a 'suppressions:' top-level mapping. "
            f"For zero suppressions write 'suppressions: []'."
        )

    if not isinstance(data, dict):
        raise SuppressionsError(
            f"{path} must be a YAML mapping at the top level, "
            f"got {type(data).__name__}"
        )

    if "suppressions" not in data:
        raise SuppressionsError(
            f"{path} is missing the required top-level key 'suppressions'"
        )

    raw_list = data["suppressions"]
    if not isinstance(raw_list, list):
        raise SuppressionsError(
            f"{path}: 'suppressions' must be a list, "
            f"got {type(raw_list).__name__}"
        )

    parsed = tuple(_parse_entry(raw, i) for i, raw in enumerate(raw_list))
    return tuple(sorted(parsed, key=lambda s: s.cve_id))


def active_suppressions(
    suppressions: tuple[Suppression, ...], *, today: date,
) -> tuple[Suppression, ...]:
    """Filter to entries still active on `today`. Order preserved."""
    return tuple(s for s in suppressions if s.is_active(today=today))


def expired_suppressions(
    suppressions: tuple[Suppression, ...], *, today: date,
) -> tuple[Suppression, ...]:
    """Inverse of active_suppressions. Order preserved."""
    return tuple(s for s in suppressions if not s.is_active(today=today))


def find_active_suppression(
    suppressions: tuple[Suppression, ...], cve_id: str, *, today: date,
) -> Suppression | None:
    """Return the active suppression for `cve_id`, or None."""
    for s in suppressions:
        if s.cve_id == cve_id and s.is_active(today=today):
            return s
    return None


def _serialise(suppressions: tuple[Suppression, ...]) -> str:
    """Render a tuple of Suppression to the canonical YAML representation."""
    payload = {
        "suppressions": [
            {
                "cve": s.cve_id,
                "until": s.until.isoformat(),
                "reason": s.reason,
                "reviewed_by": s.reviewed_by,
                "added": s.added.isoformat(),
            }
            for s in suppressions
        ]
    }
    # sort_keys=False to keep the schema field order stable and readable.
    return yaml.safe_dump(payload, sort_keys=False, default_flow_style=False)


def add_suppression(
    path: Path,
    *,
    cve_id: str,
    until: date,
    reason: str,
    reviewed_by: str,
    today: date,
) -> Suppression:
    """Append a new suppression to the file. `added` is set to `today`.

    - Missing file → created (with parent dirs) at mode 0o644.
    - Duplicate cve_id (active OR expired) → SuppressionsError. Caller must
      remove first; we do not silently overwrite audit-trail entries.
    - Validates inputs the same way load_suppressions does.
    - Atomic write to avoid torn-file artifacts on crash.
    """
    if not isinstance(cve_id, str) or not _CVE_RE.match(cve_id):
        raise SuppressionsError(
            f"'cve_id' must match CVE-YYYY-NNNN+, got {cve_id!r}"
        )
    if not isinstance(reason, str) or not reason.strip():
        raise SuppressionsError("'reason' must be a non-empty string")
    if not isinstance(reviewed_by, str) or not reviewed_by.strip():
        raise SuppressionsError("'reviewed_by' must be a non-empty string")
    if not isinstance(until, date) or not isinstance(today, date):
        raise SuppressionsError("'until' and 'today' must be date instances")

    existing = load_suppressions(path)
    if any(s.cve_id == cve_id for s in existing):
        raise SuppressionsError(
            f"A suppression for {cve_id} already exists. "
            f"Call remove_suppression first if you intend to replace it "
            f"(this protects audit-trail entries from silent overwrite)."
        )

    new_entry = Suppression(
        cve_id=cve_id,
        until=until,
        reason=reason.strip(),
        reviewed_by=reviewed_by.strip(),
        added=today,
    )
    merged = tuple(sorted(existing + (new_entry,), key=lambda s: s.cve_id))
    atomic_write_text(path, _serialise(merged), mode=0o644)
    return new_entry


def remove_suppression(path: Path, cve_id: str) -> Suppression:
    """Remove the suppression entry for `cve_id`. Returns the removed entry.

    - Missing file or unknown cve_id → SuppressionsError.
    - Atomic write.
    - Empty resulting list is written as `{"suppressions": []}` so the
      file remains as a deliberate "no suppressions" statement.
    """
    if not path.exists():
        raise SuppressionsError(
            f"Cannot remove {cve_id}: suppressions file does not exist at {path}"
        )

    existing = load_suppressions(path)
    target = next((s for s in existing if s.cve_id == cve_id), None)
    if target is None:
        raise SuppressionsError(
            f"No suppression entry for {cve_id} in {path}"
        )

    remaining = tuple(s for s in existing if s.cve_id != cve_id)
    atomic_write_text(path, _serialise(remaining), mode=0o644)
    return target
