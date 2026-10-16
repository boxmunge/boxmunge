# SPDX-License-Identifier: Apache-2.0
"""The one timestamp format every action returns: ISO 8601, UTC, trailing Z.

Box state files hold timestamps in whatever form their writer chose
(+00:00 offsets, other zones, a Z suffix). Handlers pass each one through
utc_timestamp() on the way out, and result schemas declare TIMESTAMP so
invoke() refuses any that slipped past. Calendar dates (suppression
expiries) are not timestamps and stay YYYY-MM-DD.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from boxmunge.state import StateError

TIMESTAMP_PATTERN = r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z"
TIMESTAMP: dict[str, Any] = {
    "type": "string", "pattern": TIMESTAMP_PATTERN,
    "description": "ISO 8601 in UTC with a trailing Z.",
}
NULLABLE_TIMESTAMP: dict[str, Any] = {**TIMESTAMP, "type": ["string", "null"]}


def format_utc(moment: datetime) -> str:
    """*moment* in the API's format. A naive datetime is taken as UTC."""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def utc_timestamp(value: Any, where: str) -> str | None:
    """A stored timestamp in the API's format; None stays None. Anything
    else that is not an ISO 8601 timestamp is a StateError naming *where*
    (the file and field it came from)."""
    if value is None:
        return None
    if isinstance(value, str):
        text = value[:-1] + "+00:00" if value.endswith("Z") else value
        try:
            return format_utc(datetime.fromisoformat(text))
        except ValueError:
            pass
    raise StateError(f"{where} is not an ISO 8601 timestamp: {value!r}")
