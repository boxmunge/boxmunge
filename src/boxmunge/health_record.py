# SPDX-License-Identifier: Apache-2.0
"""The health record's field types, checked where it is read.

The state reader proves a health record is a JSON object, not that its fields
are what the state machine does arithmetic and comparisons on. A record with
`consecutive_failures: "3"` is valid JSON and would raise a TypeError deep in
the machine. It is refused here instead, as a StateError naming the field.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from boxmunge.state import StateError, read_state

_STR = ("last_check", "status", "alerted_reason", "last_alert", "last_success",
        "failure_reason", "stopped_at")


def validate_health_record(state: dict[str, Any], path: Path) -> None:
    """Raise StateError naming the first field of ``state`` of the wrong type.
    Absent fields are fine: the machine has a default for each."""
    counter = state.get("consecutive_failures", 0)
    if not isinstance(counter, int) or isinstance(counter, bool) or counter < 0:
        raise StateError(f"Health state {path}: consecutive_failures must be a whole "
                         f"number of 0 or more, not {counter!r}")
    if not isinstance(state.get("alerted", False), bool):
        raise StateError(f"Health state {path}: alerted must be true or false, "
                         f"not {state['alerted']!r}")
    for field in _STR:
        if not isinstance(state.get(field, ""), str):
            raise StateError(f"Health state {path}: {field} must be text, "
                             f"not {state[field]!r}")


def read_health_record(path: Path) -> dict[str, Any]:
    """read_state, then validate_health_record. Raises StateError."""
    state = read_state(path)
    validate_health_record(state, path)
    return state
