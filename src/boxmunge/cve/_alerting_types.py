# SPDX-License-Identifier: Apache-2.0
"""Shared types for the CVE alerting subsystem.

Extracted into a tiny module so ``alerting.py`` and the formatter modules
can all import them without circular imports. Public consumers should keep
importing from ``boxmunge.cve.alerting``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, NamedTuple

from boxmunge.cve.policy import FindingDisposition

AlertKind = Literal[
    "quarantine",
    "still_running",
    "informational",
    "suppression_expired",
    "grace_heads_up",
    "kev_stale",
    "scan_failed",
    "breaker_held",
    "kev_fix_pending",
    "fix_available",
]


@dataclass(frozen=True)
class Alert:
    """A single notification to send. Pure data — no I/O."""

    kind: AlertKind
    title: str
    body: str
    priority: int  # 0 = normal, 1 = high (bypasses quiet hours)


class Hit(NamedTuple):
    """One finding's disposition and the image it was found in."""

    disposition: FindingDisposition
    image_ref: str
