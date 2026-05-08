# SPDX-License-Identifier: Apache-2.0
"""Shared types for the CVE alerting subsystem.

Extracted into a tiny module so ``alerting.py`` and
``_alerting_formatters.py`` can both import ``Alert`` / ``AlertKind``
without circular imports. Public consumers should keep importing from
``boxmunge.cve.alerting``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


AlertKind = Literal[
    "quarantine",
    "still_running",
    "informational",
    "suppression_expired",
    "grace_heads_up",
]


@dataclass(frozen=True)
class Alert:
    """A single notification to send. Pure data — no I/O."""

    kind: AlertKind
    title: str
    body: str
    priority: int  # 0 = normal, 1 = high (bypasses quiet hours)
