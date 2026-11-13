# SPDX-License-Identifier: Apache-2.0
"""The upgrade shim and boxmunge.upgrade_notes state the same notes limits.

release-lint (through upgrade_notes) refuses to publish notes a box would
refuse to read, and the shim's `guide` and `check` refuse releases from
before the first notes, so the two copies must agree: the first release
with upgrade notes and the readiness check, and the largest notes document.
"""
from __future__ import annotations

import re
from pathlib import Path

from boxmunge import upgrade_notes

CHECK_SH = Path(__file__).resolve().parents[1] / "scripts" / "boxmunge-upgrade.d" / "check.sh"


def _shim_value(name: str) -> str:
    found = re.findall(rf'^{name}="?([^"\n]*)"?$', CHECK_SH.read_text(), re.M)
    assert len(found) == 1, f"{CHECK_SH} must set {name} once, at the top level"
    return found[0]


def test_first_notes_release_agrees() -> None:
    assert _shim_value("FIRST_NOTES_RELEASE") == upgrade_notes.FIRST_NOTES_RELEASE


def test_notes_max_bytes_agrees() -> None:
    assert int(_shim_value("NOTES_MAX_BYTES")) == upgrade_notes.MAX_BYTES
