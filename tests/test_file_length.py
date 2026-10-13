# SPDX-License-Identifier: Apache-2.0
"""Enforce the source-file size rule from CONTRIBUTING.md.

Source files should stay under 500 lines; above 650 they must be split.
This test enforces the hard limit so the rule does not rely on reviewers
noticing. Tests are exempt: a long table-driven test file is not a design
smell the way a long module is.
"""
from __future__ import annotations

from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
HARD_LIMIT = 650
SOURCE_ROOTS = [REPO / "src" / "boxmunge", REPO / "cli" / "src" / "boxmunge_cli"]

SOURCE_FILES = sorted(
    path for root in SOURCE_ROOTS for path in root.rglob("*.py")
    if "__pycache__" not in path.parts
)


def test_source_roots_are_populated() -> None:
    assert len(SOURCE_FILES) > 50, "source discovery found too few files; check SOURCE_ROOTS"


@pytest.mark.parametrize("path", SOURCE_FILES, ids=lambda p: str(p.relative_to(REPO)))
def test_source_file_under_hard_limit(path: Path) -> None:
    lines = len(path.read_text().splitlines())
    assert lines <= HARD_LIMIT, (
        f"{path.relative_to(REPO)} has {lines} lines (hard limit {HARD_LIMIT}). "
        "Split it along a natural seam; see CONTRIBUTING.md."
    )
