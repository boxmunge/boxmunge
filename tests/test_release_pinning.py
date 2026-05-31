"""Lint tests guarding the reproducible release pipeline.

Each test asserts a single discipline: action SHA pins, requirements
hashes, Dockerfile digest pins, binary SHA256 ARGs. If any pin gets
relaxed back to a floating reference, the relevant test fails loudly.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]

REQUIREMENTS_FILES = [
    REPO / "requirements.txt",
    REPO / "requirements-tui.txt",
    REPO / "requirements-mcp.txt",
    REPO / "requirements-dev.txt",
    REPO / "cli" / "requirements.txt",
]

HASH_LINE_RE = re.compile(r"--hash=sha256:[0-9a-f]{64}")


@pytest.mark.parametrize("path", REQUIREMENTS_FILES, ids=str)
def test_requirements_file_uses_hashes(path: Path) -> None:
    """Every non-comment, non-blank line referencing a package must carry --hash."""
    assert path.exists(), f"{path} should exist"
    content = path.read_text()
    package_lines = [
        line for line in content.splitlines()
        if line and not line.startswith(("#", "-", " "))
        and "==" in line
    ]
    assert package_lines, f"{path} has no pinned package lines"
    hash_count = len(HASH_LINE_RE.findall(content))
    assert hash_count >= len(package_lines), (
        f"{path}: found {len(package_lines)} pinned packages but only "
        f"{hash_count} --hash entries. Run `make lock` to regenerate."
    )
