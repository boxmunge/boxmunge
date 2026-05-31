"""Lint tests guarding the reproducible release pipeline.

This module accumulates a test per pinning discipline as the work
in docs/superpowers/plans/2026-05-31-supply-chain-release-pipeline.md
lands. Today: requirements file hash coverage. Later tasks will add
release-workflow install lint, GitHub Action SHA pinning lint,
Dependabot ecosystem-coverage lint, system-Dockerfile binary
SHA256-verification lint, and per-Dockerfile base-image digest-pin
lint. Every test asserts a single discipline so a regression on any
one surface fails loudly without obscuring the others.
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
    """Every pinned package must have at least one --hash entry in its
    own stanza. pip-compile emits one stanza per package, separated by
    blank lines, with the package pin on the first line and one or more
    --hash=sha256:... continuations after it."""
    assert path.exists(), f"{path} should exist"
    content = path.read_text()

    # Walk file as stanzas separated by blank lines. A stanza is "package
    # related" if any line in it is a top-level package pin (==, @ url, or
    # editable). Every such stanza must contain at least one hash.
    stanzas = re.split(r"\n\s*\n", content)
    package_pin_re = re.compile(
        r"^(?!#)\S[^\s]*"        # starts with a non-comment, non-blank token
        r"(==|\s@\s|^-e\s)",     # ==pin, @url ref, or editable install
        re.MULTILINE,
    )
    hashless: list[str] = []
    for stanza in stanzas:
        # Skip stanzas that are clearly not package declarations (comments,
        # pip flags like --index-url, etc.).
        if not package_pin_re.search(stanza):
            continue
        if not HASH_LINE_RE.search(stanza):
            # Capture the offending package name(s) for a useful failure.
            first_line = stanza.strip().splitlines()[0]
            hashless.append(first_line)

    assert not hashless, (
        f"{path}: {len(hashless)} package(s) missing --hash entries:\n  "
        + "\n  ".join(hashless)
        + "\nRun `make lock` to regenerate."
    )
