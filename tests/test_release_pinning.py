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


# Top-of-block package declaration: starts at column 0, not a comment,
# and is one of:
#   name==version            (pip-compile's standard pinned form)
#   name @ url               (PEP 508 direct URL reference)
#   -e <url-or-path>          (editable install)
PKG_DECL_RE = re.compile(
    r"^(?:"
    r"[A-Za-z][\w.\-]*\s*==\s*\S+"   # name==version
    r"|[A-Za-z][\w.\-]*\s+@\s+\S+"    # name @ url
    r"|-e\s+\S+"                      # -e <ref>
    r")"
)


@pytest.mark.parametrize("path", REQUIREMENTS_FILES, ids=str)
def test_requirements_file_uses_hashes(path: Path) -> None:
    """Every pinned package must have at least one --hash entry between
    its declaration line and the start of the next package (or EOF).
    pip-compile emits packages without blank-line separation, so per-package
    coverage must be checked via the next-package-declaration boundary."""
    assert path.exists(), f"{path} should exist"
    lines = path.read_text().splitlines()

    # Find the file-line indices of every package declaration.
    pkg_indices = [i for i, line in enumerate(lines) if PKG_DECL_RE.match(line)]
    assert pkg_indices, f"{path} has no pinned package lines"

    # For each package, check that at least one --hash= appears in the
    # block from this declaration up to the next declaration (or EOF).
    hashless: list[str] = []
    for slot, start in enumerate(pkg_indices):
        end = pkg_indices[slot + 1] if slot + 1 < len(pkg_indices) else len(lines)
        block = "\n".join(lines[start:end])
        if not HASH_LINE_RE.search(block):
            # Name the package for the failure message — strip continuation
            # backslash and surrounding whitespace from the declaration line.
            decl = lines[start].rstrip("\\").strip()
            hashless.append(decl)

    assert not hashless, (
        f"{path}: {len(hashless)} package(s) missing --hash entries:\n  "
        + "\n  ".join(hashless)
        + "\nRun `make lock` to regenerate."
    )
