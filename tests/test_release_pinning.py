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


def test_release_workflow_uses_hash_pinned_installs() -> None:
    """The release workflow must install via --require-hashes from the
    checked-in requirements files. Any bare `pip install <package>` without
    --require-hashes lets unhashed transitive deps in."""
    workflow = REPO / ".github" / "workflows" / "release.yml"
    content = workflow.read_text()

    install_lines = [
        line.strip() for line in content.splitlines()
        if "pip install" in line and not line.lstrip().startswith("#")
    ]
    assert install_lines, "release.yml has no pip install lines"

    for line in install_lines:
        # Permitted forms:
        #   pip install --require-hashes -r requirements.txt
        #   pip install -e . --no-deps        (editable install of THIS package,
        #                                     deps already installed via --require-hashes)
        is_hash_pinned = "--require-hashes" in line
        is_local_no_deps = "-e ." in line and "--no-deps" in line
        is_pip_upgrade = re.match(r"^pip install --upgrade pip(==.*)?\s*$", line)
        assert is_hash_pinned or is_local_no_deps or is_pip_upgrade, (
            f"release.yml install line not hash-pinned: {line!r}"
        )


USES_RE = re.compile(r"^\s*-?\s*uses:\s*(.+?)\s*$", re.MULTILINE)
SHA_PIN_RE = re.compile(
    # owner/repo@<40-hex-sha>      (optional whitespace then # comment for legibility)
    r"^[^/\s]+/[^/@\s]+(?:/[^@\s]+)?@[0-9a-f]{40}(\s+#.*)?$"
)


def test_release_workflow_actions_are_sha_pinned() -> None:
    """Every `uses:` in release.yml must reference a 40-char commit SHA,
    not a tag like @v5. Tag-takeover on any pinned action would compromise
    the cosign release-signing trust root."""
    workflow = REPO / ".github" / "workflows" / "release.yml"
    matches = USES_RE.findall(workflow.read_text())
    assert matches, "release.yml has no `uses:` lines"
    bad = [m for m in matches if not SHA_PIN_RE.match(m)]
    assert not bad, (
        f"release.yml has tag-pinned actions: {bad}. "
        "Resolve each tag to a commit SHA and replace inline."
    )


def test_dependabot_covers_pinned_ecosystems() -> None:
    """Dependabot must be configured for every ecosystem we pin in this
    work: pip (requirements files), github-actions (release.yml), and
    docker (base image digests). Without dependabot, the SHA pins become
    stale-prone manual toil."""
    import yaml as _yaml  # PyYAML is already a project dep

    path = REPO / ".github" / "dependabot.yml"
    assert path.exists(), ".github/dependabot.yml must exist"
    cfg = _yaml.safe_load(path.read_text())
    assert cfg.get("version") == 2, "dependabot.yml must be version 2"

    ecosystems = {u["package-ecosystem"] for u in cfg.get("updates", [])}
    expected = {"pip", "github-actions", "docker"}
    missing = expected - ecosystems
    assert not missing, f"dependabot.yml missing ecosystems: {sorted(missing)}"


def test_system_dockerfile_verifies_external_binaries() -> None:
    """system/Dockerfile downloads age and rclone over the network. Each
    download must verify SHA256 against a baked-in ARG before the binary
    enters the build, defending against TLS-trust-only fetches."""
    path = REPO / "system" / "Dockerfile"
    content = path.read_text()
    assert re.search(r"^ARG AGE_SHA256=[0-9a-f]{64}\s*$", content, re.MULTILINE), \
        "system/Dockerfile must declare ARG AGE_SHA256=<64-hex>"
    assert re.search(r"^ARG RCLONE_SHA256=[0-9a-f]{64}\s*$", content, re.MULTILINE), \
        "system/Dockerfile must declare ARG RCLONE_SHA256=<64-hex>"
    assert "echo \"${AGE_SHA256}" in content or "${AGE_SHA256}  " in content, \
        "system/Dockerfile must verify age tarball against AGE_SHA256"
    assert "echo \"${RCLONE_SHA256}" in content or "${RCLONE_SHA256}  " in content, \
        "system/Dockerfile must verify rclone zip against RCLONE_SHA256"


DOCKERFILES_REQUIRING_DIGEST_PIN = [
    REPO / "system" / "Dockerfile",
    REPO / "canary" / "Dockerfile",
    REPO / "services" / "version-check" / "Dockerfile",
    REPO / "sample-project" / "frontend" / "Dockerfile",
    REPO / "sample-project" / "backend" / "Dockerfile",
    REPO / "tests" / "integration" / "fixture_project" / "Dockerfile",
]

FROM_LINE_RE = re.compile(r"^FROM\s+(\S+)", re.MULTILINE | re.IGNORECASE)


@pytest.mark.parametrize("path", DOCKERFILES_REQUIRING_DIGEST_PIN, ids=str)
def test_dockerfile_base_image_is_digest_pinned(path: Path) -> None:
    """Every internal Dockerfile must pin its base image by digest, not by
    floating tag. Tag-takeover on a base image silently changes what we ship."""
    assert path.exists(), f"{path} should exist"
    for ref in FROM_LINE_RE.findall(path.read_text()):
        if ref in ("scratch",) or ref.startswith("$"):
            continue
        assert "@sha256:" in ref, (
            f"{path}: FROM {ref!r} is not digest-pinned. Resolve the digest "
            f"and use FROM <image>:<tag>@sha256:<digest>."
        )
