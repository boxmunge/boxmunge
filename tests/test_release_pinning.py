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
    REPO / "requirements-build.txt",
    REPO / "cli" / "requirements.txt",
    REPO / "cli" / "requirements-publish.txt",
    REPO / "services" / "version-check" / "requirements.txt",
    REPO / "tests" / "integration" / "userns" / "requirements-dind.txt",
]

HASH_LINE_RE = re.compile(r"--hash=sha256:[0-9a-f]{64}")


# Top-of-block package declaration: starts at column 0, not a comment,
# and is one of:
#   name==version            (pip-compile's standard pinned form)
#   name[extra]==version     (the same, with extras, e.g. pyjwt[crypto])
#   name @ url               (PEP 508 direct URL reference)
#   -e <url-or-path>          (editable install)
PKG_DECL_RE = re.compile(
    r"^(?:"
    r"[A-Za-z][\w.\-]*(?:\[[\w,.\-]+\])?\s*==\s*\S+"   # name[extra]==version
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


def test_a_package_with_extras_is_its_own_block() -> None:
    """Otherwise `pyjwt[crypto]==...` (from requirements-mcp.txt) would be
    read as part of the package above it and borrow that package's hashes."""
    assert PKG_DECL_RE.match("pyjwt[crypto]==2.13.0 \\")


WORKFLOWS = sorted((REPO / ".github" / "workflows").glob("*.yml"))


def test_workflows_discovered() -> None:
    names = {w.name for w in WORKFLOWS}
    assert {"release.yml", "ci.yml", "publish-cli.yml"} <= names, names


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda p: p.name)
def test_workflow_uses_hash_pinned_installs(workflow: Path) -> None:
    """Every workflow must install via --require-hashes from checked-in
    requirements files. Any bare `pip install <package>` without
    --require-hashes lets unhashed transitive deps in. This matters most in
    release.yml (cosign signing) and publish-cli.yml (PyPI publication), and
    ci.yml follows the same rule so a contributor's PR cannot introduce an
    unpinned install path that later gets copied into a release workflow."""
    content = workflow.read_text()

    install_lines = [
        line.strip() for line in content.splitlines()
        if "pip install" in line and not line.lstrip().startswith("#")
    ]

    for line in install_lines:
        # Permitted forms:
        #   pip install --require-hashes -r requirements.txt
        #   pip install -e <local path> --no-deps   (editable install of THIS
        #       repo's package; deps already installed via --require-hashes)
        is_hash_pinned = "--require-hashes" in line
        is_local_no_deps = "-e ." in line and "--no-deps" in line
        # A wheel this workflow just built, installed without resolving deps
        # (its deps come from a --require-hashes install on the line before).
        is_local_wheel = (
            "--no-deps" in line and re.search(r"\sdist/\S*\.whl\b", line) is not None
        )
        is_pip_upgrade = re.match(r"^pip install --upgrade pip(==.*)?\s*$", line)
        assert is_hash_pinned or is_local_no_deps or is_local_wheel or is_pip_upgrade, (
            f"{workflow.name} install line not hash-pinned: {line!r}"
        )


USES_RE = re.compile(r"^\s*-?\s*uses:\s*(.+?)\s*$", re.MULTILINE)
SHA_PIN_RE = re.compile(
    # owner/repo@<40-hex-sha>      (optional whitespace then # comment for legibility)
    r"^[^/\s]+/[^/@\s]+(?:/[^@\s]+)?@[0-9a-f]{40}(\s+#.*)?$"
)


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda p: p.name)
def test_workflow_actions_are_sha_pinned(workflow: Path) -> None:
    """Every `uses:` in every workflow must reference a 40-char commit SHA,
    not a tag like @v5. Tag-takeover on any pinned action would compromise
    the cosign release-signing trust root or the PyPI publishing identity."""
    matches = USES_RE.findall(workflow.read_text())
    assert matches, f"{workflow.name} has no `uses:` lines"
    bad = [m for m in matches if not SHA_PIN_RE.match(m)]
    assert not bad, (
        f"{workflow.name} has tag-pinned actions: {bad}. "
        "Resolve each tag to a commit SHA and replace inline."
    )


FULL_VERSION_COMMENT_RE = re.compile(r"@[0-9a-f]{40} # v\d+\.\d+\.\d+$")


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda p: p.name)
def test_workflow_action_pins_name_their_full_version(workflow: Path) -> None:
    """`# v5` beside a v5.0.1 SHA is left alone when Dependabot moves the SHA
    to v7.0.1, so the comment then names the wrong release. Dependabot keeps
    a full `# vX.Y.Z` comment in step with the SHA."""
    bad = [m for m in USES_RE.findall(workflow.read_text())
           if not FULL_VERSION_COMMENT_RE.search(m)]
    assert not bad, (
        f"{workflow.name}: pin comments must be the tag's full version, "
        f"`# vX.Y.Z` (git ls-remote --tags <repo> | grep <sha>): {bad}"
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


def _dependabot_updates() -> list[dict]:
    import yaml as _yaml
    return _yaml.safe_load((REPO / ".github" / "dependabot.yml").read_text())["updates"]


def test_dependabot_has_one_entry_per_ecosystem() -> None:
    """One entry per ecosystem (several `directories`) so its minor and patch
    group is one weekly pull request, not one per directory."""
    names = [u["package-ecosystem"] for u in _dependabot_updates()]
    assert sorted(names) == sorted(set(names)), names


@pytest.mark.parametrize("update", _dependabot_updates(), ids=lambda u: u["package-ecosystem"])
def test_dependabot_waits_and_groups_minor_and_patch(update: dict) -> None:
    """A release must age before it is proposed (a compromised upload is
    usually caught and yanked within days), and minor and patch updates
    arrive as one grouped pull request; majors stay separate."""
    assert update["cooldown"]["default-days"] >= 7, update
    groups = list(update["groups"].values())
    assert [g["update-types"] for g in groups] == [["minor", "patch"]], update


def test_system_dockerfile_verifies_external_binaries() -> None:
    """system/Dockerfile downloads age and rclone over the network. Each
    download must verify SHA256 against a baked-in ARG, one per supported
    architecture, before the binary enters the build, defending against
    TLS-trust-only fetches."""
    path = REPO / "system" / "Dockerfile"
    content = path.read_text()
    for tool in ("AGE", "RCLONE"):
        for arch in ("AMD64", "ARM64"):
            assert re.search(rf"^ARG {tool}_SHA256_{arch}=[0-9a-f]{{64}}\s*$", content, re.M), \
                f"system/Dockerfile must declare ARG {tool}_SHA256_{arch}=<64-hex>"
    assert 'echo "${age_sha256}  /tmp/age.tar.gz" | sha256sum -c -' in content, \
        "system/Dockerfile must verify the age tarball against its pinned SHA256"
    assert 'echo "${rclone_sha256}  /tmp/rclone.zip" | sha256sum -c -' in content, \
        "system/Dockerfile must verify the rclone zip against its pinned SHA256"


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
