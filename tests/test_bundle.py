"""Regression tests for the release bundle (Makefile `bundle` target).

The v0.4.0 → v0.4.1 hotfix was caused by `caddy/` being added to the source
tree but missed in the Makefile's `cp -r` line. These tests pin down which
top-level directories MUST be present in the tarball so the same class of bug
fails CI noisily.
"""

from __future__ import annotations

import shutil
import subprocess
import tarfile
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

REQUIRED_BUNDLE_DIRS = [
    "bootstrap",
    "src",
    "systemd",
    "config",
    "on-server",
    "scripts",
    "caddy",
]

REQUIRED_BUNDLE_FILES = [
    "install.sh",
    "pyproject.toml",
]


def _read_version() -> str:
    with (REPO_ROOT / "pyproject.toml").open("rb") as f:
        return tomllib.load(f)["project"]["version"]


@pytest.fixture(scope="module")
def bundle_path() -> Path:
    if shutil.which("make") is None:
        pytest.skip("make not available")
    subprocess.run(
        ["make", "bundle"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
    )
    version = _read_version()
    path = REPO_ROOT / "dist" / f"boxmunge-{version}.tar.gz"
    assert path.is_file(), f"bundle not built at {path}"
    return path


def _tarball_members(path: Path) -> set[str]:
    with tarfile.open(path, "r:gz") as tf:
        return set(tf.getnames())


def test_bundle_contains_required_top_level_dirs(bundle_path: Path):
    members = _tarball_members(bundle_path)
    for d in REQUIRED_BUNDLE_DIRS:
        prefix = f"boxmunge/{d}/"
        matched = [m for m in members if m.startswith(prefix)]
        assert matched, f"bundle missing required directory: {d}"


def test_bundle_contains_required_files(bundle_path: Path):
    members = _tarball_members(bundle_path)
    for f in REQUIRED_BUNDLE_FILES:
        assert f"boxmunge/{f}" in members, f"bundle missing required file: {f}"


def test_bundle_excludes_pycache(bundle_path: Path):
    members = _tarball_members(bundle_path)
    bad = [m for m in members if "__pycache__" in m or m.endswith(".pyc")]
    assert not bad, f"bundle contains pycache artifacts: {bad[:5]}"


def test_bundle_excludes_dev_only_dirs(bundle_path: Path):
    members = _tarball_members(bundle_path)
    forbidden_prefixes = [
        "boxmunge/tests/",
        "boxmunge/cli/",
        "boxmunge/canary/",
        "boxmunge/sample-project/",
        "boxmunge/services/",
        "boxmunge/system/",
        "boxmunge/build/",
        "boxmunge/dist/",
        "boxmunge/.git/",
        "boxmunge/.venv/",
        "boxmunge/docs/superpowers/",
    ]
    for prefix in forbidden_prefixes:
        leaked = [m for m in members if m.startswith(prefix)]
        assert not leaked, f"bundle leaked dev-only path {prefix}: {leaked[:3]}"


def test_caddy_maintenance_page_bundled(bundle_path: Path):
    """v0.4.0 hotfix regression: maintenance page must be in the bundle."""
    members = _tarball_members(bundle_path)
    assert "boxmunge/caddy/maintenance/index.html" in members, (
        "bundle missing caddy/maintenance/index.html (v0.4.1 hotfix regression)"
    )
