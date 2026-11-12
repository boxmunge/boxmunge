"""Regression tests for the release bundle (Makefile `bundle` target).

The v0.4.0 → v0.4.1 hotfix was caused by `caddy/` being added to the source
tree but missed in the Makefile's `cp -r` line. These tests pin down which
top-level directories MUST be present in the tarball so the same class of bug
fails CI noisily.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
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
    # canary/ ships in the release bundle so install.sh + the upgrade shim
    # can place it at /opt/boxmunge/canary, where `boxmunge self-test` looks
    # for it. Without this, self-test errors with "Canary project not found"
    # on every real install (regression caught during v0.5.4 fleet test).
    "canary",
    # system/ ships so install.sh can build + run the boxmunge-system
    # container (age/rclone isolation). Excluding it meant the container could
    # never be provisioned on a real install — only the host fallback ran.
    "system",
]

REQUIRED_BUNDLE_FILES = [
    "install.sh",
    "pyproject.toml",
    # The hash-pinned dependencies install.sh and the upgrade shim install;
    # MCP among them, so it survives every upgrade.
    "requirements-build.txt",
    "requirements-tui.txt",
    "requirements-mcp.txt",
]


def _read_version() -> str:
    with (REPO_ROOT / "pyproject.toml").open("rb") as f:
        return tomllib.load(f)["project"]["version"]


@pytest.fixture(scope="module")
def bundle_path(tmp_path_factory: pytest.TempPathFactory) -> Path:
    if shutil.which("make") is None:
        pytest.skip("make not available")
    # Built outside the checkout, so parallel test workers (and a developer's
    # own `make bundle`) never share dist/.stage.
    dist = tmp_path_factory.mktemp("dist")
    subprocess.run(
        ["make", "bundle", f"DIST={dist}"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
    )
    version = _read_version()
    path = dist / f"boxmunge-{version}.tar.gz"
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
        "boxmunge/sample-project/",
        "boxmunge/services/",
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


def test_install_guard_runs_its_detector_from_the_bundle(bundle_path: Path, tmp_path: Path):
    """bootstrap/unresolved-stage.sh runs the upgrade's detector from the
    bundle's own src/, before install.sh installs the package: both must ship,
    where the script looks, and the run must leave the bundle as it was."""
    with tarfile.open(bundle_path, "r:gz") as tf:
        tf.extractall(tmp_path, filter="data")
    bundle = tmp_path / "boxmunge"
    before = sorted(str(p) for p in bundle.rglob("*"))
    box = tmp_path / "box"
    staged = box / "projects" / "shop" / ".releases" / "prestage"
    staged.mkdir(parents=True)
    (box / "projects" / "shop" / "manifest.yml").write_text("project: shop\n")
    (box / "config").mkdir()
    (box / "config" / "version").write_text("0.11.6\n")
    # python3 is the interpreter running the tests: the host's may be too old.
    path = os.pathsep.join([str(Path(sys.executable).parent), os.environ["PATH"]])
    env = {"PATH": path, "FROM_UPGRADE_SHIM": "0", "BOXMUNGE_ROOT": str(box)}
    result = subprocess.run(
        ["bash", str(bundle / "bootstrap" / "unresolved-stage.sh")],
        env=env, capture_output=True, text=True, timeout=60, check=False,
    )
    assert result.returncode == 1, result.stderr
    assert "run `boxmunge-server legacy-stage shop`" in result.stderr
    assert sorted(str(p) for p in bundle.rglob("*")) == before
    staged.rmdir()
    result = subprocess.run(
        ["bash", str(bundle / "bootstrap" / "unresolved-stage.sh")],
        env=env, capture_output=True, text=True, timeout=60, check=False,
    )
    assert (result.returncode, result.stderr) == (0, "")
