# SPDX-License-Identifier: Apache-2.0
"""The init scaffold deploys as-is on the current server once a host is set."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from boxmunge_cli.bundle_cmd import run_bundle
from boxmunge_cli.init_cmd import run_init

REPO_SRC = Path(__file__).resolve().parents[2] / "src"


@pytest.fixture
def scaffold(tmp_path: Path) -> Path:
    root = tmp_path / "myapp"
    assert run_init(root, server="box.example.com", host="myapp.example.com") == 0
    return root


def test_scaffold_files(scaffold: Path) -> None:
    for rel in ["manifest.yml", "compose.yml", "Dockerfile", "site/index.html",
                "project.env", "boxmunge-scripts/smoke.sh"]:
        assert (scaffold / rel).is_file(), rel
    assert not (scaffold / ".env.example").exists()
    assert os.stat(scaffold / "boxmunge-scripts/smoke.sh").st_mode & 0o777 == 0o755


def test_compose_builds_from_files_that_exist(scaffold: Path) -> None:
    compose = yaml.safe_load((scaffold / "compose.yml").read_text())
    web = compose["services"]["web"]
    assert web["build"] == "."
    assert "env_file" not in web and "ports" not in web
    assert web["restart"] == "unless-stopped"
    dockerfile = (scaffold / "Dockerfile").read_text()
    for line in dockerfile.splitlines():
        if line.startswith("COPY "):
            assert (scaffold / line.split()[1]).exists(), line


def test_manifest_is_current_schema(scaffold: Path) -> None:
    manifest = yaml.safe_load((scaffold / "manifest.yml").read_text())
    assert manifest["schema_version"] == 3
    assert manifest["hosts"] == ["myapp.example.com"]
    web = manifest["services"]["web"]
    assert web["limits"]["memory"] and web["limits"]["cpus"]
    assert (scaffold / web["smoke"]).is_file()
    assert "writable:" in (scaffold / "manifest.yml").read_text()  # documented example


def test_scaffold_bundles_without_warnings(scaffold: Path, tmp_path: Path, capsys) -> None:
    out = tmp_path / "out"
    out.mkdir()
    assert run_bundle(str(scaffold), output=str(out)) == 0
    assert "WARN" not in capsys.readouterr().err


def test_placeholder_host_is_refused(tmp_path: Path, capsys) -> None:
    root = tmp_path / "myapp"
    assert run_init(root, server="box.example.com") == 0
    assert run_bundle(str(root), validate_only=True) == 1
    err = capsys.readouterr().err
    assert "change-me" in err and "hosts" in err


def test_init_rejects_a_bad_host(tmp_path: Path) -> None:
    assert run_init(tmp_path / "myapp", server="box.example.com", host="Bad Host") == 1


def test_server_validators_accept_the_scaffold(scaffold: Path, tmp_path: Path) -> None:
    if not (REPO_SRC / "boxmunge" / "manifest.py").is_file():
        pytest.skip("server source tree not present (sdist)")
    sys.path.insert(0, str(REPO_SRC))
    try:
        from boxmunge.compose_validate import validate_user_compose
        from boxmunge.manifest import validate_manifest
        from boxmunge.paths import BoxPaths
    finally:
        sys.path.remove(str(REPO_SRC))
    manifest = yaml.safe_load((scaffold / "manifest.yml").read_text())
    errors, warnings = validate_manifest(manifest, "myapp")
    assert errors == [] and warnings == []
    validate_user_compose(scaffold / "compose.yml", BoxPaths(tmp_path / "box"),
                          project_name="myapp", manifest_services=manifest["services"])


def _run_smoke(scaffold: Path, tmp_path: Path, tools: dict[str, str], shell: str):
    bin_dir = tmp_path / "smokebin"
    bin_dir.mkdir()
    for name, body in tools.items():
        (bin_dir / name).write_text(f"#!/bin/sh\n{body}\n")
        (bin_dir / name).chmod(0o755)
    return subprocess.run([shell, str(scaffold / "boxmunge-scripts/smoke.sh"), "web"],
                          capture_output=True, text=True, env={"PATH": str(bin_dir)})


def _shells() -> list[str]:
    return [s for s in (shutil.which("dash"), "/bin/sh") if s]


@pytest.mark.parametrize("shell", _shells())
def test_smoke_parses_as_posix_sh(scaffold: Path, shell: str) -> None:
    text = (scaffold / "boxmunge-scripts/smoke.sh").read_text()
    assert text.startswith("#!/bin/sh\n")
    assert "pipefail" not in text and "[[" not in text
    subprocess.run([shell, "-n", str(scaffold / "boxmunge-scripts/smoke.sh")], check=True)


@pytest.mark.parametrize("shell", _shells())
def test_smoke_reports_one_line_and_never_critical(scaffold: Path, tmp_path: Path,
                                                   shell: str) -> None:
    down = _run_smoke(scaffold, tmp_path, {"wget": "exit 4"}, shell)
    assert down.returncode == 1
    assert len([ln for ln in down.stderr.splitlines() if ln.strip()]) == 1


@pytest.mark.parametrize("shell", _shells())
def test_smoke_without_probe_tools_is_a_warning(scaffold: Path, tmp_path: Path,
                                                shell: str) -> None:
    result = _run_smoke(scaffold, tmp_path, {}, shell)
    assert result.returncode == 1
    assert "no wget, curl or python3" in result.stderr


@pytest.mark.parametrize("shell", _shells())
def test_smoke_passes_when_the_service_answers(scaffold: Path, tmp_path: Path,
                                               shell: str) -> None:
    result = _run_smoke(scaffold, tmp_path, {"wget": "exit 0"}, shell)
    assert result.returncode == 0 and result.stderr == ""
