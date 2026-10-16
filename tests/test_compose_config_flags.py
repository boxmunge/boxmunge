# SPDX-License-Identifier: Apache-2.0
"""docker.compose_config must not read service env files.

Validation runs on bundles in an extraction directory, where on-box files
such as secrets.env are absent; reading them would refuse every deploy of a
project whose compose names them. Validation never needs their values.
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

from boxmunge import docker

# Captured at import, before tests/conftest.py swaps in its no-Docker stub.
_REAL_COMPOSE_CONFIG = docker.compose_config


def test_compose_config_skips_service_env_file_resolution(tmp_path: Path) -> None:
    seen: list[list[str]] = []

    def fake_run(cmd, **_kw):
        seen.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="{}", stderr="")

    with patch.object(docker, "_run", side_effect=fake_run):
        _REAL_COMPOSE_CONFIG(tmp_path, project_name="myapp")
    assert seen and "--no-env-resolution" in seen[0]


def test_missing_env_file_exists_only_during_resolution(tmp_path: Path) -> None:
    from boxmunge import compose_resolve

    (tmp_path / "compose.yml").write_text(
        "services:\n  web:\n    image: nginx\n    env_file: [project.env, secrets.env]\n"
    )
    (tmp_path / "project.env").write_text("MODE=prod\n")
    during: list[bool] = []

    def fake_config(project_dir, compose_files=None, *, project_name, **_kw):
        during.append((project_dir / "secrets.env").exists())
        return '{"services": {"web": {"image": "nginx"}}}'

    with patch.object(compose_resolve.docker, "compose_config", side_effect=fake_config):
        compose_resolve.resolve_compose_config(tmp_path / "compose.yml", "myapp")
    assert during == [True]
    assert not (tmp_path / "secrets.env").exists()
    assert (tmp_path / "project.env").read_text() == "MODE=prod\n"
