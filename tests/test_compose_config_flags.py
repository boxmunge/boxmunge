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
