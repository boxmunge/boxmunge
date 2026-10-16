# SPDX-License-Identifier: Apache-2.0
"""data adopt on a real daemon: the copy is complete and Compose adopts it."""
from __future__ import annotations

import subprocess
import uuid

import pytest
import yaml

from boxmunge.commands import data_cmd
from tests.integration.conftest import skip_no_docker
from tests.integration.docker_images import BUSYBOX, ensure_busybox

pytestmark = [pytest.mark.integration, skip_no_docker, pytest.mark.usefixtures("helper_image")]


def test_adopt_then_compose_up_uses_the_copy(int_paths, monkeypatch) -> None:
    ensure_busybox()
    name = f"bmad{uuid.uuid4().hex[:8]}"
    project = int_paths.project_dir(name)
    project.mkdir(parents=True)
    compose = {"services": {"db": {"image": BUSYBOX, "command": ["sleep", "600"],
                                   "network_mode": "none", "volumes": ["/data"]}}}
    (project / "compose.yml").write_text(yaml.safe_dump(compose))
    up = ["docker", "compose", "-p", name, "-f", "compose.yml"]
    # The start checks re-validate a real boxmunge project (covered by
    # test_root_compose_call_sites); this plain compose project is started
    # again with docker start, as start_containers_checked does.
    monkeypatch.setattr(data_cmd, "check_containers_start", lambda *a, **kw: None)
    restarted = []
    monkeypatch.setattr(data_cmd, "start_containers_checked", lambda paths, p, names, **kw: (
        restarted.extend(names),
        subprocess.run(["docker", "start", *names], check=True, capture_output=True)))
    anonymous: list[str] = []
    try:
        subprocess.run([*up, "up", "-d"], cwd=project, check=True, capture_output=True)
        subprocess.run([*up, "exec", "db", "sh", "-c",
                        "echo row42 > /data/t && chown 999:999 /data/t && chmod 600 /data/t"],
                       cwd=project, check=True, capture_output=True)
        anonymous = subprocess.run(
            ["docker", "inspect", "-f", '{{range .Mounts}}{{.Name}}{{end}}', f"{name}-db-1"],
            check=True, capture_output=True, text=True).stdout.split()
        data_cmd.adopt_locked(int_paths, name, "db", "/data", "data")
        assert restarted == [f"{name}-db-1"]
        compose["services"]["db"]["volumes"] = ["data:/data"]
        compose["volumes"] = {"data": {}}
        (project / "compose.yml").write_text(yaml.safe_dump(compose))
        out = subprocess.run([*up, "up", "-d"], cwd=project, check=True, capture_output=True,
                             text=True)
        assert "not created by Docker Compose" not in out.stderr
        assert "already exists" not in out.stderr
        got = subprocess.run([*up, "exec", "db", "stat", "-c", "%u:%a:%n", "/data/t"],
                             cwd=project, check=True, capture_output=True, text=True).stdout
        assert got.strip() == "999:600:/data/t"
        got = subprocess.run([*up, "exec", "db", "cat", "/data/t"], cwd=project, check=True,
                             capture_output=True, text=True).stdout
        assert got.strip() == "row42"
    finally:
        subprocess.run([*up, "down", "-v"], cwd=project, capture_output=True)
        # adopt leaves the anonymous volume for the operator to remove.
        subprocess.run(["docker", "volume", "rm", "-f", f"{name}_data", *anonymous],
                       capture_output=True)
