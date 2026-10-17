"""Every compose helper can run a project kept outside its directory (the slot)."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from boxmunge import docker

# Captured at import, before tests/conftest.py swaps in its no-Docker stub.
_REAL_COMPOSE_CONFIG = docker.compose_config

SLOT = Path("/opt/boxmunge/projects/myapp/.releases/staged")
KW = {"compose_files": [str(SLOT / "compose.staging-base.yml"),
                        str(SLOT / "compose.boxmunge-staging.yml")],
      "project_name": "myapp-staging", "project_directory": SLOT / "release",
      "env_file": SLOT / "release" / ".env"}


@pytest.mark.parametrize("verb, call", [
    ("up", lambda: docker.compose_up(SLOT / "release", **KW)),
    ("down", lambda: docker.compose_down(SLOT / "release", **KW)),
    ("stop", lambda: docker.compose_stop(SLOT / "release", **KW)),
    ("ps", lambda: docker.compose_ps(SLOT / "release", **KW)),
    ("logs", lambda: docker.compose_logs(SLOT / "release", **KW)),
    ("logs", lambda: docker.compose_logs_capture(SLOT / "release", **KW)),
    ("config", lambda: _REAL_COMPOSE_CONFIG(SLOT / "release", **KW)),
    ("pull", lambda: docker.compose_pull(SLOT / "release", services=["web"], **KW)),
])
def test_project_directory_and_env_file_come_before_the_verb(verb, call) -> None:
    with patch.object(docker, "_run") as run:
        run.return_value.stdout = ""
        call()
    argv = run.call_args.args[0]
    i = argv.index("--project-directory")
    assert argv[i + 1] == str(SLOT / "release")
    assert argv[argv.index("--env-file") + 1] == str(SLOT / "release" / ".env")
    assert i < argv.index(verb)
    assert run.call_args.kwargs["cwd"] == SLOT / "release"


def test_production_calls_are_unchanged() -> None:
    with patch.object(docker, "_run") as run:
        docker.compose_down(Path("/p"), compose_files=["compose.yml"], project_name="myapp")
    assert "--project-directory" not in run.call_args.args[0]
    assert "--env-file" not in run.call_args.args[0]


def test_start_containers() -> None:
    with patch.object(docker, "_run") as run:
        docker.start_containers(["myapp-web-1", "myapp-db-1"])
    assert run.call_args.args[0] == ["docker", "start", "myapp-web-1", "myapp-db-1"]


def test_built_image_helpers_live_in_built_images() -> None:
    from boxmunge import built_images
    assert hasattr(built_images, "untag_old_built_names")
    assert hasattr(built_images, "remove_built_images")
    assert not hasattr(docker, "untag_old_built_names")
    assert not hasattr(docker, "remove_built_images")
