"""Drive stage/unstage/promote without Docker."""
from __future__ import annotations

from contextlib import contextmanager
from unittest.mock import patch

from boxmunge.commands.deploy import run_deploy
from boxmunge.commands.stage_cmd import run_stage
from boxmunge.project_registry import add_project
from tests.bundle_helpers import place_bundle

V1, V2, V3 = ("2026-10-16T090000000000", "2026-10-16T100000000000",
              "2026-10-16T110000000000")


@contextmanager
def staging_docker_off():
    with patch("boxmunge.compose_guard.compose_up") as up, \
            patch("boxmunge.compose_guard.start_containers"), \
            patch("boxmunge.commands.deploy.caddy_reload"), \
            patch("boxmunge.staging_bringup.caddy_reload"), \
            patch("boxmunge.stage_slot.compose_down") as down_retire, \
            patch("boxmunge.commands.unstage_cmd.compose_down") as down, \
            patch("boxmunge.commands.unstage_cmd.caddy_reload"), \
            patch("boxmunge.docker.compose_logs_capture", return_value=""):
        # compose_logs_capture: the post-deploy writable diagnostics and a
        # failed smoke's hint fetch logs, production's and staging's.
        yield {"up": up, "down": down, "down_retire": down_retire}


def prod_and_stage(paths, *, prod_files=None, staged_files=None):
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1, files={"VERSION": "v1\n", **(prod_files or {})})
    place_bundle(paths, timestamp=V2, files={"VERSION": "v2\n", **(staged_files or {})})
    with staging_docker_off():
        assert run_deploy("myapp", paths, ref=V1) == 0
        assert run_stage("myapp", paths, ref=V2) == 0
    return paths.project_dir("myapp")
