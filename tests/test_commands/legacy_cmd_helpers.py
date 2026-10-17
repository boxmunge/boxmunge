# SPDX-License-Identifier: Apache-2.0
"""Running legacy-stage with Docker, staging, compose and alerts mocked."""
from __future__ import annotations

from unittest.mock import patch

from boxmunge.commands.legacy_stage_cmd import legacy_stage_locked
from tests.stage_helpers import staging_docker_off
from tests.test_legacy_stage_evidence import T, _created


def legacy_run(paths, choice, confirm=False, created=(-5,), at=T):
    with staging_docker_off() as docker, \
            patch("boxmunge.docker_containers.created_times",
                  return_value=_created(*created, at=at)), \
            patch("boxmunge.legacy_stage_ops.compose_down") as down, \
            patch("boxmunge.legacy_stage_ops.caddy_reload"), \
            patch("boxmunge.legacy_stage_ops.notify") as sent, \
            patch("boxmunge.legacy_stage.notify", return_value=True):
        rc = legacy_stage_locked(paths, "myapp", choice, confirm)
    # The latest run's mocks, for the assertions.
    legacy_run.up, legacy_run.down, legacy_run.sent = docker["up"], down, sent
    return rc

