"""Non-root deploy cases on a plain (unremapped) daemon."""
from __future__ import annotations

import uuid

import pytest

from tests.integration import nonroot_cases as nc
from tests.integration.conftest import skip_no_docker

pytestmark = [pytest.mark.integration, skip_no_docker]

CASES = [nc.case_registry_root_refused, nc.case_declared_image_runs,
         nc.case_redis_saves_after_recreate, nc.case_image_owned_target_refused,
         nc.case_chowned_target_survives_recreates, nc.case_imageless_target_chowned_once,
         nc.case_user_change_needs_chown]


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.__name__)
def test_case(int_paths, helper_image, capsys, case) -> None:
    project = f"bmnr{uuid.uuid4().hex[:8]}"
    try:
        case(int_paths, project, capsys)
    finally:
        nc.teardown(int_paths, project)


def test_anonymous_volume_warns_before_migration(int_paths, helper_image, capsys) -> None:
    project = f"bmnr{uuid.uuid4().hex[:8]}"
    try:
        nc.case_anonymous_volume(int_paths, project, capsys, remapped=False)
    finally:
        nc.teardown(int_paths, project)


@pytest.mark.parametrize("case", [nc.case_chown_snapshot_pairs_with_the_next_deploy,
                                  nc.case_chown_snapshot_dropped_after_a_docker_start],
                         ids=lambda c: c.__name__)
def test_chown_snapshot(int_paths, helper_image, system_container, capsys, case) -> None:
    project = f"bmnr{uuid.uuid4().hex[:8]}"
    try:
        case(int_paths, project, capsys)
    finally:
        nc.teardown(int_paths, project)
