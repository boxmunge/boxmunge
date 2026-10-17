# SPDX-License-Identifier: Apache-2.0
"""The non-root deploy cases on a remapped daemon, through run_deploy."""
from __future__ import annotations

import subprocess
import uuid

import pytest

from boxmunge import data_helper
from tests.integration import nonroot_cases as nc
from tests.integration.userns.conftest import USERNS_DIND
from tests.integration.userns.dockerd import BUSYBOX

pytestmark = USERNS_DIND


@pytest.fixture(scope="module")
def box(remapped_daemon):
    """The helper image (busybox stands in for the system image, as in
    test_helper_remapped) and the proxy network every overlay names."""
    subprocess.run(["docker", "tag", BUSYBOX, data_helper.HELPER_IMAGE], check=True)
    subprocess.run(["docker", "tag", BUSYBOX, nc.BUSYBOX], check=True)
    subprocess.run(["docker", "network", "create", "boxmunge-proxy"], capture_output=True)
    yield remapped_daemon
    subprocess.run(["docker", "network", "rm", "boxmunge-proxy"], capture_output=True)
    subprocess.run(["docker", "image", "rm", data_helper.HELPER_IMAGE], capture_output=True)


CASES = [nc.case_registry_root_refused, nc.case_declared_image_runs,
         nc.case_redis_saves_after_recreate, nc.case_image_owned_target_refused,
         nc.case_chowned_target_survives_recreates, nc.case_imageless_target_chowned_once]


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.__name__)
def test_case(box, dind_record, capsys, case) -> None:
    project = f"bmnr{uuid.uuid4().hex[:8]}"
    try:
        case(dind_record, project, capsys)
    finally:
        nc.teardown(dind_record, project)


def test_anonymous_volume_is_refused_when_remapped(box, dind_record, capsys) -> None:
    project = f"bmnr{uuid.uuid4().hex[:8]}"
    try:
        nc.case_anonymous_volume(dind_record, project, capsys, remapped=True)
    finally:
        nc.teardown(dind_record, project)
