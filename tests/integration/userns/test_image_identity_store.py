# SPDX-License-Identifier: Apache-2.0
"""image_identity_cases on the dind job's own image store, through
run_deploy: the containerd store in one matrix entry, the graph driver in
the others. No remap: these run on the daemon as the job started it."""
from __future__ import annotations

import subprocess

import pytest

from tests.integration import image_identity_cases as ic
from tests.integration import nonroot_cases as nc
from tests.integration.userns.conftest import USERNS_DIND
from tests.integration.userns.dockerd import BUSYBOX

pytestmark = USERNS_DIND


@pytest.fixture(scope="module")
def box():
    """busybox under the cases' name, and the proxy network every overlay names."""
    subprocess.run(["docker", "pull", "-q", BUSYBOX], check=True, capture_output=True)
    subprocess.run(["docker", "tag", BUSYBOX, nc.BUSYBOX], check=True)
    subprocess.run(["docker", "network", "create", "boxmunge-proxy"], capture_output=True)
    yield
    subprocess.run(["docker", "network", "rm", "boxmunge-proxy"], capture_output=True)


@pytest.mark.parametrize("case", [ic.case_restart_starts_the_deployed_image,
                                  ic.case_a_start_recreates_a_container_whose_image_is_gone,
                                  ic.case_regenerating_names_a_stopped_containers_build,
                                  ic.case_a_start_names_a_nameless_build_and_runs_it],
                         ids=lambda c: c.__name__)
def test_case(box, tmp_path, capsys, case) -> None:
    paths, project = ic.box_paths(tmp_path / "boxmunge"), ic.project_name()
    try:
        case(paths, project, capsys)
    finally:
        ic.teardown(paths, project)
