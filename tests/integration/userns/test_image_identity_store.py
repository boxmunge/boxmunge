# SPDX-License-Identifier: Apache-2.0
"""image_identity_cases on the dind job's own image store, through
run_deploy: the containerd store in one matrix entry, the graph driver in
the others. No remap: these run on the daemon as the job started it."""
from __future__ import annotations

import os
import subprocess

import pytest

from tests.integration import image_identity_cases as ic
from tests.integration import nonroot_cases as nc
from tests.integration.userns.conftest import USERNS_DIND
from tests.integration.userns.dockerd import BUSYBOX

pytestmark = USERNS_DIND


@pytest.fixture(scope="module")
def box():
    """busybox under the cases' name, and the proxy network every overlay names.
    The daemon must run the store the job names: a case's containerd branch
    is the regression test, and must not quietly become the other one."""
    prior = os.environ["BOXMUNGE_DIND_PRIOR_STORE"]
    assert ic.containerd_store() == (prior == "containerd"), prior
    subprocess.run(["docker", "pull", "-q", BUSYBOX], check=True, capture_output=True)
    subprocess.run(["docker", "tag", BUSYBOX, nc.BUSYBOX], check=True)
    subprocess.run(["docker", "network", "create", "boxmunge-proxy"], capture_output=True)
    yield
    subprocess.run(["docker", "network", "rm", "boxmunge-proxy"], capture_output=True)


@pytest.mark.parametrize("case", [ic.case_restart_starts_the_deployed_image,
                                  ic.case_a_start_recreates_a_container_whose_image_is_gone,
                                  ic.case_a_start_whose_image_is_missing_is_refused,
                                  ic.case_a_pinned_up_applies_no_pull_policy],
                         ids=lambda c: c.__name__)
def test_case(box, tmp_path, capsys, case) -> None:
    paths, project = ic.box_paths(tmp_path / "boxmunge"), ic.project_name()
    try:
        case(paths, project, capsys)
    finally:
        ic.teardown(paths, project)
