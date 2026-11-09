# SPDX-License-Identifier: Apache-2.0
"""A deployed build service's image across later starts, on a plain daemon
(see image_identity_cases; the dind job runs them on both image stores)."""
from __future__ import annotations

import pytest

from tests.integration import image_identity_cases as ic
from tests.integration.conftest import skip_no_docker

pytestmark = [pytest.mark.integration, skip_no_docker]


@pytest.mark.parametrize("case", [ic.case_restart_starts_the_deployed_image,
                                  ic.case_a_start_recreates_a_container_whose_image_is_gone],
                         ids=lambda c: c.__name__)
def test_case(tmp_path, capsys, case) -> None:
    paths, project = ic.box_paths(tmp_path / "boxmunge"), ic.project_name()
    try:
        case(paths, project, capsys)
    finally:
        ic.teardown(paths, project)
