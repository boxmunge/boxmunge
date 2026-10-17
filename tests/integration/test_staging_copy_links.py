# SPDX-License-Identifier: Apache-2.0
"""A link a container planted in staging's copies cannot redirect the copy.

The daemon resolves a -v host path's links as root, so a link at an
intermediate directory (data-staging/a -> elsewhere) would have the helper
empty and fill `elsewhere`. The copy mounts only the top -staging entry and
resolves the rest inside the helper, which refuses the link.
"""
from __future__ import annotations

import uuid

import pytest

from boxmunge.docker_run import DockerError
from boxmunge.staging_copy_plan import CopyPlan, Store
from boxmunge.staging_data import copy_production_data
from tests.integration.conftest import skip_no_docker

pytestmark = [pytest.mark.integration, skip_no_docker, pytest.mark.usefixtures("helper_image")]


@pytest.mark.parametrize("absolute", [False, True], ids=["relative", "absolute"])
def test_a_planted_intermediate_link_makes_the_copy_refuse(int_paths, tmp_path,
                                                           absolute) -> None:
    project = f"bmln{uuid.uuid4().hex[:8]}"
    project_dir = int_paths.project_dir(project)
    (project_dir / "data" / "a" / "b").mkdir(parents=True)
    (project_dir / "data" / "a" / "b" / "row").write_text("production's")
    victim = project_dir.parent / f"{project}-victim"
    (victim / "b").mkdir(parents=True)
    (victim / "b" / "keep").write_text("not staging's")
    (project_dir / "data-staging").mkdir()
    (project_dir / "data-staging" / "a").symlink_to(
        victim if absolute else f"../../{victim.name}")
    plan = CopyPlan(pairs=[(Store("bind", "./data/a/b", str(project_dir / "data/a/b")),
                            Store("bind", "./data/a/b", str(project_dir / "data-staging/a/b")))])
    with pytest.raises(DockerError, match="reached through a symlink"):
        copy_production_data(int_paths, project, plan)
    assert [p.name for p in (victim / "b").iterdir()] == ["keep"]
    assert (victim / "b" / "keep").read_text() == "not staging's"
