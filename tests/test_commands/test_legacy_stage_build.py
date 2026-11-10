# SPDX-License-Identifier: Apache-2.0
"""legacy-stage builds the release it keeps before it starts it: no start
builds, so production's containers, which may run the other release's
images, would otherwise go on running them over this release's files."""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from boxmunge import legacy_stage_ops
from boxmunge.commands import deploy_images
from boxmunge.legacy_stage import legacy_stage
from tests.test_commands.legacy_cmd_helpers import legacy_run
from tests.txn_helpers import fake_backups

BUILT = {"services": {"web": {"build": ".", "command": ["sleep", "infinity"]}}}


def _with_a_build_service(pdir: Path) -> None:
    for release in (pdir, pdir / ".releases" / "prestage" / "release"):
        (release / "compose.yml").write_text(yaml.safe_dump(BUILT))
        (release / "Dockerfile").write_text("FROM busybox:1.36\n")


@pytest.mark.parametrize("choice, confirm, created", [
    ("keep-staged", False, (-5,)), ("discard", True, (-5, 2))],
    ids=["keep-staged", "discard --confirm-recreated"])
def test_the_release_is_built_under_candidates_before_the_start(
        paths, legacy, monkeypatch, choice, confirm, created) -> None:
    _with_a_build_service(legacy)
    order: list = []

    def decide(paths_, target, manifest, *, component, pull, rollback=False,
               refetch=frozenset()):
        overlay = yaml.safe_load(Path(target.compose.files[-1]).read_text())
        # A release 0.10.1 deployed predates users being decided: as a
        # rollback, it is built again from the base images the box has.
        order.append(("build", overlay["services"]["web"]["image"], rollback, pull))
        return {}
    monkeypatch.setattr(deploy_images, "prepare_release_users", decide)
    real_promote = legacy_stage_ops.promote_candidates
    monkeypatch.setattr(legacy_stage_ops, "promote_candidates",
                        lambda p, name: order.append(("promote",)) or real_promote(p, name))
    with fake_backups([]):  # --keep-staged takes the pre-deploy snapshot
        assert legacy_run(paths, choice, confirm=confirm, created=created) == 0
    assert legacy_stage(paths, "myapp") is None
    assert order == [("build", "boxmunge.invalid/myapp/web:boxmunge-candidate", True, False),
                     ("promote",)]
    legacy_run.up.assert_called()
