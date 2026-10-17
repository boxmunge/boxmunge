"""The interim staging layers (#46, #65, #67) are gone (spec 'What is deleted')."""
from __future__ import annotations

import importlib.util

import pytest

from boxmunge.compose import generate_compose_override
from boxmunge.paths import BoxPaths


@pytest.mark.parametrize("module", ["boxmunge.release_staging", "boxmunge.live_mounts",
                                    "boxmunge.live_mirror", "boxmunge.commands.promote_release"])
def test_module_deleted(module) -> None:
    assert importlib.util.find_spec(module) is None


def test_no_live_scripts_in_the_overlay() -> None:
    manifest = {"project": "myapp", "services": {"web": {"port": 80, "smoke": "s.sh"}}}
    overlay = generate_compose_override(manifest, user_compose={"services": {"web": {}}})
    assert "live-scripts" not in overlay and "./boxmunge-scripts" in overlay


def test_state_staging_retired(tmp_path) -> None:
    assert not hasattr(BoxPaths(root=tmp_path), "project_staging_state")
