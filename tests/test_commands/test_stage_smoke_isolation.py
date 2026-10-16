"""Production is checked with its own smoke script while a release is staged.

`stage` installs the staged release into the project dir production runs
from. Production's overlay used to mount ./boxmunge-scripts from there, so
after a stage, `check` ran the staged release's smoke.sh against the
production release; a check only the new release passes marked production
FAILING, and one exiting 2 got it stopped by the health monitor.
"""
from __future__ import annotations

from contextlib import contextmanager
from unittest.mock import patch

import pytest
import yaml

from boxmunge.commands.smoke_result import SmokeResult
from boxmunge.commands.deploy import run_deploy
from boxmunge.commands.promote_cmd import run_promote
from boxmunge.commands.stage_cmd import run_stage
from boxmunge.commands.unstage_cmd import run_unstage
from boxmunge.compose import prepare_compose_override
from boxmunge.docker import DockerError
from boxmunge.manifest import load_manifest
from boxmunge.project_registry import add_project
from boxmunge.release_staging import has_prestage

from tests.bundle_helpers import manifest_text, place_bundle

V1 = "2026-10-13T090000000000"
V2 = "2026-10-13T100000000000"
SMOKE_MANIFEST = manifest_text().replace(
    "      - path: /\n", "      - path: /\n    smoke: boxmunge-scripts/smoke.sh\n")


def _bundle(paths, timestamp: str, smoke: str) -> None:
    place_bundle(paths, timestamp=timestamp, files={
        "manifest.yml": SMOKE_MANIFEST,
        "boxmunge-scripts/smoke.sh": smoke,
    })


@contextmanager
def _docker(deploy_up=None):
    with patch("boxmunge.commands.deploy.compose_up", side_effect=deploy_up), \
            patch("boxmunge.commands.deploy.caddy_reload"), \
            patch("boxmunge.commands.check.run_smoke_in_container",
                  return_value=SmokeResult("ok", "")), \
            patch("boxmunge.commands.stage_cmd.compose_up"), \
            patch("boxmunge.commands.stage_cmd.caddy_reload"), \
            patch("boxmunge.commands.unstage_cmd.compose_down"), \
            patch("boxmunge.commands.unstage_cmd.caddy_reload"):
        yield


def _prod_smoke(paths) -> str:
    """The smoke.sh production's container sees at /boxmunge-scripts."""
    pdir = paths.project_dir("myapp")
    overlay = yaml.safe_load(paths.project_compose_override("myapp").read_text())
    source = overlay["services"]["web"]["volumes"][0]["source"]
    return (pdir / source / "smoke.sh").read_text()


@pytest.fixture
def staged(paths):
    add_project("myapp", paths)
    _bundle(paths, V1, "prod check\n")
    with _docker():
        assert run_deploy("myapp", paths) == 0
    _bundle(paths, V2, "staged check\n")
    with _docker():
        assert run_stage("myapp", paths) == 0
    return paths


def test_stage_leaves_production_on_its_own_smoke_script(staged) -> None:
    pdir = staged.project_dir("myapp")
    assert (pdir / "boxmunge-scripts" / "smoke.sh").read_text() == "staged check\n"
    assert _prod_smoke(staged) == "prod check\n"


def test_regenerating_production_overlay_during_stage_keeps_its_script(staged) -> None:
    # resume, recover, upgrade: regenerate for the release production runs.
    manifest = load_manifest(staged.project_manifest("myapp"))
    prepare_compose_override(staged, manifest, component="resume")
    assert _prod_smoke(staged) == "prod check\n"


def test_promote_switches_production_to_the_staged_script(staged) -> None:
    with _docker():
        assert run_promote("myapp", staged) == 0
    assert _prod_smoke(staged) == "staged check\n"


def test_promote_failing_before_any_start_keeps_production_on_its_own_script(
    paths,
) -> None:
    """A pre-deploy hook that fails runs before any container is touched:
    production still runs its own release, so it keeps its own script."""
    add_project("myapp", paths)
    _bundle(paths, V1, "prod check\n")
    with _docker():
        assert run_deploy("myapp", paths) == 0
    place_bundle(paths, timestamp=V2, files={
        "manifest.yml": SMOKE_MANIFEST + "deploy:\n  pre_deploy: \"false\"\n",
        "boxmunge-scripts/smoke.sh": "staged check\n",
    })
    with _docker():
        assert run_stage("myapp", paths) == 0
        assert run_promote("myapp", paths) == 1
    assert _prod_smoke(paths) == "prod check\n"
    assert has_prestage(paths, "myapp")


def test_promote_failing_once_containers_started_runs_the_staged_script(
    staged,
) -> None:
    """A failed `compose up` may have recreated some services: production is
    taken to run the staged release, which it is then checked with."""
    with _docker(deploy_up=DockerError("boom")):
        assert run_promote("myapp", staged) == 1
    assert _prod_smoke(staged) == "staged check\n"
    assert not has_prestage(staged, "myapp")


def test_unstage_keeps_production_on_its_own_script(staged) -> None:
    with _docker():
        assert run_unstage("myapp", staged) == 0
    assert _prod_smoke(staged) == "prod check\n"
    pdir = staged.project_dir("myapp")
    assert (pdir / "boxmunge-scripts" / "smoke.sh").read_text() == "prod check\n"
