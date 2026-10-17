# SPDX-License-Identifier: Apache-2.0
"""The slot against real Docker and Compose (spec Test plan, Integration).

Staging runs from .releases/staged/release with --project-directory; these
pin how Compose resolves the staged release's relative paths there, and
that stage, re-stage, unstage, promote (killed and rerun included), and
production's own deploys and rollbacks during a stage never mix the two
environments. Production's own commands during a stage (upgrade restart,
pause/resume, check smoke, backup dump, critical down and recover) start,
exec into or stop production as v1 from its own project dir while v2 is
staged, and leave staging running as it was.
"""
from __future__ import annotations

import shutil
import time
from unittest.mock import patch

import pytest
import yaml

from boxmunge.backup_dump import execute_dump
from boxmunge.commands.check import run_check
from boxmunge.commands.deploy import run_deploy
from boxmunge.commands.health_state import update_health_state
from boxmunge.commands.pause_cmd import run_pause
from boxmunge.commands.promote_cmd import run_promote
from boxmunge.commands.recover_cmd import run_recover
from boxmunge.commands.resume_cmd import run_resume
from boxmunge.commands.rollback import run_rollback
from boxmunge.commands.stage_cmd import run_stage
from boxmunge.commands.unstage_cmd import run_unstage
from boxmunge.commands.upgrade_steps import restart_projects
from boxmunge.staged_release import release_dir, slot_dir, staging_target
from boxmunge.staging_isolation import production_model, staging_model
from tests.bundle_helpers import place_bundle, tree_snapshot
from tests.integration.docker_images import docker
from tests.integration.slot_release import (
    V1, V2, V3, containers, no_caddy, production_files, project, release, runs,
    slot_project, working_dir,
)
from tests.txn_helpers import crash_at

__all__ = ["project"]  # the fixture, imported for pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which("docker") is None, reason="docker CLI not on PATH"),
    # Data copies, placeholders and unstage's cleanup run in the data helper.
    pytest.mark.usefixtures("helper_image"),
]


def _staged(project: str) -> str:
    return f"{project}-staging-app-1"


def _live(project: str) -> str:
    return f"{project}-app-1"


def test_compose_resolves_relative_paths_in_the_slot(paths, project) -> None:
    pdir = paths.project_dir(project)
    with no_caddy():
        assert run_deploy(project, paths, ref=V1) == 0
        assert run_stage(project, paths, ref=V2) == 0
    slot_release = release_dir(slot_dir(paths, project))
    model = staging_model(staging_target(paths, project))
    app = model["services"]["app"]
    vols = {v["target"]: v["source"] for v in app["volumes"]}
    assert vols == {"/etc/app": str(slot_release / "appconfig"),
                    "/data": str(pdir / "data-staging"),
                    "/boxmunge-scripts": str(slot_release / "boxmunge-scripts")}
    # env_file and .env resolve in the slot, not in production's dir.
    # Compose 2.35 reads env files into `environment` even with
    # --no-env-resolution; later versions list them instead.
    if "env_file" in app:
        assert [e["path"] for e in app["env_file"]] == [str(slot_release / "app.env")]
    else:
        assert app["environment"]["FROM_ENV_FILE"] == "v2"
    assert app["environment"]["TAG"] == "v2"
    assert runs(_staged(project), "v2") and runs(_live(project), "v1")
    assert working_dir(_staged(project)) == str(slot_release)
    assert working_dir(_live(project)) == str(pdir)


def test_a_build_context_resolves_in_the_slot(paths) -> None:
    """build: is resolved, not built: no image is made."""
    def with_build(version: str) -> dict:
        compose = {"services": {"app": {"build": {"context": "./img"},
                                        "network_mode": "none",
                                        "environment": {"VERSION": version}}}}
        return {"compose.yml": yaml.safe_dump(compose), "img/Dockerfile": "FROM scratch\n"}

    with slot_project(paths) as project:
        for ref, version in ((V1, "v1"), (V2, "v2")):
            place_bundle(paths, project, ref, {**release(project, version), **with_build(version)})
        with no_caddy(), patch("boxmunge.compose_guard.compose_up"):
            assert run_deploy(project, paths, ref=V1) == 0
            assert run_stage(project, paths, ref=V2) == 0
        staged = staging_model(staging_target(paths, project))["services"]["app"]
        live = production_model(paths, project)["services"]["app"]
    assert staged["build"]["context"] == str(release_dir(slot_dir(paths, project)) / "img")
    assert live["build"]["context"] == str(paths.project_dir(project) / "img")


def test_stage_and_unstage_leave_production_untouched(paths, project) -> None:
    with no_caddy():
        assert run_deploy(project, paths, ref=V1) == 0
        assert run_deploy(project, paths, ref=V2) == 0   # production has a previous/
        before, files = containers(project), production_files(paths, project)
        assert any(rel.startswith(".releases/previous") for rel in files)
        assert run_stage(project, paths, ref=V3) == 0
        assert runs(_staged(project), "v3")
        assert containers(project) == before and production_files(paths, project) == files
        assert run_unstage(project, paths) == 0
    assert containers(project) == before and production_files(paths, project) == files
    assert containers(f"{project}-staging") == {}
    assert not slot_dir(paths, project).exists()


def _start_events(container_id: str, since: str) -> int:
    out = docker("events", "--since", since, "--until", str(int(time.time()) + 1),
                 "--filter", f"container={container_id}", "--filter", "event=start",
                 "--format", "{{.Action}}")
    return len(out.split())


def test_copy_data_restarts_production_once_with_the_same_containers(paths) -> None:
    copying = {"copy_data": True}
    with slot_project(paths, {V1: copying, V2: copying}) as project:
        with no_caddy():
            assert run_deploy(project, paths, ref=V1) == 0
            before, files = containers(project), production_files(paths, project)
            assert run_stage(project, paths, ref=V2) == 0
        after = containers(project)
        assert {k: v[0] for k, v in after.items()} == {k: v[0] for k, v in before.items()}
        for name, (cid, started) in before.items():
            assert after[name][1] != started          # restarted, not recreated ...
            assert _start_events(cid, started) == 2   # ... once: deploy's start, the copy's
        assert production_files(paths, project) == files
        assert runs(_live(project), "v1") and runs(_staged(project), "v2")


def test_restage_replaces_staging_and_leaves_production_alone(paths, project) -> None:
    with no_caddy():
        assert run_deploy(project, paths, ref=V1) == 0
        assert run_stage(project, paths, ref=V2) == 0
        before, files = containers(project), production_files(paths, project)
        assert run_stage(project, paths, ref=V3) == 0
    assert runs(_staged(project), "v3") and runs(_live(project), "v1")
    assert containers(project) == before and production_files(paths, project) == files


def test_promote_deploys_the_staged_release_and_removes_staging(paths, project) -> None:
    with no_caddy():
        assert run_deploy(project, paths, ref=V1) == 0
        assert run_stage(project, paths, ref=V2) == 0
        assert run_promote(project, paths) == 0
    assert runs(_live(project), "v2")
    assert working_dir(_live(project)) == str(paths.project_dir(project))
    assert containers(f"{project}-staging") == {}
    assert not slot_dir(paths, project).exists()
    # Staging's copy of ./data outlives the stage: production still mounts ./data.
    assert (paths.project_dir(project) / "data-staging").is_dir()


def test_prod_deploy_and_rollback_during_a_stage_leave_staging_alone(paths, project) -> None:
    with no_caddy():
        assert run_deploy(project, paths, ref=V1) == 0
        assert run_stage(project, paths, ref=V2) == 0
        staged, slot = containers(f"{project}-staging"), _slot_snapshot(paths, project)
        assert run_deploy(project, paths, ref=V3) == 0
        assert runs(_live(project), "v3")
        assert containers(f"{project}-staging") == staged
        assert _slot_snapshot(paths, project) == slot
        assert run_rollback(project, paths, yes=True) == 0
    assert runs(_live(project), "v1") and runs(_staged(project), "v2")
    assert containers(f"{project}-staging") == staged
    assert _slot_snapshot(paths, project) == slot


def _slot_snapshot(paths, project: str) -> dict:
    return tree_snapshot(slot_dir(paths, project))


def test_a_production_release_mounting_staging_data_is_refused(paths, capsys) -> None:
    """Staging's copy of ./uploads is ./uploads-staging: a production
    release mounting that would share staging's data (D8)."""
    with slot_project(paths, {V2: {"volumes": ["./uploads:/uploads"]},
                              V3: {"volumes": ["./uploads-staging:/uploads"]}}) as project:
        with no_caddy():
            assert run_deploy(project, paths, ref=V1) == 0
            assert run_stage(project, paths, ref=V2) == 0
            before, files = containers(project), production_files(paths, project)
            capsys.readouterr()
            assert run_deploy(project, paths, ref=V3) != 0
        err = capsys.readouterr().err
        assert "staging would share these with production after this install" in err
        assert "uploads-staging" in err and "Nothing was changed" in err
        assert containers(project) == before and production_files(paths, project) == files
        assert runs(_live(project), "v1") and runs(_staged(project), "v2")


def test_promote_killed_at_switching_is_finished_by_promote(paths, project) -> None:
    with no_caddy():
        assert run_deploy(project, paths, ref=V1) == 0
        assert run_stage(project, paths, ref=V2) == 0
        assert crash_at("txn.switching", lambda: run_promote(project, paths)) == 137
        assert slot_dir(paths, project).exists()
        assert run_promote(project, paths) == 0
    assert runs(_live(project), "v2")
    assert containers(f"{project}-staging") == {}
    assert not slot_dir(paths, project).exists()
    assert not (paths.project_releases(project) / "install.json").exists()


# --- Production commands during a stage ---------------------------------

@pytest.fixture
def staged(paths, project):
    """v1 live, v2 staged; yields the project and staging's containers."""
    with no_caddy():
        assert run_deploy(project, paths, ref=V1) == 0
        assert run_stage(project, paths, ref=V2) == 0
        yield project, containers(f"{project}-staging")


def _production_is_v1(paths, project: str, staging: dict) -> None:
    assert runs(_live(project), "v1")
    assert working_dir(_live(project)) == str(paths.project_dir(project))
    assert runs(_staged(project), "v2")
    assert containers(f"{project}-staging") == staging


def test_upgrade_restart_uses_production_files(paths, staged) -> None:
    project, staging = staged
    before = containers(project)
    result = restart_projects(paths, refused=())
    assert result.succeeded == [project] and not result.failed
    # `up` from production's own files finds its model unchanged; from the
    # staged release's it would have recreated the container as v2.
    assert containers(project) == before
    _production_is_v1(paths, project, staging)


def test_pause_and_resume_use_production_files(paths, staged) -> None:
    project, staging = staged
    assert run_pause(project, paths, yes=True) == 0
    assert run_resume(project, paths, yes=True, skip_security_checks=True) == 0
    _production_is_v1(paths, project, staging)


def test_check_smoke_and_backup_dump_use_production_files(paths, staged) -> None:
    """v2's smoke script fails in a v1 container: check passing means
    production ran its own script."""
    project, staging = staged
    assert run_check(project, paths, verbose=False) == 0
    dump = execute_dump(paths, project, 'echo "$VERSION $TAG"; cat /etc/app/settings', "app")
    try:
        assert dump.read_text().split() == ["v1", "v1", "v1"]
    finally:
        dump.unlink()
    _production_is_v1(paths, project, staging)


def test_critical_down_stops_only_production_and_recover_uses_its_files(paths, staged) -> None:
    project, staging = staged
    update_health_state(project, 2, "smoke failed (test)", paths)
    assert containers(project) == {}
    assert containers(f"{project}-staging") == staging
    assert run_recover(project, paths, yes=True) == 0
    _production_is_v1(paths, project, staging)
