# SPDX-License-Identifier: Apache-2.0
"""The stage precheck with real `docker compose config` (nothing is started).

A candidate is checked from where it lies (its own tree), against
production as it runs and as it would run once the candidate is promoted.
Env files are the hard part: Compose 2.35 (the supported minimum) refuses
to resolve a model naming a missing env file, even with
--no-env-resolution, so a missing box-state file must be refused by name,
and release code the project dir lacks until the install must not be.
"""
from __future__ import annotations

import shutil
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from boxmunge.commands.deploy import run_deploy
from boxmunge.project_registry import add_project
from boxmunge.staged_release import staging_target_for
from boxmunge.staging_copy_plan import StagingDataError
from boxmunge.staging_isolation import (
    StagingIsolationError, candidate_model, production_model, staging_model,
)
from boxmunge.staging_prepare import precheck_candidate
from tests.bundle_helpers import manifest_text, place_bundle

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which("docker") is None, reason="docker CLI not on PATH"),
]

V1 = "2026-10-13T090000000000"


def _compose(**web) -> str:
    return yaml.safe_dump({"services": {"web": {
        "image": "nginx",
        "volumes": ["./appconfig:/etc/app:ro", "./uploads:/uploads"], **web}}})


def _files(project: str, **web) -> dict[str, str]:
    return {"manifest.yml": manifest_text(project, image_users=True), "compose.yml": _compose(**web),
            "appconfig/settings": "x", "uploads/.keep": ""}


@pytest.fixture
def deployed(paths):
    project = f"bmpc{uuid.uuid4().hex[:8]}"
    add_project(project, paths)
    place_bundle(paths, project, V1, _files(project))
    with patch("boxmunge.compose_guard.compose_up"), \
            patch("boxmunge.commands.deploy.caddy_reload"):
        assert run_deploy(project, paths, ref=V1) == 0
    return project


def _candidate(paths, project: str, **web) -> tuple[Path, Path, dict]:
    workspace = paths.project_releases(project) / "incoming"
    tree = workspace / "tree"
    for rel, text in _files(project, **web).items():
        (tree / rel).parent.mkdir(parents=True, exist_ok=True)
        (tree / rel).write_text(text)
    return tree, workspace, yaml.safe_load((tree / "manifest.yml").read_text())


def test_staging_resolves_from_the_candidate_and_production_from_the_project_dir(
        paths, deployed) -> None:
    tree, workspace, manifest = _candidate(paths, deployed)
    precheck_candidate(paths, deployed, manifest, tree, workspace)
    check = workspace / "staging-check"
    staging = staging_model(staging_target_for(tree, check, deployed))
    after = candidate_model(paths, deployed, tree, manifest, check)
    project_dir = paths.project_dir(deployed)

    def sources(model):
        return {v["target"]: v["source"] for v in model["services"]["web"]["volumes"]}
    assert sources(staging)["/etc/app"] == str(tree / "appconfig")
    assert sources(staging)["/uploads"] == str(project_dir / "uploads-staging")
    assert sources(after)["/etc/app"] == str(project_dir / "appconfig")
    assert sources(production_model(paths, deployed))["/uploads"] == str(project_dir / "uploads")


def test_a_missing_secrets_env_is_refused_by_name(paths, deployed) -> None:
    """Production has no secrets.env, which the candidate's service reads:
    staging could not start (nor production once promoted)."""
    assert not paths.project_secrets(deployed).exists()
    tree, workspace, manifest = _candidate(paths, deployed, env_file=["./secrets.env"])
    with pytest.raises(StagingDataError) as e:
        precheck_candidate(paths, deployed, manifest, tree, workspace)
    assert f"service web env_file {paths.project_secrets(deployed)}" in str(e.value)


def test_an_existing_or_optional_secrets_env_passes(paths, deployed) -> None:
    tree, workspace, manifest = _candidate(
        paths, deployed, env_file=[{"path": "./secrets.env", "required": False}])
    precheck_candidate(paths, deployed, manifest, tree, workspace)
    shutil.rmtree(workspace)
    paths.project_secrets(deployed).write_text("KEY=1\n")
    tree, workspace, manifest = _candidate(paths, deployed, env_file=["./secrets.env"])
    precheck_candidate(paths, deployed, manifest, tree, workspace)


def test_a_new_release_env_file_does_not_block_the_precheck(paths, deployed) -> None:
    """The project dir has no app.env until the candidate is installed."""
    tree, workspace, manifest = _candidate(paths, deployed, env_file=["./app.env"],
                                           label_file="./labels")
    (tree / "app.env").write_text("A=1\n")
    (tree / "labels").write_text("x=1\n")
    assert not (paths.project_dir(deployed) / "app.env").exists()
    precheck_candidate(paths, deployed, manifest, tree, workspace)


def test_sharing_with_production_after_promote_is_refused(paths, deployed) -> None:
    """Staging's copy of uploads is what production would mount once this
    release is promoted."""
    tree, workspace, manifest = _candidate(
        paths, deployed, volumes=["./appconfig:/etc/app:ro", "./uploads:/uploads",
                                  "./uploads-staging:/mirror:ro"])
    with pytest.raises(StagingIsolationError,
                       match="share these with production after promoting this release"):
        precheck_candidate(paths, deployed, manifest, tree, workspace)
