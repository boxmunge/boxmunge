# SPDX-License-Identifier: Apache-2.0
"""Staging's files are written for a release and validated where it lies.

Resolution here is the unit tier's literal stand-in for `docker compose
config`; tests/integration/test_staging_precheck.py runs the real one.
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from boxmunge.compose_validate import ComposeSecurityError
from boxmunge.staged_release import STAGING_BASE, STAGING_OVERLAY
from boxmunge.staging_copy_plan import StagingDataError
from boxmunge.staging_prepare import (
    env_files_for_staging, validate_staging_base, write_staging_files,
)
from tests.bundle_helpers import manifest_text

P = "myapp"


def _release(root: Path, **web) -> tuple[Path, dict]:
    release = root / "release"
    release.mkdir(parents=True)
    (release / "manifest.yml").write_text(manifest_text(P))
    (release / "compose.yml").write_text(yaml.safe_dump(
        {"services": {"web": {"image": "nginx", **web}}}))
    return release, yaml.safe_load(manifest_text(P))


def _files(paths, tmp_path, **web) -> tuple[Path, Path, dict]:
    paths.project_dir(P).mkdir(parents=True, exist_ok=True)
    release, manifest = _release(paths.project_releases(P) / "staged", **web)
    write_staging_files(paths, P, manifest, release, release.parent)
    return release, release.parent, manifest


def test_env_files_read_the_staged_project_env_and_productions_secrets(paths, tmp_path) -> None:
    release, _ = _release(tmp_path)
    paths.project_dir(P).mkdir(parents=True)
    assert env_files_for_staging(paths, P, release) == {}
    paths.host_secrets.write_text("")
    paths.project_secrets(P).write_text("")
    (paths.project_dir(P) / "project.env").write_text("")   # production's: not staging's
    assert env_files_for_staging(paths, P, release) == {
        "host_secrets": str(paths.host_secrets),
        "project_secrets": str(paths.project_secrets(P))}
    (release / "project.env").write_text("")
    assert env_files_for_staging(paths, P, release)["project_env"] == "./project.env"


def test_files_are_written_beside_the_release_for_it(paths, tmp_path) -> None:
    release, files_dir, _ = _files(paths, tmp_path, volumes=["./uploads:/u", "./conf:/c:ro"])
    (release / "uploads").mkdir()
    base = yaml.safe_load((files_dir / STAGING_BASE).read_text())
    assert (files_dir / STAGING_OVERLAY).is_file()
    # uploads is mounted read-write, so box state: staging gets its copy.
    assert base["services"]["web"]["volumes"] == [
        f"{paths.project_dir(P)}/uploads-staging:/u", "./conf:/c:ro"]


def test_validation_refuses_a_missing_box_state_env_file(paths, tmp_path) -> None:
    """Production has no secrets.env: staging could not start, and Compose
    2.35 could not even resolve the base. Refused naming the file."""
    release, files_dir, manifest = _files(paths, tmp_path, env_file=["./secrets.env"])
    with pytest.raises(StagingDataError) as e:
        validate_staging_base(paths, P, manifest, files_dir, release)
    assert f"service web env_file {paths.project_secrets(P)}" in str(e.value)
    assert "secrets set myapp" in str(e.value)


def test_validation_accepts_an_optional_or_existing_env_file(paths, tmp_path) -> None:
    release, files_dir, manifest = _files(
        paths, tmp_path, env_file=[{"path": "./secrets.env", "required": False}])
    validate_staging_base(paths, P, manifest, files_dir, release)
    paths.project_secrets(P).write_text("")
    write_staging_files(paths, P, manifest, release, files_dir)
    validate_staging_base(paths, P, manifest, files_dir, release)


def test_validation_refuses_a_missing_release_env_file(paths, tmp_path) -> None:
    release, files_dir, manifest = _files(paths, tmp_path, env_file="./app.env")
    with pytest.raises(StagingDataError, match=f"service web env_file {release}/app.env"):
        validate_staging_base(paths, P, manifest, files_dir, release)


def test_the_releases_env_file_is_never_writable_by_staging(paths, tmp_path) -> None:
    """Staging interpolates from release/.env (--env-file). A read-write
    mount of it becomes staging's copy, and a base that mounted the
    release's own file read-write anyway is refused (.releases is
    protected)."""
    release, files_dir, manifest = _files(paths, tmp_path, volumes=["./.env:/e"])
    base = files_dir / STAGING_BASE
    assert yaml.safe_load(base.read_text())["services"]["web"]["volumes"] == [
        f"{paths.project_dir(P)}/.env-staging:/e"]
    (release / ".env").write_text("TAG=1\n")
    base.write_text(yaml.safe_dump({"services": {"web": {"image": "nginx",
                                                         "volumes": ["./.env:/e"]}}}))
    with pytest.raises(ComposeSecurityError, match="read-write.*rewrite .releases"):
        validate_staging_base(paths, P, manifest, files_dir, release)


def test_precheck_refuses_staging_mounting_productions_release_code(paths, tmp_path) -> None:
    """I3: an absolute path to production's release code is not rewritten
    (it is not box state), so staging would read production's files."""
    from boxmunge.staging_isolation import StagingIsolationError
    from boxmunge.staging_prepare import precheck_candidate
    conf = paths.project_dir(P) / "appconfig"
    conf.mkdir(parents=True)
    workspace = paths.project_releases(P) / "incoming"
    tree, manifest = _release(workspace, volumes=[f"{conf}:/etc/app:ro"])
    with pytest.raises(StagingIsolationError, match=f"mounts {conf}, which is production's"):
        precheck_candidate(paths, P, manifest, tree, workspace)
