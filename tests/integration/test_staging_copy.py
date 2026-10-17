# SPDX-License-Identifier: Apache-2.0
"""staging.copy_data against real Docker: volumes, bind dirs, re-stage.

Codebase review findings 11 and 26. Production and staging really run (a
busybox "database" that never stops by itself, no network). Re-staging
must take the running staging down before its data is replaced, copy into
a destination emptied of hidden files too, and start staging only after
the copy. A store the staged release renames is refused until the manifest
says where its data comes from, and then copied from production's store.
"""
from __future__ import annotations

import shutil
import subprocess
import uuid
from contextlib import contextmanager
from unittest.mock import patch

import pytest
import yaml

from boxmunge import docker_containers
from boxmunge.commands import stage_cmd
from boxmunge.commands.deploy import run_deploy
from boxmunge.commands.stage_cmd import run_stage
from boxmunge.commands.unstage_cmd import run_unstage
from boxmunge.project_registry import add_project
from tests.bundle_helpers import manifest_text, place_bundle
from tests.integration.docker_images import BUSYBOX, docker, ensure_busybox

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which("docker") is None, reason="docker CLI not on PATH"),
    # Copies, placeholders and cleanup run in the data helper.
    pytest.mark.usefixtures("helper_image"),
]

_DB = ["sh", "-c", "trap 'exit 0' TERM; while :; do sleep 1; done"]


def _release(project: str, volume: str, sources: dict | None = None) -> dict[str, str]:
    manifest = yaml.safe_load(manifest_text(project))
    manifest["schema_version"] = 3
    manifest["services"] = {"db": {"internal": True, "writable": {"external": True}}}
    manifest["staging"] = {"copy_data": {"sources": sources} if sources else True}
    compose = {
        "services": {"db": {"image": BUSYBOX, "command": _DB, "network_mode": "none",
                            "volumes": [f"{volume}:/pg", "./data:/data"]}},
        "volumes": {volume: {}},
    }
    return {"manifest.yml": yaml.safe_dump(manifest), "compose.yml": yaml.safe_dump(compose),
            "data/.keep": ""}


def _remove_project(compose_project: str) -> None:
    label = f"label=com.docker.compose.project={compose_project}"
    for kind, ls in (("container", ["ps", "-aq"]), ("volume", ["volume", "ls", "-q"]),
                     ("network", ["network", "ls", "-q"])):
        ids = docker(*ls, "--filter", label).split()
        if ids:
            rm = ["rm", "-f"] if kind == "container" else [kind, "rm"]
            subprocess.run(["docker", *rm, *ids], capture_output=True, check=False)


@pytest.fixture
def project(paths):
    ensure_busybox()
    name = f"bmcp{uuid.uuid4().hex[:8]}"
    add_project(name, paths)
    yield name
    _remove_project(f"{name}-staging")
    _remove_project(name)


@contextmanager
def _no_caddy():
    with patch("boxmunge.commands.deploy.caddy_reload"), \
            patch("boxmunge.commands.stage_cmd.caddy_reload"), \
            patch("boxmunge.commands.unstage_cmd.caddy_reload"):
        yield


def _sh(volume: str, script: str) -> str:
    return docker("run", "--rm", "--network", "none", "-v", f"{volume}:/v", BUSYBOX,
                  "sh", "-c", script)


def _running(compose_project: str) -> list[str]:
    return sorted(c.service for c in docker_containers.project_containers(compose_project)
                  if c.running)


def test_restage_replaces_quiescent_staging_data_completely(paths, project) -> None:
    pdir = paths.project_dir(project)
    stage = f"{project}-staging"
    for ts in ("2026-10-13T090000000000", "2026-10-13T100000000000",
               "2026-10-13T110000000000"):
        place_bundle(paths, project, ts, _release(project, "pgdata"))
    with _no_caddy():
        assert run_deploy(project, paths, ref="2026-10-13T090000000000") == 0
        _sh(f"{project}_pgdata", "echo v1 > /v/rows")
        (pdir / "data" / "upload").write_text("v1")
        assert run_stage(project, paths, ref="2026-10-13T100000000000") == 0
    assert _running(stage) == ["db"]
    assert _sh(f"{stage}_pgdata", "cat /v/rows") == "v1"
    assert (pdir / "data-staging" / "upload").read_text() == "v1"

    # Staging's database writes its own state, hidden files included.
    docker("exec", f"{stage}-db-1", "sh", "-c", "echo stale > /pg/.wal; echo x > /pg/extra")
    (pdir / "data-staging" / ".cache").write_text("stale")
    _sh(f"{project}_pgdata", "echo v2 > /v/rows")
    (pdir / "data" / "upload").write_text("v2")

    seen_running: list[list[str]] = []
    real_copy = stage_cmd.copy_production_data

    def copy(paths_, project_name, plan, **kwargs):
        seen_running.append(_running(stage))
        real_copy(paths_, project_name, plan, **kwargs)

    with _no_caddy(), patch("boxmunge.commands.stage_cmd.copy_production_data", copy):
        assert run_stage(project, paths, ref="2026-10-13T110000000000") == 0
    assert seen_running == [[]]  # staging was down while its data was replaced
    assert _running(stage) == ["db"] and _running(project) == ["db"]
    assert _sh(f"{stage}_pgdata", "ls -A /v; cat /v/rows").split() == ["rows", "v2"]
    assert sorted(p.name for p in (pdir / "data-staging").iterdir()) == ["upload"]
    assert (pdir / "data-staging" / "upload").read_text() == "v2"


def test_a_renamed_volume_is_copied_only_with_a_mapping(paths, project, capsys) -> None:
    stage = f"{project}-staging"
    place_bundle(paths, project, "2026-10-13T090000000000", _release(project, "pgdata"))
    place_bundle(paths, project, "2026-10-13T100000000000", _release(project, "newdata"))
    place_bundle(paths, project, "2026-10-13T110000000000",
                 _release(project, "newdata", {"newdata": "pgdata"}))
    with _no_caddy():
        assert run_deploy(project, paths, ref="2026-10-13T090000000000") == 0
        _sh(f"{project}_pgdata", "echo prod > /v/rows")
        assert run_stage(project, paths, ref="2026-10-13T100000000000") == 1
        assert "copy_data: {sources: {newdata: pgdata}}" in capsys.readouterr().err
        assert _running(stage) == []
        assert run_stage(project, paths, ref="2026-10-13T110000000000") == 0
    assert _sh(f"{stage}_newdata", "cat /v/rows") == "prod"
    assert docker("volume", "ls", "-q", "--filter", f"name={project}_newdata") == ""


def test_unstage_removes_staging_copies_production_does_not_mount(paths, project) -> None:
    pdir = paths.project_dir(project)
    v2 = _release(project, "pgdata")
    v2["compose.yml"] = v2["compose.yml"].replace("./data:/data", "./media:/data")
    v2["manifest.yml"] = v2["manifest.yml"].replace("copy_data: true", "copy_data:\n    sources: {pgdata: pgdata, ./media: null}")
    v2.pop("data/.keep")
    place_bundle(paths, project, "2026-10-13T090000000000", _release(project, "pgdata"))
    place_bundle(paths, project, "2026-10-13T100000000000", v2)
    with _no_caddy():
        assert run_deploy(project, paths, ref="2026-10-13T090000000000") == 0
        assert run_stage(project, paths, ref="2026-10-13T100000000000") == 0
        docker("exec", f"{project}-staging-db-1", "sh", "-c", "echo s > /data/.f")
        assert (pdir / "media-staging" / ".f").exists()
        (pdir / "data-staging").mkdir(exist_ok=True)
        (pdir / "data-staging" / "kept").write_text("staging's own")
        assert run_unstage(project, paths) == 0
    assert not (pdir / "media-staging").exists()   # only the unstaged release used it
    assert (pdir / "data-staging" / "kept").exists()  # production mounts ./data


def test_production_runs_again_after_a_signal_while_it_stops(paths, project) -> None:
    """Review of PR #65: SIGTERM during `docker stop` left production down."""
    from boxmunge import staging_data
    from boxmunge.termination import Terminated

    place_bundle(paths, project, "2026-10-13T090000000000", _release(project, "pgdata"))
    place_bundle(paths, project, "2026-10-13T100000000000", _release(project, "pgdata"))
    real_run = staging_data._run

    def run(cmd, **kwargs):
        result = real_run(cmd, **kwargs)
        if cmd[:2] == ["docker", "stop"]:
            raise Terminated(15)
        return result

    with _no_caddy():
        assert run_deploy(project, paths, ref="2026-10-13T090000000000") == 0
        with patch.object(staging_data, "_run", run), pytest.raises(Terminated):
            run_stage(project, paths, ref="2026-10-13T100000000000")
    assert _running(project) == ["db"]
    assert _running(f"{project}-staging") == []


def _with_config(release: dict[str, str], copy_data: bool) -> dict[str, str]:
    """The service reads a config file kept in production's data directory."""
    compose = yaml.safe_load(release["compose.yml"])
    compose["services"]["db"]["configs"] = ["key"]
    compose["configs"] = {"key": {"file": "./data/key.pem"}}
    manifest = yaml.safe_load(release["manifest.yml"])
    if not copy_data:
        manifest.pop("staging")
    return {**release, "compose.yml": yaml.safe_dump(compose),
            "manifest.yml": yaml.safe_dump(manifest)}


def test_a_config_file_in_a_read_write_data_directory_is_refused(paths, project, capsys) -> None:
    """A config file inside a directory a service mounts read-write could be
    swapped by that container for a symlink to any host file, which Docker
    would mount on the container's next start (a restart by its policy
    included, which no boxmunge check sees). The deploy refuses it, before
    anything is installed (PR #67 nesting rule)."""
    pdir = paths.project_dir(project)
    (pdir / "data").mkdir(parents=True)
    (pdir / "data" / "key.pem").write_text("production key")
    release = _with_config(_release(project, "pgdata"), copy_data=True)
    place_bundle(paths, project, "2026-10-13T090000000000", release)
    with _no_caddy():
        assert run_deploy(project, paths, ref="2026-10-13T090000000000") == 3
    err = capsys.readouterr().err
    assert "configs key" in err and "lies inside" in err
    assert "keep a secrets/configs file outside every directory" in err
    assert not docker("ps", "-aq", "--filter",
                      f"label=com.docker.compose.project={project}").strip()


def _with_file_store(release: dict[str, str], source: str) -> dict[str, str]:
    compose = yaml.safe_load(release["compose.yml"])
    compose["services"]["db"]["volumes"].append(f"{source}:/files/app.db")
    return {**release, "compose.yml": yaml.safe_dump(compose)}


@pytest.mark.parametrize("source,staged", [
    ("./app.db", "app.db-staging"), ("./store/app.db", "store-staging/app.db"),
], ids=["top-level", "nested"])
def test_a_single_file_data_store_is_copied_as_a_file(paths, project, capsys,
                                                      source, staged) -> None:
    """Review of PR #65: the placeholder for a top-level file store was made
    as a directory, and that leftover broke every later stage."""
    pdir = paths.project_dir(project)
    (pdir / source).parent.mkdir(parents=True, exist_ok=True)
    (pdir / source).write_text("production rows")
    release = _with_file_store(_release(project, "pgdata"), source)
    for ts in ("2026-10-13T090000000000", "2026-10-13T100000000000",
               "2026-10-13T110000000000"):
        place_bundle(paths, project, ts, release)
    with _no_caddy():
        assert run_deploy(project, paths, ref="2026-10-13T090000000000") == 0
        assert run_stage(project, paths, ref="2026-10-13T100000000000") == 0
        assert (pdir / staged).is_file()
        assert docker("exec", f"{project}-staging-db-1", "cat", "/files/app.db") == \
            "production rows"
        # A wrong-type leftover (as the bug left) is replaced, and said so.
        assert run_unstage(project, paths) == 0
        if (pdir / staged).exists():
            _sh_rm = ["run", "--rm", "--network", "none", "-v", f"{pdir}:/p", BUSYBOX,
                      "rm", "-rf", f"/p/{staged}"]
            docker(*_sh_rm)
        (pdir / staged).mkdir(parents=True)
        capsys.readouterr()
        assert run_stage(project, paths, ref="2026-10-13T110000000000") == 0
    assert "is a directory, but production's" in capsys.readouterr().out
    assert (pdir / staged).is_file()
    assert docker("exec", f"{project}-staging-db-1", "cat", "/files/app.db") == \
        "production rows"
