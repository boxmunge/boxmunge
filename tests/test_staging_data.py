# SPDX-License-Identifier: Apache-2.0
"""Planning and running the production -> staging data copy.

The models are shaped like `docker compose config` output (long syntax,
absolute bind sources). Docker commands are recorded, not run; the copy
itself against real Docker is in tests/integration/test_staging_copy.py.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from boxmunge import staging_data
from boxmunge.docker_run import DockerError
from boxmunge.manifest import validate_manifest
from boxmunge.paths import BoxPaths
from boxmunge.staged_release import new_meta, slot_dir, write_meta
from boxmunge.staging_copy_plan import (
    StagingDataError, Store, copy_sources, plan_copy, stores,
)


def _model(project_dir: Path, volumes: dict[str, str], binds: list[str] = (),
           compose_project: str = "myapp") -> dict:
    mounts = [{"type": "volume", "source": key, "target": f"/{key}"} for key in volumes]
    mounts += [{"type": "bind", "source": str(project_dir / b), "target": f"/b/{b}"}
               for b in binds]
    return {"services": {"web": {"image": "x", "volumes": mounts}},
            "volumes": {k: {"name": f"{compose_project}_{k}"} for k in volumes}}


def _stores(project_dir: Path, volumes=(), binds=(), *, staging=False,
            data=("data", "uploads", ".releases")) -> list[Store]:
    project = "myapp-staging" if staging else "myapp"
    model = _model(project_dir, dict.fromkeys(volumes, ""), binds, project)
    return stores(model, project, project_dir, set(data), staging=staging)


def test_stores_are_production_data_and_staging_copies(tmp_path: Path) -> None:
    prod = _stores(tmp_path, ["pgdata", "myapp_files"],
                   ["data/db", "data", "uploads/img", "appconfig", ".releases/live-mounts/x"])
    assert [(s.kind, s.key, s.ref) for s in prod] == [
        ("bind", "./data", str(tmp_path / "data")),  # data/db lies inside it
        ("bind", "./uploads/img", str(tmp_path / "uploads/img")),
        ("volume", "myapp_files", "myapp_myapp_files"),
        ("volume", "pgdata", "myapp_pgdata"),
    ]
    staging = _stores(tmp_path, ["pgdata"], ["data-staging", "appconfig"], staging=True)
    assert [(s.key, s.ref) for s in staging] == [
        ("./data", str(tmp_path / "data-staging")), ("pgdata", "myapp-staging_pgdata")]


def test_stores_are_paired_by_name(tmp_path: Path) -> None:
    plan = plan_copy(_stores(tmp_path, ["pgdata"], ["data"]),
                     _stores(tmp_path, ["pgdata"], ["data-staging"], staging=True), {}, "myapp")
    assert [(s.ref, d.ref) for s, d in plan.pairs] == [
        (str(tmp_path / "data"), str(tmp_path / "data-staging")),
        ("myapp_pgdata", "myapp-staging_pgdata")]


def test_a_rename_without_a_mapping_is_refused(tmp_path: Path) -> None:
    """Review finding 26: the staged name is not production's store."""
    with pytest.raises(StagingDataError, match=r"sources: \{newdata: proddata\}"):
        plan_copy(_stores(tmp_path, ["myapp_proddata"]),
                  _stores(tmp_path, ["myapp_newdata"], staging=True), {}, "myapp")


def test_a_rename_is_copied_from_the_mapped_production_store(tmp_path: Path) -> None:
    plan = plan_copy(_stores(tmp_path, ["myapp_proddata"]),
                     _stores(tmp_path, ["myapp_newdata"], staging=True),
                     {"newdata": "proddata"}, "myapp")
    assert [(s.ref, d.ref) for s, d in plan.pairs] == [
        ("myapp_myapp_proddata", "myapp-staging_myapp_newdata")]


def test_null_leaves_a_store_uncopied(tmp_path: Path) -> None:
    plan = plan_copy(_stores(tmp_path, ["pgdata", "old"]),
                     _stores(tmp_path, ["pgdata", "cache"], staging=True),
                     {"cache": None}, "myapp")
    assert [d.key for _, d in plan.pairs] == ["pgdata"]
    assert [s.key for s in plan.fresh] == ["cache"]
    assert [s.key for s in plan.unused] == ["old"]


def test_new_stores_need_no_mapping_when_every_production_store_is_copied(tmp_path) -> None:
    plan = plan_copy(_stores(tmp_path, ["pgdata"]),
                     _stores(tmp_path, ["pgdata", "cache"], staging=True), {}, "myapp")
    assert [s.key for s in plan.fresh] == ["cache"]


@pytest.mark.parametrize("sources,match", [
    ({"nosuch": "pgdata"}, "names none of the staged"),
    ({"pgdata": "nosuch"}, "names none of the production"),
    ({"./data": "./nosuch"}, "names none of the production"),
])
def test_unknown_store_names_are_refused(tmp_path: Path, sources, match) -> None:
    with pytest.raises(StagingDataError, match=match):
        plan_copy(_stores(tmp_path, ["pgdata"], ["data"]),
                  _stores(tmp_path, ["pgdata"], ["data-staging"], staging=True),
                  sources, "myapp")


def _manifest(copy_data) -> dict:
    return {"id": "01TESTULID0000000000000000", "project": "myapp", "source": "bundle",
            "hosts": ["myapp.example.com"],
            "services": {"web": {"port": 80, "routes": [{"path": "/"}]}},
            "staging": {"copy_data": copy_data}}


@pytest.mark.parametrize("copy_data,expected", [
    (True, {}), (False, None), ({"sources": {"new": "old", "cache": None}},
                                {"new": "old", "cache": None}),
])
def test_copy_sources_from_the_manifest(copy_data, expected) -> None:
    assert validate_manifest(_manifest(copy_data), "myapp")[0] == []
    assert copy_sources(_manifest(copy_data)) == expected


@pytest.mark.parametrize("copy_data", [
    "yes", {"sources": {}}, {"sources": {"a": 1}}, {"map": {"a": "b"}}, {"sources": ["a"]},
])
def test_malformed_copy_data_is_refused(copy_data) -> None:
    errors, _ = validate_manifest(_manifest(copy_data), "myapp")
    assert any("copy_data" in e for e in errors)


class _Docker:
    """Records docker commands; volumes and containers as the test says."""

    def __init__(self, monkeypatch, volumes=(), running=None) -> None:
        self.calls: list[list[str]] = []
        self.volumes = set(volumes)
        self.running = running or {}
        self.fail_copy = False
        monkeypatch.setattr(staging_data, "_run", self)
        monkeypatch.setattr("boxmunge.data_helper._run", self)
        monkeypatch.setattr("boxmunge.docker._run", self)
        monkeypatch.setattr(staging_data, "_running",
                            lambda project: list(self.running.get(project, [])))
        # The start checks around production's stop and start have their own
        # tests (test_compose_guard, test_root_compose_call_sites).
        self.checks: list[str] = []
        monkeypatch.setattr(staging_data, "check_containers_start",
                            lambda paths, project, component: self.checks.append("before stop"))
        monkeypatch.setattr("boxmunge.compose_guard.check_containers_start",
                            lambda paths, project, component: self.checks.append("before start"))

    def __call__(self, cmd, capture=False, check=True, timeout=None):
        self.calls.append(cmd)
        if cmd[:3] == ["docker", "volume", "inspect"] and cmd[3] not in self.volumes:
            raise DockerError("Error response from daemon: get x: no such volume")
        if cmd[:2] == ["docker", "run"] and self.fail_copy:
            raise DockerError("cp: write error: No space left on device")
        if cmd[:2] == ["docker", "rm"]:
            raise DockerError("Error response from daemon: No such container: x")

        class Done:
            returncode = 0
            stdout = ""
        return Done()

    def verbs(self) -> list[str]:
        return [c[1] for c in self.calls if c[1] != "rm"]


def _plan(tmp_path: Path):
    """A volume and a bind pair of the project under BoxPaths(tmp_path / "bm")."""
    project_dir = BoxPaths(tmp_path / "bm").project_dir("myapp")
    (project_dir / "data").mkdir(parents=True)
    (project_dir / "data-staging").mkdir()
    return plan_copy(_stores(project_dir, ["pgdata"], ["data"]),
                     _stores(project_dir, ["pgdata"], ["data-staging"], staging=True), {},
                     "myapp")


def _slot(paths: BoxPaths, fake_containers, names: list[str]) -> None:
    """A slot to record production's stop in, and the containers it stops
    (the start-again around a copy: tests/test_staging_copy_marker.py)."""
    slot = slot_dir(paths, "myapp")
    (slot / "release").mkdir(parents=True)
    write_meta(slot, new_meta("bundle", "myapp-v2", None))
    for name in names:
        fake_containers.run("myapp", name.split("-")[1], "sha256:1", name=name)


def test_copy_stops_production_around_a_complete_replacement(tmp_path, monkeypatch,
                                                              fake_containers) -> None:
    docker = _Docker(monkeypatch, volumes={"myapp_pgdata", "myapp-staging_pgdata"},
                     running={"myapp": ["myapp-web-1"]})
    paths = BoxPaths(tmp_path / "bm")
    _slot(paths, fake_containers, ["myapp-web-1"])
    staging_data.copy_production_data(paths, "myapp", _plan(tmp_path))
    assert docker.verbs()[-4:] == ["stop", "run", "run", "start"]
    assert docker.checks == ["before stop", "before start"]
    runs = [c for c in docker.calls if c[1] == "run"]
    copy = " ".join(runs[-1])
    assert "type=volume,src=myapp_pgdata,dst=/src,readonly" in copy
    assert "type=volume,src=myapp-staging_pgdata,dst=/dst" in copy
    # Hidden entries are removed too, and the destination proven empty.
    assert "/dst/.[!.]*" in copy and 'ls -A /dst' in copy


def test_a_missing_production_volume_is_never_created(tmp_path, monkeypatch) -> None:
    docker = _Docker(monkeypatch, volumes={"myapp-staging_pgdata"})
    with pytest.raises(StagingDataError, match="myapp_pgdata .* does not exist"):
        staging_data.copy_production_data(BoxPaths(tmp_path / "bm"), "myapp", _plan(tmp_path))
    assert not [c for c in docker.calls if c[1] in ("run", "stop")]


def test_each_copy_container_is_named_and_force_removed(tmp_path, monkeypatch) -> None:
    """An interrupted boxmunge must not leave a copy writing into staging."""
    docker = _Docker(monkeypatch, volumes={"myapp_pgdata", "myapp-staging_pgdata"})
    docker.fail_copy = True
    with pytest.raises(DockerError):
        staging_data.copy_production_data(BoxPaths(tmp_path / "bm"), "myapp", _plan(tmp_path))
    run, rm = docker.calls[-2:]
    name = run[run.index("--name") + 1]
    assert name.startswith("boxmunge-myapp-staging-copy-")
    assert rm == ["docker", "rm", "-f", name]


def test_running_staging_is_refused(tmp_path, monkeypatch) -> None:
    """Review finding 11: never replace data under a running staging DB."""
    docker = _Docker(monkeypatch, volumes={"myapp_pgdata", "myapp-staging_pgdata"},
                     running={"myapp-staging": ["myapp-staging-db-1"]})
    with pytest.raises(StagingDataError, match="myapp-staging-db-1"):
        staging_data.copy_production_data(BoxPaths(tmp_path / "bm"), "myapp", _plan(tmp_path))
    assert docker.calls == []


def test_copies_run_in_the_helper_image(tmp_path, monkeypatch) -> None:
    from boxmunge.data_helper import HELPER_IMAGE
    docker = _Docker(monkeypatch, volumes={"myapp_pgdata", "myapp-staging_pgdata"})
    staging_data.copy_production_data(BoxPaths(tmp_path / "bm"), "myapp", _plan(tmp_path))
    runs = [c for c in docker.calls if c[1] == "run"]
    assert len(runs) == 2
    assert all(HELPER_IMAGE in c and "busybox:1.36" not in c and "--read-only" in c
               for c in runs)


def _file_store_plan(paths: BoxPaths):
    project_dir = paths.project_dir("myapp")
    project_dir.mkdir(parents=True)
    (project_dir / "app.db").write_text("x")
    return project_dir, plan_copy(
        _stores(project_dir, [], ["app.db"], data=["app.db"]),
        _stores(project_dir, [], ["app.db-staging"], staging=True, data=["app.db"]),
        {}, "myapp")


def test_top_level_file_store_is_refused_on_a_remapped_box(tmp_path, monkeypatch) -> None:
    from tests.userns_helpers import remap_box
    paths = BoxPaths(tmp_path / "bm")
    remap_box(paths, monkeypatch)
    project_dir, plan = _file_store_plan(paths)
    docker = _Docker(monkeypatch, running={"myapp": ["myapp-web-1"]})
    with pytest.raises(StagingDataError, match="single-file store ./app.db"):
        staging_data.prepare_destinations(paths, "myapp", plan)
    assert not (project_dir / "app.db-staging").exists()
    with pytest.raises(StagingDataError, match="single-file store ./app.db"):
        staging_data.copy_production_data(paths, "myapp", plan)
    assert not [c for c in docker.calls if c[1] in ("run", "stop")]


def test_top_level_file_store_is_copied_on_an_unremapped_box(tmp_path, monkeypatch) -> None:
    paths = BoxPaths(tmp_path / "bm")
    project_dir, plan = _file_store_plan(paths)
    docker = _Docker(monkeypatch)
    staging_data.prepare_destinations(paths, "myapp", plan)
    assert (project_dir / "app.db-staging").is_file()
    staging_data.copy_production_data(paths, "myapp", plan)
    run, = [c for c in docker.calls if c[1] == "run"]
    assert f"{project_dir / 'app.db'}:/srcroot:ro" in run and f"{project_dir}:/dst" in run
    assert run[-1].endswith("rm -rf /dst/app.db-staging && cp -a \"$s\" /dst/app.db-staging")



def test_an_inconsistent_remap_state_refuses_the_copy(tmp_path, monkeypatch) -> None:
    """A RemapError would escape stage's cleanup as a traceback."""
    from tests.userns_helpers import remap_box
    from tests.userns_helpers import UNREMAPPED_INFO
    paths = BoxPaths(tmp_path / "bm")
    remap_box(paths, monkeypatch)
    monkeypatch.setattr("boxmunge.userns.offset.docker_info", lambda: dict(UNREMAPPED_INFO))
    _project_dir, plan = _file_store_plan(paths)
    _Docker(monkeypatch)
    with pytest.raises(StagingDataError, match="whether the box is remapped.*not remapped"):
        staging_data.prepare_destinations(paths, "myapp", plan)


def test_nested_binds_are_reached_inside_the_helper(tmp_path, monkeypatch) -> None:
    """The daemon follows links in a -v host path as root: only the top
    entries (no container can write the project directory) are mounted,
    and the rest is resolved inside the helper, refusing a link."""
    paths = BoxPaths(tmp_path / "bm")
    project_dir = paths.project_dir("myapp")
    for d in ("data/db", "data-staging/db"):
        (project_dir / d).mkdir(parents=True)
    plan = plan_copy(_stores(project_dir, [], ["data/db"]),
                     _stores(project_dir, [], ["data-staging/db"], staging=True), {}, "myapp")
    docker = _Docker(monkeypatch)
    staging_data.copy_production_data(paths, "myapp", plan)
    run, = [c for c in docker.calls if c[1] == "run"]
    assert f"{project_dir / 'data'}:/srcroot:ro" in run
    assert f"{project_dir / 'data-staging'}:/dst" in run
    script = run[-1]
    assert script.startswith("s=/srcroot/db && ")
    assert "d=/dst/db && " in script
    assert script.count('[ "$(readlink -f "$') == 2
    assert script.endswith('cp -a "$s"/. "$d"/')


def test_a_linked_top_entry_is_refused_before_anything_runs(tmp_path, monkeypatch) -> None:
    paths = BoxPaths(tmp_path / "bm")
    project_dir = paths.project_dir("myapp")
    (project_dir / "data" / "db").mkdir(parents=True)
    (tmp_path / "elsewhere" / "db").mkdir(parents=True)
    plan = plan_copy(_stores(project_dir, [], ["data/db"]),
                     _stores(project_dir, [], ["data-staging/db"], staging=True), {}, "myapp")
    (project_dir / "data-staging").symlink_to(tmp_path / "elsewhere")
    docker = _Docker(monkeypatch, running={"myapp": ["myapp-web-1"]})
    with pytest.raises(StagingDataError, match="data-staging is a symlink"):
        staging_data.copy_production_data(paths, "myapp", plan)
    assert not [c for c in docker.calls if c[1] in ("run", "stop")]

