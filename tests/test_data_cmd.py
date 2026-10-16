# SPDX-License-Identifier: Apache-2.0
"""data adopt: an anonymous volume becomes a Compose-labelled named one."""
from __future__ import annotations

import pytest

from boxmunge import data_helper
from boxmunge.commands import data_cmd

ANON = "a" * 64
DEST = "/var/lib/postgresql/data"


class _Box:
    def __init__(self, monkeypatch, *, running=True, existing=None, mounts=None) -> None:
        self.calls: list = []
        self.existing = existing  # labels of an existing <p>_<name>, or None
        self.empty = True
        monkeypatch.setattr(data_cmd, "container_mounts", lambda p: mounts if mounts is not None
                            else [("myapp-db-1", "db", {"Type": "volume", "Name": ANON,
                                                        "Destination": DEST})])
        monkeypatch.setattr(data_cmd, "volume_labels", self.labels)
        monkeypatch.setattr(data_cmd, "_running",
                            lambda p, s: ["myapp-db-1"] if running else [])
        monkeypatch.setattr(data_cmd, "_run", lambda cmd, **kw: self.calls.append(cmd))
        monkeypatch.setattr(data_cmd, "volume_is_empty", lambda label, name: self.empty)
        monkeypatch.setattr(data_cmd, "copy_into_volume",
                            lambda label, src, dst: self.calls.append(("copy", src, dst)))
        monkeypatch.setattr(data_cmd, "check_containers_start",
                            lambda paths, project, component: self.calls.append(("check",)))
        monkeypatch.setattr(data_cmd, "start_containers_checked",
                            lambda paths, project, names, component:
                            self.calls.append(("start", names)))
        monkeypatch.setattr(data_helper, "_compose_version", lambda: "2.40.0")

    def labels(self, name):
        if name == ANON:
            return {"com.docker.volume.anonymous": ""}
        return self.existing

    def verbs(self) -> list[str]:
        return [c[0] if isinstance(c, tuple) else c[1] for c in self.calls]


def test_adopt_creates_a_labelled_volume_copies_and_restarts(paths, monkeypatch) -> None:
    box = _Box(monkeypatch)
    assert data_cmd.run_data_adopt(paths, "myapp", "db", DEST, "pgdata") == 0
    create = next(c for c in box.calls if c[:3] == ["docker", "volume", "create"])
    assert create[-1] == "myapp_pgdata"
    for label in ("com.docker.compose.project=myapp", "com.docker.compose.volume=pgdata",
                  "com.docker.compose.version=2.40.0"):
        assert label in create
    assert box.verbs() == ["check", "volume", "stop", "copy", "start"]
    assert ("copy", ANON, "myapp_pgdata") in box.calls
    assert ("start", ["myapp-db-1"]) in box.calls


def test_adopt_of_a_stopped_service_starts_nothing(paths, monkeypatch) -> None:
    box = _Box(monkeypatch, running=False)
    data_cmd.adopt_locked(paths, "myapp", "db", DEST, "pgdata")
    assert box.verbs() == ["volume", "copy"]


def test_adopt_reuses_an_empty_volume_compose_labelled(paths, monkeypatch) -> None:
    box = _Box(monkeypatch, existing={"com.docker.compose.project": "myapp",
                                      "com.docker.compose.volume": "pgdata"})
    data_cmd.adopt_locked(paths, "myapp", "db", DEST, "pgdata")
    assert "volume" not in box.verbs() and ("copy", ANON, "myapp_pgdata") in box.calls


def test_adopt_refuses_a_non_empty_existing_target(paths, monkeypatch) -> None:
    box = _Box(monkeypatch, existing={"com.docker.compose.project": "myapp",
                                      "com.docker.compose.volume": "pgdata"})
    box.empty = False
    with pytest.raises(data_cmd.DataError, match="already exists and holds data"):
        data_cmd.adopt_locked(paths, "myapp", "db", DEST, "pgdata")
    assert box.calls == []


def test_adopt_refuses_an_existing_volume_compose_did_not_label(paths, monkeypatch) -> None:
    box = _Box(monkeypatch, existing={})
    with pytest.raises(data_cmd.DataError, match="not labelled for Compose"):
        data_cmd.adopt_locked(paths, "myapp", "db", DEST, "pgdata")
    assert box.calls == []


def test_adopt_refuses_a_named_volume(paths, monkeypatch) -> None:
    box = _Box(monkeypatch)
    monkeypatch.setattr(data_cmd, "volume_labels", lambda n: {
        "com.docker.compose.project": "myapp", "com.docker.compose.volume": "x"})
    with pytest.raises(data_cmd.DataError, match="already a named volume"):
        data_cmd.adopt_locked(paths, "myapp", "db", DEST, "pgdata")
    assert box.calls == []


def test_adopt_refuses_a_path_with_no_volume(paths, monkeypatch) -> None:
    _Box(monkeypatch)
    with pytest.raises(data_cmd.DataError, match="no volume mounted at /data"):
        data_cmd.adopt_locked(paths, "myapp", "db", "/data", "pgdata")


def test_adopt_refuses_several_replicas(paths, monkeypatch) -> None:
    mount = {"Type": "volume", "Destination": DEST}
    _Box(monkeypatch, mounts=[("myapp-db-1", "db", {**mount, "Name": ANON}),
                              ("myapp-db-2", "db", {**mount, "Name": "b" * 64})])
    with pytest.raises(data_cmd.DataError, match="several volumes"):
        data_cmd.adopt_locked(paths, "myapp", "db", DEST, "pgdata")


def test_adopt_restarts_the_service_even_when_the_copy_fails(paths, monkeypatch) -> None:
    box = _Box(monkeypatch)

    def boom(label, src, dst):
        raise data_cmd.DockerError("cp: no space")
    monkeypatch.setattr(data_cmd, "copy_into_volume", boom)
    with pytest.raises(data_cmd.DockerError):
        data_cmd.adopt_locked(paths, "myapp", "db", DEST, "pgdata")
    assert box.calls[-1] == ("start", ["myapp-db-1"])


@pytest.mark.parametrize("name", ["", "Pg", "a/b", "-x", "x" * 64, "a b"])
def test_adopt_refuses_bad_volume_names(paths, monkeypatch, name) -> None:
    box = _Box(monkeypatch)
    with pytest.raises(data_cmd.DataError, match="volume name"):
        data_cmd.adopt_locked(paths, "myapp", "db", DEST, name)
    assert box.calls == []


def test_errors_are_reported_not_raised(paths, monkeypatch, capsys) -> None:
    _Box(monkeypatch, existing={})
    assert data_cmd.run_data_adopt(paths, "myapp", "db", DEST, "pgdata") == 1
    assert "not labelled for Compose" in capsys.readouterr().err


@pytest.mark.parametrize("args", [
    [], ["chown"], ["adopt", "myapp", "db", "pgdata"], ["adopt", "myapp", "db:data", "pgdata"],
    ["adopt", "myapp", ":/data", "pgdata"]])
def test_cli_refuses_malformed_forms(args) -> None:
    with pytest.raises(SystemExit) as e:
        data_cmd.cmd_data(args)
    assert e.value.code == 2


@pytest.mark.parametrize("labels, name, anonymous", [
    ({"com.docker.volume.anonymous": ""}, "x", True),
    ({}, "a" * 64, True),
    (None, "a" * 64, True),
    ({"com.docker.compose.volume": "data"}, "a" * 64, False),
    ({}, "pgdata", False),
])
def test_is_anonymous(labels, name, anonymous) -> None:
    assert data_helper.is_anonymous(labels, name) is anonymous


def test_a_failed_restart_says_the_service_is_down(paths, monkeypatch, capsys) -> None:
    _Box(monkeypatch)

    def down(paths, project, names, component):
        raise data_cmd.DockerError("Cannot connect to the Docker daemon")
    monkeypatch.setattr(data_cmd, "start_containers_checked", down)
    assert data_cmd.run_data_adopt(paths, "myapp", "db", DEST, "pgdata") == 1
    err = capsys.readouterr().err
    assert "SERVICE db IS DOWN" in err and "docker start myapp-db-1" in err


def test_compose_labels_need_a_valid_compose_project(monkeypatch) -> None:
    monkeypatch.setattr(data_helper, "_compose_version", lambda: "2.40.0")
    assert data_helper.compose_volume_labels("myapp", "pgdata")[:2] == [
        "--label", "com.docker.compose.project=myapp"]
    with pytest.raises(ValueError):
        data_helper.compose_volume_labels("../other", "pgdata")
