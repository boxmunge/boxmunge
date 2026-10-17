"""data chown: the one deliberate change of a service's data ownership."""
from __future__ import annotations

import pytest

from boxmunge.commands import data_cmd
from boxmunge.run_as import ServiceUser, read_users, write_users


def _setup(paths, monkeypatch, volumes_exist=True):
    calls = []
    project_dir = paths.project_dir("shop")
    (project_dir / "uploads").mkdir(parents=True)
    services = {"app": {"volumes": [
        {"type": "bind", "source": str(project_dir / "uploads"), "target": "/u"},
        {"type": "bind", "source": str(project_dir / "conf"), "target": "/c", "read_only": True},
        {"type": "bind", "source": str(project_dir / "never-made"), "target": "/n"},
        {"type": "volume", "source": "cache", "target": "/cache"}]}}
    monkeypatch.setattr(data_cmd, "resolved_services", lambda target: ({}, services))
    monkeypatch.setattr(data_cmd, "_running", lambda p, s: ["shop-app-1"])
    monkeypatch.setattr(data_cmd, "_run", lambda cmd, **kw: calls.append(cmd))
    monkeypatch.setattr(data_cmd, "volume_labels", lambda n: {} if volumes_exist else None)
    monkeypatch.setattr(data_cmd, "run_helper", lambda label, mounts, script:
                        calls.append((mounts[1], script)))
    monkeypatch.setattr(data_cmd, "chown_under", lambda label, root, rel, ids:
                        calls.append((f"{root}:{rel}", ids)))
    return project_dir, calls


def test_chown_stops_chowns_every_persistent_mount_and_records(paths, monkeypatch) -> None:
    project_dir, calls = _setup(paths, monkeypatch)
    write_users(paths, "shop", {"app": ServiceUser(None, "image", "node"),
                                "db": ServiceUser(None, "manifest")})
    data_cmd.chown_locked(paths, "shop", "app", (10001, 10001))
    assert calls[0][:2] == ["docker", "stop"]
    assert calls[1:] == [(f"{project_dir}:uploads", (10001, 10001)),
                         ("type=volume,src=shop_cache,dst=/x", "chown -R -h 10001:10001 /x")]
    users = read_users(paths, "shop")
    assert users["app"] == ServiceUser("10001:10001", "data-chown", "node")
    assert users["db"] == ServiceUser(None, "manifest")
    assert not (project_dir / "never-made").exists()


def test_a_volume_not_yet_created_is_not_created(paths, monkeypatch) -> None:
    _project_dir, calls = _setup(paths, monkeypatch, volumes_exist=False)
    data_cmd.chown_locked(paths, "shop", "app", (10001, 10001))
    assert [c for c in calls if isinstance(c, tuple) and c[0].startswith("type=volume")] == []


def test_a_bind_reached_through_a_link_is_refused(paths, monkeypatch, tmp_path) -> None:
    from boxmunge.bind_sources import BindSourceError
    project_dir, calls = _setup(paths, monkeypatch)
    (project_dir / "uploads").rmdir()
    (project_dir / "uploads").symlink_to(tmp_path)
    with pytest.raises(BindSourceError, match="symlink"):
        data_cmd.chown_locked(paths, "shop", "app", (10001, 10001))
    assert [c for c in calls if isinstance(c, tuple)] == []


def test_a_service_without_data_is_refused(paths, monkeypatch, capsys) -> None:
    monkeypatch.setattr(data_cmd, "resolved_services", lambda target: ({}, {"app": {}}))
    assert data_cmd.run_data_chown(paths, "shop", "app", "10001:10001") == 1
    assert "nothing to chown" in capsys.readouterr().err


@pytest.mark.parametrize("spec", ["0:0", "10001", "70000:1", "a:b", "1:0"])
def test_bad_ids_are_refused(paths, spec) -> None:
    assert data_cmd.run_data_chown(paths, "shop", "app", spec) == 2


def test_a_bind_inside_another_containers_rw_bind_is_refused(paths, monkeypatch) -> None:
    project_dir, calls = _setup(paths, monkeypatch)
    monkeypatch.setattr("boxmunge.docker_containers.container_bind_sources",
                        lambda p: [(str(project_dir), True)] if p == "shop" else [])
    with pytest.raises(data_cmd.DataError, match="mounts read-write"):
        data_cmd.chown_locked(paths, "shop", "app", (10001, 10001))
