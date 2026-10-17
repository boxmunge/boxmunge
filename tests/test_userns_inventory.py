"""Inventory classification and the canned-Docker inventory."""
from __future__ import annotations

import json

import pytest

from boxmunge.userns import inventory as inv_mod
from boxmunge.userns.inventory import Inventory, classify, take_inventory


@pytest.mark.parametrize("mount, name, kind", [
    ({"Type": "bind", "Source": "{p}/shop/uploads", "RW": True}, "shop-app-1", "data"),
    ({"Type": "bind", "Source": "{p}/shop/conf", "RW": False}, "shop-app-1", "readable"),
    ({"Type": "bind", "Source": "{p}", "RW": True}, "shop-app-1", "refuse"),
    ({"Type": "bind", "Source": "{c}/Caddyfile", "RW": False}, "boxmunge-caddy", "platform"),
    ({"Type": "bind", "Source": "{c}/logs", "RW": True}, "boxmunge-caddy", "refuse"),
    ({"Type": "bind", "Source": "{p}", "RW": True}, "boxmunge-system", "system"),
    ({"Type": "bind", "Source": "/etc", "RW": False}, "shop-app-1", "refuse"),
    ({"Type": "volume", "Name": "x"}, "shop-app-1", "volume"),
    ({"Type": "tmpfs"}, "shop-app-1", "tmpfs"),
    ({"Type": "npipe"}, "shop-app-1", "refuse"),
])
def test_classify(paths, mount, name, kind) -> None:
    mount = {**mount, "Source": mount.get("Source", "").format(p=paths.projects, c=paths.caddy)}
    assert classify(mount, name, paths) == kind


def _docker(paths, tmp_path):
    full, empty, loose = (tmp_path / v for v in ("full", "empty", "loose"))
    for d in (full, empty, loose):
        d.mkdir()
    (full / "row").write_text("42")
    (loose / "f").write_text("x")
    containers = [
        {"Id": "c1", "Name": "/shop-db-1", "Image": "sha256:img", "State": {"Running": False},
         "Config": {"Image": "postgres:16@sha256:" + "f" * 64,
                    "Labels": {"com.docker.compose.project": "shop",
                               "com.docker.compose.service": "db"}},
         "HostConfig": {}, "Mounts": [
             {"Type": "volume", "Name": "a" * 64, "Destination": "/var/lib/postgresql/data", "RW": True},
             {"Type": "bind", "Source": f"{paths.projects}/shop/uploads/", "Destination": "/u",
              "RW": True}]},
    ]
    volumes = [
        {"Name": "a" * 64, "Driver": "local", "Labels": {"com.docker.volume.anonymous": ""},
         "Mountpoint": str(full), "Options": None},
        {"Name": "shop_cache", "Driver": "local", "Labels": {"com.docker.compose.volume": "cache"},
         "Mountpoint": str(empty), "Options": None},
        {"Name": "old_data", "Driver": "local", "Labels": None, "Mountpoint": str(loose), "Options": {}},
    ]

    def run(cmd, capture=False, timeout=None):
        class R:
            stdout = ""
        r = R()
        if cmd[:3] == ["docker", "ps", "-aq"]:
            r.stdout = "c1\n"
        elif cmd[:3] == ["docker", "volume", "ls"]:
            r.stdout = "\n".join(v["Name"] for v in volumes)
        elif cmd[:3] == ["docker", "image", "ls"]:
            assert "-a" in cmd
            r.stdout = "sha256:img\nsha256:loose\nsha256:img\n"
        elif cmd[:3] == ["docker", "network", "ls"]:
            r.stdout = "b0\nb1\nb2\n" if "driver=bridge" in cmd else "n1\n"
        elif cmd[:3] == ["docker", "network", "inspect"]:
            if cmd[3:] == ["b0", "b1", "b2"]:
                r.stdout = json.dumps([
                    {"Name": "bridge", "Id": "b0" * 32},
                    {"Name": "boxmunge-proxy", "Id": "0123456789ab" + "f" * 52, "Options": None},
                    {"Name": "shop_default", "Id": "e" * 64,
                     "Options": {"com.docker.network.bridge.name": "br-shop"}}])
            else:
                r.stdout = json.dumps([{"Driver": "bridge", "IPAM": {"Config": [
                    {"Subnet": "172.30.0.0/16"}]}, "Options": None, "Labels": {}}])
        elif cmd[:3] == ["docker", "container", "inspect"]:
            r.stdout = json.dumps(containers)
        elif cmd[:3] == ["docker", "volume", "inspect"]:
            r.stdout = json.dumps(volumes)
        elif cmd[:3] == ["docker", "image", "inspect"]:
            assert cmd[3:] == ["sha256:img", "sha256:loose"]
            r.stdout = json.dumps([{"Id": "sha256:img", "Size": 10,
                                    "RepoTags": ["postgres:16", "postgres@sha256:" + "f" * 64]},
                                   {"Id": "sha256:loose", "RepoTags": None, "Size": 5}])
        else:
            raise AssertionError(cmd)
        return r
    return run


def _info(monkeypatch, **info) -> None:
    monkeypatch.setattr(inv_mod, "docker_info", lambda: {
        "Driver": "overlayfs", "DriverStatus": [["driver-type", "io.containerd.snapshotter.v1"]],
        "DockerRootDir": "/var/lib/docker", "ServerVersion": "29.9.0", **info})


def test_inventory_from_docker(paths, tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(inv_mod, "_run", _docker(paths, tmp_path))
    _info(monkeypatch)
    monkeypatch.setattr(inv_mod, "load_registered_projects", lambda p: {"shop"})
    inv = take_inventory(paths)
    assert (inv.driver, inv.driver_type) == ("overlayfs", inv_mod.CONTAINERD_STORE)
    by_name = {v.name: v for v in inv.volumes}
    assert by_name["a" * 64].anonymous and by_name["a" * 64].has_data and by_name["a" * 64].attached
    assert not by_name["shop_cache"].anonymous and not by_name["shop_cache"].has_data
    assert not by_name["old_data"].anonymous and not by_name["old_data"].attached
    assert inv.containers[0].mounts[0].kind == "anonymous"
    assert inv.data_binds() == [f"{paths.projects}/shop/uploads"]  # normalised
    assert [i.in_use for i in inv.images] == [True, False]
    assert inv.images[0].refs == ["postgres:16@sha256:" + "f" * 64] and inv.images[0].carried
    assert inv.images[0].tags == ["postgres:16"]  # the containerd store's name@digest is no tag
    assert not inv.images[1].carried
    assert inv.network["ipam"]["Config"] == [{"Subnet": "172.30.0.0/16"}]
    assert inv.bridges == ["br-0123456789ab", "br-shop"]  # docker0 is every daemon's
    assert Inventory.from_json(json.loads(json.dumps(inv.to_json()))) == inv


def test_recorded_data_no_container_mounts_is_carried(paths, tmp_path, monkeypatch) -> None:
    project = paths.project_dir("shop")
    (project / "media").mkdir(parents=True)
    (project / "media" / "row").write_text("42")  # data a stopped service left
    (project / "media-staging").mkdir()
    (project / "uploads-staging").mkdir()  # the copy of the mounted uploads
    (project / "compose.yml").write_text("services:\n  app:\n    image: x\n")
    (project / ".releases").mkdir()
    (project / ".releases" / "data-dirs.json").write_text(
        json.dumps({"version": 1, "data_dirs": ["media", "gone"]}))
    monkeypatch.setattr(inv_mod, "_run", _docker(paths, tmp_path))
    _info(monkeypatch)
    monkeypatch.setattr(inv_mod, "load_registered_projects", lambda p: {"shop"})
    assert take_inventory(paths).data_binds() == [
        str(project / "media"), str(project / "media-staging"),
        f"{paths.projects}/shop/uploads", str(project / "uploads-staging")]


def test_running_state_survives_a_reinventory_after_quiesce(paths, tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(inv_mod, "_run", _docker(paths, tmp_path))
    _info(monkeypatch, Driver="overlay2", DriverStatus=[])
    monkeypatch.setattr(inv_mod, "load_registered_projects", lambda p: {"shop"})
    earlier = take_inventory(paths)
    earlier.containers[0].running = True
    later = take_inventory(paths).with_running_from(earlier)
    assert later.containers[0].running and later.driver_type == ""


def test_containers_removed_since_are_kept_for_the_bring_up(paths, tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(inv_mod, "_run", _docker(paths, tmp_path))
    _info(monkeypatch, Driver="overlay2", DriverStatus=[])
    monkeypatch.setattr(inv_mod, "load_registered_projects", lambda p: {"shop"})
    earlier = take_inventory(paths)
    earlier.containers[0].running = True
    later = Inventory("overlay2", "", "/v", "29.9.0").with_running_from(earlier)
    assert [(c.id, c.running) for c in later.containers] == [("c1", True)]
