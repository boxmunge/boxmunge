"""Storage before the first start: helper-made bind sources, fresh volume roots."""
from __future__ import annotations

import pytest

from boxmunge.bind_sources import BindSourceError
from boxmunge.commands import deploy_storage as ds
from boxmunge.docker_containers import ImageFacts
from boxmunge.image_probe import DirOwner
from boxmunge.release_target import production_target
from boxmunge.run_as import ServiceUser, write_users

S = 1048576


def _setup(paths, monkeypatch, *, offset=0, existing=frozenset(), probe=None, model=None,
           volumes=None):
    calls = []
    project_dir = paths.project_dir("shop")
    project_dir.mkdir(parents=True, exist_ok=True)
    services = {"app": {"build": ".", "image": "boxmunge.invalid/shop/app", "volumes": volumes or [
        {"type": "bind", "source": str(project_dir / "data" / "uploads"), "target": "/u"},
        {"type": "bind", "source": str(project_dir / "conf"), "target": "/c", "read_only": True},
        {"type": "volume", "source": "cache", "target": "/cache"}]}}
    monkeypatch.setattr(ds, "resolved_services", lambda target: (model or {}, services))
    monkeypatch.setattr(ds, "remap_offset", lambda paths: offset)
    monkeypatch.setattr(ds, "run_helper", lambda label, mounts, script: calls.append((mounts, script)))
    monkeypatch.setattr(ds, "mkdir_under", lambda label, root, rel, ids:
                        calls.append(("mkdir", root, str(rel), ids)))
    monkeypatch.setattr(ds, "volume_labels", lambda name: {} if name in existing else None)
    monkeypatch.setattr(ds, "image_facts", lambda ref: ImageFacts("sha256:" + "a" * 64, "", ()))
    monkeypatch.setattr(ds, "probe_dir", lambda image, path, off: probe)
    monkeypatch.setattr(ds, "_run", lambda cmd, capture=False: calls.append(cmd))
    monkeypatch.setattr(ds, "compose_volume_labels", lambda cp, key: ["--label", f"k={key}"])
    write_users(paths, "shop", {"app": ServiceUser("10001:10001", "default")})
    return production_target(paths, "shop"), calls


def test_missing_rw_source_is_made_by_the_daemon_and_given_to_the_user(paths, monkeypatch) -> None:
    target, calls = _setup(paths, monkeypatch)
    ds.prepare_storage(paths, target)
    assert calls[0] == ("mkdir", paths.project_dir("shop"), "data/uploads", (10001, 10001))
    assert (paths.project_dir("shop") / "data").is_dir()  # parents as deploy
    assert not (paths.project_dir("shop") / "conf").exists()  # read-only: the start check makes it


def test_a_parent_reached_through_a_link_is_refused(paths, monkeypatch, tmp_path) -> None:
    target, calls = _setup(paths, monkeypatch)
    (paths.project_dir("shop") / "data").symlink_to(tmp_path)
    with pytest.raises(BindSourceError, match="symlink"):
        ds.prepare_storage(paths, target)
    assert calls == []


def test_a_source_the_v_syntax_would_misread_is_refused(paths, monkeypatch) -> None:
    project_dir = paths.project_dir("shop")
    target, calls = _setup(paths, monkeypatch, offset=S, volumes=[
        {"type": "bind", "source": str(project_dir / "a:b"), "target": "/u"}])
    with pytest.raises(BindSourceError, match="misread"):
        ds.prepare_storage(paths, target)


def test_fresh_imageless_volume_is_created_labelled_and_chowned_once(paths, monkeypatch) -> None:
    target, calls = _setup(paths, monkeypatch)
    ds.prepare_storage(paths, target)
    create = next(c for c in calls if isinstance(c, list) and c[:3] == ["docker", "volume", "create"])
    assert create[-1] == "shop_cache" and "k=cache" in create
    assert (["--mount", "type=volume,src=shop_cache,dst=/x"], "chown 10001:10001 /x") in calls


@pytest.mark.parametrize("kwargs", [
    {"existing": {"shop_cache"}},
    {"probe": DirOwner(10001, 10001, 0o755, True)},
    {"model": {"volumes": {"cache": {"external": True, "name": "cache"}}}},
])
def test_existing_external_or_image_owned_volume_is_left_alone(paths, monkeypatch, kwargs) -> None:
    target, calls = _setup(paths, monkeypatch, **kwargs)
    ds.prepare_storage(paths, target)
    assert not [c for c in calls if isinstance(c, tuple) and "src=shop_cache" in str(c)]
    assert not [c for c in calls if isinstance(c, list)]


def test_root_service_on_unremapped_box_keeps_the_start_checks_creation(paths, monkeypatch) -> None:
    target, calls = _setup(paths, monkeypatch)
    write_users(paths, "shop", {"app": ServiceUser("0:0", "manifest")})
    ds.prepare_storage(paths, target)
    assert calls == []


def test_remapped_box_makes_rw_sources_through_the_helper_even_for_root(paths, monkeypatch) -> None:
    target, calls = _setup(paths, monkeypatch, offset=S)
    write_users(paths, "shop", {"app": ServiceUser("0:0", "manifest")})
    ds.prepare_storage(paths, target)
    assert calls == [(["-v", f"{paths.project_dir('shop') / 'data' / 'uploads'}:/x"], "true")]


def test_a_source_inside_a_containers_rw_bind_is_refused(paths, monkeypatch) -> None:
    """An old release's container mounting ./data read-write could swap
    data/uploads for a link before the helper makes it."""
    target, calls = _setup(paths, monkeypatch)
    data = paths.project_dir("shop") / "data"
    monkeypatch.setattr("boxmunge.docker_containers.container_bind_sources",
                        lambda p: [(str(data), True)] if p == "shop" else [])
    with pytest.raises(BindSourceError, match="mounts read-write"):
        ds.prepare_storage(paths, target)
    assert calls == []
