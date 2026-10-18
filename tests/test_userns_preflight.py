"""Phase 0: each refusal lists its offenders; the verdict line always prints."""
from __future__ import annotations

from pathlib import Path

import pytest

from boxmunge.userns import preflight as pf
from boxmunge.userns import preflight_checks as checks
from boxmunge.userns.inventory import ContainerEntry, ImageEntry, Inventory, MountEntry, VolumeEntry
from boxmunge.userns.journal import FORWARD, ROLLBACK
from boxmunge.userns.shift import Scan

S = 1048576


@pytest.fixture
def quiet(monkeypatch, paths, tmp_path):
    root = tmp_path / "var-lib-docker"
    (root / "volumes").mkdir(parents=True)
    monkeypatch.setattr(checks, "DEFAULT_DATA_ROOT", str(root))
    monkeypatch.setattr(pf, "compose_version_problem", lambda: None)
    monkeypatch.setattr(checks, "scan_tree", lambda tree, s, d: Scan([], 1))
    monkeypatch.setattr(checks, "image_high_ids", lambda image_id: [])
    monkeypatch.setattr(pf, "_undeclared_root", lambda paths, r: None)
    monkeypatch.setattr(pf, "_compose_users", lambda paths, inv, r: None)
    paths.config_file.write_text("hostname: h\nadmin_email: a@b.c\nbackup_remote: \"remote:box\"\n")
    return root


def _inv(docker_root, **kw) -> Inventory:
    return Inventory(**{"driver": "overlay2", "driver_type": "", "root": str(docker_root),
                        "server_version": "29.9.0", "projects": ["shop"], **kw})


def _container(**kw) -> ContainerEntry:
    base = dict(id="c1", name="shop-app-1", compose_project="shop", service="app",
                image_id="sha256:i", running=False, privileged=False, pid="", network="",
                ipc="", userns="", mounts=[])
    return ContainerEntry(**{**base, **kw})


def _run(paths, inv, direction=FORWARD):
    return pf.preflight(paths, inv, direction=direction, offset=S,
                        images_dir=Path(inv.root) / "img")


def test_a_clean_box_is_ready(paths, quiet) -> None:
    report = _run(paths, _inv(quiet))
    assert report.ok and report.text().endswith("VERDICT: ready")
    assert "prior store: overlay2 (graph driver)" in report.text()


def test_host_namespaces_old_docker_and_drivers_are_refused(paths, quiet) -> None:
    inv = _inv(quiet, server_version="27.5.1",
               containers=[_container(ipc="host"), _container(id="c2", name="shop-x-1",
                                                              privileged=True)],
               volumes=[VolumeEntry("nfs", "local", {"type": "nfs"}, {}, str(quiet), False,
                                    False, False)])
    text = _run(paths, inv).text()
    assert "older than 28.0" in text and "ipc cannot run" in text and "privileged cannot run" in text
    assert "only plain local volumes" in text and "VERDICT: not ready" in text


@pytest.mark.parametrize("kw, needle", [
    ({"remapped": True}, "already remaps"),
    ({"driver": "btrfs"}, "supports overlay2 and the containerd store"),
    ({"root": "/srv/docker"}, "supports only"),
])
def test_only_an_unremapped_overlay_store_at_the_default_root_migrates(paths, quiet, kw,
                                                                       needle) -> None:
    assert needle in _run(paths, _inv(quiet, **kw)).text()


def test_containers_boxmunge_does_not_run_are_refused(paths, quiet) -> None:
    inv = _inv(quiet, containers=[
        _container(name="portainer", compose_project=""),
        _container(id="c2", name="shop-staging-app-1", compose_project="shop-staging"),
        _container(id="c3", name="boxmunge-caddy", compose_project="caddy")])
    text = _run(paths, inv).text()
    assert "container portainer (no compose project)" in text
    assert "unstage shop first" in text and "boxmunge-caddy" not in text


def test_a_bind_outside_the_project_and_caddy_config_is_refused(paths, quiet) -> None:
    inv = _inv(quiet, containers=[_container(mounts=[MountEntry(
        "bind", "/etc", "/host-etc", False, "", "refuse")])])
    assert "mounts /etc at /host-etc" in _run(paths, inv).text()


def test_anonymous_data_is_refused_with_adopt_guidance(paths, quiet) -> None:
    anon = "a" * 64
    inv = _inv(quiet, containers=[_container(mounts=[MountEntry(
        "volume", "", "/var/lib/postgresql/data", True, anon, "anonymous")])],
        volumes=[VolumeEntry(anon, "local", {}, {}, str(quiet), True, True, True)])
    text = _run(paths, inv).text()
    assert "boxmunge data adopt shop app:/var/lib/postgresql/data <name>" in text


def test_a_dangling_anonymous_volume_is_only_reported(paths, quiet) -> None:
    inv = _inv(quiet, volumes=[VolumeEntry("b" * 64, "local", {}, {}, str(quiet), False, True,
                                           True)])
    report = _run(paths, inv)
    assert report.ok and "dangling anonymous volume bbbbbbbbbbbb" in report.text()


def test_high_ids_in_an_image_are_refused(paths, quiet, monkeypatch) -> None:
    monkeypatch.setattr(checks, "image_high_ids", lambda image_id: ["big (70000:70000)"])
    inv = _inv(quiet, images=[ImageEntry("sha256:i", ["x:1"], 1, True),
                              ImageEntry("sha256:u", [], 1, False)])
    text = _run(paths, inv).text()
    assert "ids above 65535" in text and "1 image(s) with no tag that no container runs" in text


def test_shift_problems_are_refused_per_tree(paths, quiet, monkeypatch) -> None:
    monkeypatch.setattr(checks, "scan_tree", lambda tree, s, d: Scan(["x: uid 70000"], 3))
    uploads = paths.project_dir("shop") / "uploads"
    uploads.mkdir(parents=True)
    inv = _inv(quiet, containers=[_container(mounts=[MountEntry(
        "bind", str(uploads), "/u", True, "", "data")])])
    report = _run(paths, inv)
    assert f"{uploads}: x: uid 70000" in report.text() and report.files == 3


def test_unreadable_read_only_bind_is_refused_but_not_the_caddyfile(paths, quiet) -> None:
    conf = paths.project_dir("shop") / "conf"
    conf.mkdir(parents=True)
    (conf / "secret.ini").write_text("x")
    (conf / "secret.ini").chmod(0o600)
    paths.caddyfile.write_text("x")
    paths.caddyfile.chmod(0o640)
    inv = _inv(quiet, containers=[
        _container(mounts=[MountEntry("bind", str(conf), "/c", False, "", "readable")]),
        _container(id="c2", name="boxmunge-caddy", compose_project="caddy", mounts=[
            MountEntry("bind", str(paths.caddyfile), "/etc/caddy/Caddyfile", False, "",
                       "platform")])])
    text = _run(paths, inv).text()
    assert "secret.ini" in text and "REFUSED: read-only bind " + str(conf) in text
    assert f"REFUSED: read-only bind {paths.caddyfile}" not in text
    assert f"{paths.caddyfile} is made 0644" in text


def test_rollback_skips_the_forward_only_checks(paths, quiet) -> None:
    paths.probation.parent.mkdir(parents=True, exist_ok=True)
    paths.probation.write_text("{}")
    inv = _inv(quiet, containers=[_container(ipc="host")], remapped=True)
    assert _run(paths, inv, direction=ROLLBACK).ok
    assert "probation" in _run(paths, inv).text()


def test_a_staged_release_is_refused(paths, quiet) -> None:
    (paths.project_releases("shop") / "staged").mkdir(parents=True)
    text = _run(paths, _inv(quiet)).text()
    assert "shop: a release is staged" in text
    assert "shop: a release is staged" in _run(paths, _inv(quiet), ROLLBACK).text()


def test_an_open_install_transaction_is_refused(paths, quiet, monkeypatch) -> None:
    monkeypatch.setattr(pf, "open_install_reason", lambda paths, p: f"{p}: install open")
    monkeypatch.setattr(pf, "legacy_stage_refusal", lambda paths, p: f"{p}: old-layout stage")
    text = _run(paths, _inv(quiet)).text()
    assert "REFUSED: shop: install open" in text and "REFUSED: shop: old-layout stage" in text


def test_a_project_without_a_binds_record_is_reported(paths, quiet) -> None:
    uploads = paths.project_dir("shop") / "uploads"
    inv = _inv(quiet, containers=[_container(mounts=[MountEntry(
        "bind", str(uploads), "/u", True, "", "data")])])
    text = _run(paths, inv).text()
    assert "shop: no binds record" in text and "uploads" in text


def test_data_no_container_mounts_is_reported(paths, quiet) -> None:
    (paths.project_data("shop") / "uploads").mkdir(parents=True)
    (paths.project_data("shop") / "old").mkdir()
    inv = _inv(quiet, containers=[_container(mounts=[MountEntry(
        "bind", str(paths.project_data("shop") / "uploads"), "/u", True, "", "data")])])
    text = _run(paths, inv).text()
    assert f"{paths.project_data('shop') / 'old'} is not mounted by any container" in text
    assert "data/uploads is not mounted" not in text


def test_missing_backup_remote_is_refused(paths, quiet) -> None:
    paths.config_file.write_text("hostname: h\nadmin_email: a@b.c\n")
    assert "backup_remote is not configured" in _run(paths, _inv(quiet)).text()


def test_undeclared_root_services_are_refused_with_the_line_to_add(paths, quiet,
                                                                   monkeypatch) -> None:
    monkeypatch.undo()  # the real _undeclared_root, over the users check's answer
    monkeypatch.setattr("boxmunge.health_checks.service_users.pending_declarations",
                        lambda paths: (["shop/db (postgres:16)"], ["blog: unreadable"]))
    r = checks.Report()
    pf._undeclared_root(paths, r)
    assert any("shop/db (postgres:16) runs as its image's root" in x
               and "services.db: security: {user: image" in x for x in r.refusals)
    assert "cannot tell who a service runs as: blog: unreadable" in r.refusals


_COMPOSE_USERS = pf._compose_users  # before the quiet fixture stands it in


def test_compose_user_ids_a_remapped_daemon_cannot_map_are_refused(paths) -> None:
    project = paths.project_dir("shop")
    project.mkdir(parents=True)
    (project / "manifest.yml").write_text("project: shop\n")
    (project / "compose.yml").write_text(
        "services:\n  app:\n    image: x\n    user: \"70000:70000\"\n"
        "  ok:\n    image: y\n    user: \"1000\"\n")
    r = checks.Report()
    _COMPOSE_USERS(paths, Inventory("overlay2", "", "/v", "29.9.0", projects=["shop"]), r)
    assert r.refusals and all("shop: service app: user = '70000:70000': id 70000 is above "
                              "65535" in x for x in r.refusals)


def test_tarballs_a_stopped_run_wrote_need_no_new_space(paths, quiet, monkeypatch) -> None:
    images_dir = Path(_inv(quiet).root) / "img"
    images_dir.mkdir()
    (images_dir / "a.tar").write_bytes(b"x" * 1000)
    free = type("U", (), {"free": 1500})()
    monkeypatch.setattr(checks.shutil, "disk_usage", lambda p: free)
    inv = _inv(quiet, images=[ImageEntry("sha256:i", ["x:1"], 1000, True)])
    assert _run(paths, inv).ok  # 2200 needed, 1000 of it written already
    (images_dir / "a.tar").unlink()
    assert "1500 bytes free, 2200 needed" in _run(paths, inv).text()
