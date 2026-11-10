"""data chown: the one deliberate change of a service's data ownership."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from boxmunge import docker_containers
from boxmunge.backup import BackupError
from boxmunge import chown_hold
from boxmunge.commands import backup_cmd, chown_snapshot, data_cmd
from boxmunge.docker_containers import StartState
from boxmunge.pending_snapshot import pending, record_pending
from boxmunge.run_as import ServiceUser, read_users, write_users
from boxmunge.state import write_state

from tests.bundle_helpers import manifest_text

LONG_AGO = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _setup(paths, monkeypatch, volumes_exist=True, backup="none", backup_service="app",
           others=None):
    calls = []
    project_dir = paths.project_dir("shop")
    (project_dir / "uploads").mkdir(parents=True)
    manifest = manifest_text("shop", backup=backup)
    if backup != "none":
        manifest += f"  service: {backup_service}\n"
    (project_dir / "manifest.yml").write_text(manifest)
    paths.deploy_state.mkdir(parents=True, exist_ok=True)
    write_state(paths.project_deploy_state("shop"), {"current_ref": "shop-r1"})
    services = {"app": {"volumes": [
        {"type": "bind", "source": str(project_dir / "uploads"), "target": "/u"},
        {"type": "bind", "source": str(project_dir / "conf"), "target": "/c", "read_only": True},
        {"type": "bind", "source": str(project_dir / "never-made"), "target": "/n"},
        {"type": "volume", "source": "cache", "target": "/cache"}]}, **(others or {})}
    monkeypatch.setattr(data_cmd, "resolved_services", lambda target: ({}, services))
    monkeypatch.setattr(data_cmd, "_running", lambda p, s: ["shop-app-1"])
    monkeypatch.setattr(data_cmd, "_run", lambda cmd, **kw: calls.append(cmd))
    monkeypatch.setattr(data_cmd, "volume_labels", lambda n: {} if volumes_exist else None)
    monkeypatch.setattr(data_cmd, "run_helper", lambda label, mounts, script:
                        calls.append((mounts[1], script)))
    monkeypatch.setattr(data_cmd, "chown_under", lambda label, root, rel, ids:
                        calls.append((f"{root}:{rel}", ids)))
    monkeypatch.setattr(data_cmd, "_containers", lambda p, s: ["shop-app-1"])
    monkeypatch.setattr(data_cmd, "staging_copies", lambda *a: [])
    monkeypatch.setattr(chown_hold, "hold", lambda p, n, s: calls.append(("hold", s)) or [s])
    monkeypatch.setattr(data_cmd, "prepare_compose_override",
                        lambda p, m, component: calls.append(("overlay", component)))
    monkeypatch.setattr(chown_snapshot, "running_by_service",
                        lambda p: {"app": ["shop-app-1"], "db": ["shop-db-1"]})
    return project_dir, calls


def test_chown_stops_chowns_every_persistent_mount_and_records(paths, monkeypatch) -> None:
    project_dir, calls = _setup(paths, monkeypatch)
    write_users(paths, "shop", {"app": ServiceUser(None, "image", "node"),
                                "db": ServiceUser(None, "manifest")})
    data_cmd.chown_locked(paths, "shop", "app", (10001, 10001))
    assert calls[0][:2] == ["docker", "stop"]
    assert calls[1:] == [("hold", "app"), (f"{project_dir}:uploads", (10001, 10001)),
                         ("type=volume,src=shop_cache,dst=/x", "chown -R -h 10001:10001 /x"),
                         ("overlay", "data-chown")]
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
    assert [c for c in calls if isinstance(c, tuple) and c[0] != "hold"] == []


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


def _dumping(paths, monkeypatch, calls, fail=False):
    def dump(paths_, project, dump_command, service, compose_file=None, offline=False):
        calls.append("dump-offline" if offline else "dump")
        if fail:
            raise BackupError("service web is not running")
        raw = paths.project_backups(project) / ".dump-x.tar.gz"
        raw.write_bytes(b"dump")
        return raw
    paths.project_backups("shop").mkdir(exist_ok=True)
    monkeypatch.setattr(backup_cmd, "execute_dump", dump)


def _snapshots(paths):
    return sorted(f.name for f in paths.project_backups("shop").glob("*.tar.gz.age"))


def test_the_snapshot_is_taken_before_the_stop_and_kept_for_the_deploy(
        paths, monkeypatch, system_container, capsys) -> None:
    _project_dir, calls = _setup(paths, monkeypatch, backup="postgres")
    _dumping(paths, monkeypatch, calls)
    data_cmd.chown_locked(paths, "shop", "app", (10001, 10001))
    assert calls[0] == "dump" and calls[1][:2] == ["docker", "stop"]
    [snap] = _snapshots(paths)
    assert snap.endswith("-prechown.tar.gz.age")
    entry = pending(paths, "shop")
    assert (entry["name"], entry["ref"], entry["service"], entry["containers"]) == \
        (snap, "shop-r1", "app", ["shop-app-1"])
    assert "is the next deploy's pre-deploy snapshot" in capsys.readouterr().out


def test_a_service_other_than_the_backup_service_is_snapshotted_but_not_kept(
        paths, monkeypatch, system_container, capsys) -> None:
    """The backup service keeps running, so the deploy's own dump works and
    holds newer data than data chown's snapshot."""
    _project_dir, calls = _setup(paths, monkeypatch, backup="postgres", backup_service="db")
    _dumping(paths, monkeypatch, calls)
    data_cmd.chown_locked(paths, "shop", "app", (10001, 10001))
    assert calls[0] == "dump" and calls[1][:2] == ["docker", "stop"]
    assert [s.rsplit("-", 1)[1] for s in _snapshots(paths)] == ["prechown.tar.gz.age"]
    assert pending(paths, "shop") is None
    assert "the next deploy takes its own" in capsys.readouterr().out


def test_a_failed_snapshot_refuses_and_changes_nothing(
        paths, monkeypatch, system_container, capsys) -> None:
    _project_dir, calls = _setup(paths, monkeypatch, backup="postgres")
    _dumping(paths, monkeypatch, calls, fail=True)
    write_users(paths, "shop", {"app": ServiceUser(None, "image", "node")})
    assert data_cmd.run_data_chown(paths, "shop", "app", "10001:10001") == 1
    err = capsys.readouterr().err
    assert "snapshot before the ownership change was not taken" in err
    assert "--no-snapshot" in err
    assert calls == ["dump"]
    assert read_users(paths, "shop")["app"] == ServiceUser(None, "image", "node")
    assert pending(paths, "shop") is None and _snapshots(paths) == []


def test_a_backup_that_writes_nothing_refuses(paths, monkeypatch, capsys) -> None:
    _project_dir, calls = _setup(paths, monkeypatch, backup="postgres")
    monkeypatch.setattr(backup_cmd, "backup_locked", lambda *a, **kw: 0)
    with pytest.raises(data_cmd.DataError, match="not taken"):
        data_cmd.chown_locked(paths, "shop", "app", (10001, 10001))
    assert calls == []


def test_type_none_skips_the_snapshot_and_says_so(paths, monkeypatch, capsys) -> None:
    _project_dir, calls = _setup(paths, monkeypatch)
    monkeypatch.setattr(backup_cmd, "backup_locked", lambda *a, **kw: pytest.fail("backed up"))
    data_cmd.chown_locked(paths, "shop", "app", (10001, 10001))
    assert "backup.type is none" in capsys.readouterr().out
    assert calls[0][:2] == ["docker", "stop"]
    assert pending(paths, "shop") is None


def test_no_snapshot_goes_on_without_one_and_says_so(paths, monkeypatch, capsys) -> None:
    _project_dir, calls = _setup(paths, monkeypatch, backup="postgres")
    monkeypatch.setattr(backup_cmd, "backup_locked", lambda *a, **kw: pytest.fail("backed up"))
    data_cmd.chown_locked(paths, "shop", "app", (10001, 10001), no_snapshot=True)
    assert "a rollback of the next deploy then cannot restore data" in capsys.readouterr().out
    assert pending(paths, "shop") is None


def _earlier_chown(paths, monkeypatch, state: StartState) -> str:
    """An earlier chown's record for app, and what Docker now shows of it."""
    paths.project_backups("shop").mkdir(exist_ok=True)
    first = "shop-2026-11-01T100000-prechown.tar.gz.age"
    (paths.project_backups("shop") / first).write_bytes(b"x")
    record_pending(paths, "shop", first, "data chown", "app", ["shop-app-1"])
    monkeypatch.setattr(docker_containers, "start_states", lambda p: {"shop-app-1": state})
    return first


def test_a_second_chown_keeps_the_first_snapshot_while_the_service_stays_stopped(
        paths, monkeypatch, capsys) -> None:
    """The first chown stopped the backup service: the second's dump could
    not run, and the first snapshot is the data before either."""
    _project_dir, calls = _setup(paths, monkeypatch, backup="postgres")
    monkeypatch.setattr(data_cmd, "_running", lambda p, s: [])
    first = _earlier_chown(paths, monkeypatch, StartState("app", False, LONG_AGO))
    monkeypatch.setattr(backup_cmd, "backup_locked", lambda *a, **kw: pytest.fail("backed up"))
    data_cmd.chown_locked(paths, "shop", "app", (10001, 10001))
    assert "No new one is taken" in capsys.readouterr().out
    assert pending(paths, "shop")["name"] == first


def test_a_second_chown_of_a_service_running_again_takes_a_new_snapshot(
        paths, monkeypatch, system_container, capsys) -> None:
    _project_dir, calls = _setup(paths, monkeypatch, backup="postgres")
    _dumping(paths, monkeypatch, calls)
    first = _earlier_chown(paths, monkeypatch, StartState("app", True, LONG_AGO))
    data_cmd.chown_locked(paths, "shop", "app", (10001, 10001))
    assert "is dropped: app is running again" in capsys.readouterr().out
    assert calls[0] == "dump"
    assert pending(paths, "shop")["name"] not in (first, None)


def test_a_failed_stop_records_nothing(paths, monkeypatch, system_container) -> None:
    """The service keeps running, so its data moves on from the snapshot."""
    from boxmunge.docker_run import DockerError
    _project_dir, calls = _setup(paths, monkeypatch, backup="postgres")
    _dumping(paths, monkeypatch, calls)

    def stop(cmd, **kw):
        raise DockerError("docker stop timed out")
    monkeypatch.setattr(data_cmd, "_run", stop)
    with pytest.raises(DockerError):
        data_cmd.chown_locked(paths, "shop", "app", (10001, 10001))
    assert pending(paths, "shop") is None
    assert [s.rsplit("-", 1)[1] for s in _snapshots(paths)] == ["prechown.tar.gz.age"]


def test_data_another_service_writes_too_is_not_kept(
        paths, monkeypatch, system_container, capsys) -> None:
    root = paths.project_dir("shop")
    project_dir, calls = _setup(paths, monkeypatch, backup="postgres", others={"worker": {
        "volumes": [{"type": "bind", "source": str(root), "target": "/all"}]}})
    _dumping(paths, monkeypatch, calls)
    data_cmd.chown_locked(paths, "shop", "app", (10001, 10001))
    out = capsys.readouterr().out
    assert f"worker also mounts {project_dir / 'uploads'} read-write" in out
    assert pending(paths, "shop") is None


def test_a_read_only_mount_elsewhere_does_not_stop_it_being_kept(
        paths, monkeypatch, system_container) -> None:
    _project_dir, calls = _setup(paths, monkeypatch, backup="postgres", others={"worker": {
        "volumes": [{"type": "volume", "source": "cache", "target": "/c", "read_only": True}]}})
    _dumping(paths, monkeypatch, calls)
    data_cmd.chown_locked(paths, "shop", "app", (10001, 10001))
    assert pending(paths, "shop") is not None


def test_a_project_whose_running_release_cannot_be_told_refuses(paths, monkeypatch) -> None:
    from boxmunge.backup_source import BackupSource
    _project_dir, calls = _setup(paths, monkeypatch, backup="postgres")
    monkeypatch.setattr(chown_snapshot, "backup_source",
                        lambda p, n: BackupSource(None, skip="which release runs is ambiguous"))
    with pytest.raises(data_cmd.DataError, match="ambiguous.*--no-snapshot"):
        data_cmd.chown_locked(paths, "shop", "app", (10001, 10001))
    assert calls == []
