"""data chown on a project that is not simply running, and what it leaves.

The review of 2026-11-09 (findings 03, 08) and an operator session found:
the overlay kept the old user; a quarantined, paused or monitor-stopped
project could not be snapshotted and the refusal offered only
--no-snapshot; staging's copies of the data were left to the old user.
"""
from __future__ import annotations

import pytest
import yaml

from boxmunge.commands import backup_cmd, chown_snapshot, data_cmd
from boxmunge.commands.chown_staging import StagingCopy
from boxmunge.pending_snapshot import pending
from boxmunge.run_as import ServiceUser, write_users
from boxmunge.state import write_state

from tests.test_data_chown import _dumping, _setup, _snapshots


def _stopped(monkeypatch, *, running=()) -> None:
    """The backup service is not running (nothing of the project is)."""
    monkeypatch.setattr(data_cmd, "_running", lambda p, s: [])
    monkeypatch.setattr(chown_snapshot, "running_by_service",
                        lambda p: {s: [f"shop-{s}-1"] for s in running})


def _quarantine(paths) -> None:
    from tests.test_commands.cve_helpers import seed_quarantine
    seed_quarantine(paths, "shop")


def test_the_overlay_is_regenerated_with_the_new_user(paths, monkeypatch) -> None:
    """Every start after the chown (container-update, restore, a staging
    copy's restart, an upgrade) runs the overlay as it is."""
    project_dir, calls = _setup(paths, monkeypatch)
    from boxmunge.compose import prepare_compose_override
    monkeypatch.setattr(data_cmd, "prepare_compose_override", prepare_compose_override)
    (project_dir / "compose.yml").write_text(yaml.safe_dump(
        {"services": {"app": {"image": "shop-app:1"}}}))
    overlay = paths.project_compose_override("shop")
    overlay.write_text(yaml.safe_dump({"services": {"app": {"user": "10001:10001"}}}))
    write_users(paths, "shop", {"app": ServiceUser("10001:10001", "default", "")})
    data_cmd.chown_locked(paths, "shop", "app", (10002, 10002))
    assert yaml.safe_load(overlay.read_text())["services"]["app"]["user"] == "10002:10002"


def test_while_an_install_is_open_its_deploy_writes_the_overlay(
        paths, monkeypatch, capsys) -> None:
    _project_dir, calls = _setup(paths, monkeypatch)
    monkeypatch.setattr(data_cmd, "open_install_reason", lambda p, n: "an install is open")
    data_cmd.chown_locked(paths, "shop", "app", (10002, 10002))
    assert ("overlay", "data-chown") not in calls
    assert "its deploy generates it" in capsys.readouterr().out


def test_a_failed_regeneration_says_the_data_was_changed_and_to_deploy(
        paths, monkeypatch) -> None:
    from boxmunge.compose import ComposeError
    _setup(paths, monkeypatch)

    def boom(*a, **k):
        raise ComposeError("cannot resolve compose.yml")
    monkeypatch.setattr(data_cmd, "prepare_compose_override", boom)
    with pytest.raises(data_cmd.DataError, match="given to its new user.*prod-deploy shop"):
        data_cmd.chown_locked(paths, "shop", "app", (10002, 10002))


def test_the_restart_policy_is_held(paths, monkeypatch) -> None:
    _project_dir, calls = _setup(paths, monkeypatch)
    data_cmd.chown_locked(paths, "shop", "app", (10002, 10002))
    assert ("hold", "app") in calls


def test_a_quarantined_projects_hold_is_its_quarantines(paths, monkeypatch) -> None:
    _project_dir, calls = _setup(paths, monkeypatch)
    _quarantine(paths)
    data_cmd.chown_locked(paths, "shop", "app", (10002, 10002))
    assert ("hold", "app") not in calls


def test_a_stopped_backup_service_is_dumped_offline_and_paired(
        paths, monkeypatch, system_container, capsys) -> None:
    """Backlog: a quarantined project's backup is skipped, so the chown had no
    snapshot and needed --no-snapshot. Its data is at rest: the dump runs in
    a one-off container, offline, and the deploy pairs it."""
    _project_dir, calls = _setup(paths, monkeypatch, backup="postgres")
    _quarantine(paths)
    _stopped(monkeypatch)
    _dumping(paths, monkeypatch, calls)
    data_cmd.chown_locked(paths, "shop", "app", (10002, 10002))
    out = capsys.readouterr().out
    assert "is not running (the project is CVE-quarantined)" in out
    assert "offline (no network, no ports) only for the dump" in out
    assert calls[0] == "dump-offline"
    [snap] = _snapshots(paths)
    entry = pending(paths, "shop")
    assert (entry["name"], entry["containers"]) == (snap, ["shop-app-1"])


@pytest.mark.parametrize("state, why, way_out", [
    ("quarantined", "CVE-quarantined", "boxmunge security resume shop"),
    ("paused", "paused", "boxmunge resume shop"),
    ("monitor", "health monitor stopped", "boxmunge recover shop"),
    ("stopped", "app is stopped", "prod-deploy shop"),
])
def test_a_dump_that_cannot_run_offline_names_the_states_way_out_first(
        paths, monkeypatch, system_container, capsys, state, why, way_out) -> None:
    """Review 08 (a): the refusal offered only --no-snapshot, giving up the
    rollback, where the state's own exit would keep it."""
    _project_dir, calls = _setup(paths, monkeypatch, backup="postgres")
    _stopped(monkeypatch)
    if state == "quarantined":
        _quarantine(paths)
    elif state == "paused":
        from boxmunge.pause import write_paused_state
        write_paused_state("shop", paths, reason="maintenance")
    elif state == "monitor":
        monkeypatch.setattr(chown_snapshot, "is_monitor_stopped", lambda p, paths_: True)
    _dumping(paths, monkeypatch, calls, fail=True)
    assert data_cmd.run_data_chown(paths, "shop", "app", "10002:10002") == 1
    err = capsys.readouterr().err
    assert why in err and way_out in err
    assert err.index(way_out) < err.index("--no-snapshot")
    assert "Only if you cannot" in err
    assert calls == ["dump-offline"] and pending(paths, "shop") is None


def test_staging_copies_are_given_to_the_new_user_too(paths, monkeypatch) -> None:
    """Backlog: staging's data-staging stayed root-owned and the app crashed
    there once it ran as 10001."""
    _project_dir, calls = _setup(paths, monkeypatch)
    copies = [StagingCopy("bind", "uploads-staging"), StagingCopy("volume", "shop-staging_cache")]
    monkeypatch.setattr(data_cmd, "staging_copies", lambda *a: copies)
    monkeypatch.setattr(data_cmd, "chown_staging_copies",
                        lambda p, n, c, ids: calls.append(("staging", [x.where for x in c], ids))
                        or [x.where for x in c])
    data_cmd.chown_locked(paths, "shop", "app", (10002, 10002))
    assert ("staging", ["uploads-staging", "shop-staging_cache"], (10002, 10002)) in calls


def test_staging_alone_changes_nothing_of_productions(paths, monkeypatch, capsys) -> None:
    _project_dir, calls = _setup(paths, monkeypatch, backup="postgres")
    monkeypatch.setattr(backup_cmd, "backup_locked", lambda *a, **kw: pytest.fail("backed up"))
    monkeypatch.setattr(data_cmd, "staging_copies",
                        lambda *a: [StagingCopy("bind", "uploads-staging")])
    monkeypatch.setattr(data_cmd, "chown_staging_copies",
                        lambda p, n, c, ids: calls.append(("staging", ids)) or [])
    write_users(paths, "shop", {"app": ServiceUser("10001:10001", "default", "")})
    data_cmd.chown_locked(paths, "shop", "app", (10002, 10002), staging_only=True)
    assert calls == [("staging", (10002, 10002))]
    from boxmunge.run_as import read_users
    assert read_users(paths, "shop")["app"].user == "10001:10001"
    assert "production was not changed" in capsys.readouterr().out


def test_staging_running_the_service_refuses_before_anything_changes(
        paths, monkeypatch) -> None:
    from boxmunge.commands import chown_staging
    from boxmunge.docker_containers import ProjectContainer
    project_dir, calls = _setup(paths, monkeypatch)
    monkeypatch.setattr(data_cmd, "staging_copies", chown_staging.staging_copies)
    (project_dir / "uploads-staging").mkdir()
    monkeypatch.setattr(chown_staging, "slot_made", lambda p, n: ("uploads-staging",))
    monkeypatch.setattr(chown_staging, "production_view", lambda d: _NoDirs())
    monkeypatch.setattr(chown_staging, "volume_labels", lambda n: None)
    monkeypatch.setattr(chown_staging, "project_containers", lambda p: [ProjectContainer(
        name="shop-staging-app-1", service="app", image_id="sha256:x", repo_digests=(),
        running=True, health=None, oneoff=False, exit_code=None, restart_policy="always")])
    with pytest.raises(data_cmd.DataError, match="unstage shop"):
        data_cmd.chown_locked(paths, "shop", "app", (10002, 10002))
    assert calls == []


class _NoDirs:
    recorded: set = set()
    mounted: set = set()


def test_a_monitor_stop_does_not_turn_the_pairing_stale(paths, monkeypatch) -> None:
    """Review 08 (b): the critical stop removes every container; a removal
    is not a run of the service."""
    from datetime import datetime, timezone
    from boxmunge import docker_containers
    from boxmunge.docker_containers import StartState
    from boxmunge.pending_snapshot import note_removal, pending_for_live, record_pending
    paths.deploy_state.mkdir(parents=True, exist_ok=True)
    write_state(paths.project_deploy_state("shop"), {"current_ref": "shop-r1"})
    paths.project_backups("shop").mkdir(parents=True)
    (paths.project_backups("shop") / "snap.tar.gz.age").write_bytes(b"x")
    record_pending(paths, "shop", "snap.tar.gz.age", "data chown", "app", ["shop-app-1"])
    long_ago = datetime(2026, 1, 1, tzinfo=timezone.utc)
    monkeypatch.setattr(docker_containers, "start_states", lambda p: {
        "shop-app-1": StartState("app", False, long_ago),
        "shop-db-1": StartState("db", True, long_ago)})
    note_removal(paths, "shop")
    monkeypatch.setattr(docker_containers, "start_states", lambda p: {})
    assert pending_for_live(paths, "shop")["name"] == "snap.tar.gz.age"
    # ...but a container of it started after that is a run.
    monkeypatch.setattr(docker_containers, "start_states", lambda p: {
        "shop-app-1": StartState("app", False, datetime.now(timezone.utc))})
    assert pending_for_live(paths, "shop") is None


def _mount(kind: str, source: str):
    from boxmunge.commands.deploy_checks import Mount
    return Mount(kind=kind, source=source, target="/d", read_only=False)


def test_staging_copies_are_found_by_staging_naming(paths, monkeypatch) -> None:
    from boxmunge.commands import chown_staging
    project_dir = paths.project_dir("shop")
    (project_dir / "data" / "db").mkdir(parents=True)
    (project_dir / "data-staging" / "db").mkdir(parents=True)
    (project_dir / "uploads").mkdir()
    monkeypatch.setattr(chown_staging, "slot_made", lambda p, n: ())
    monkeypatch.setattr(chown_staging, "project_containers", lambda p: [])
    labels = {"shop-staging_cache": {"com.docker.compose.project": "shop-staging",
                                     "com.docker.compose.volume": "cache"}}
    monkeypatch.setattr(chown_staging, "volume_labels", labels.get)
    found = chown_staging.staging_copies(paths, "shop", "app", [
        _mount("bind", str(project_dir / "data" / "db")),
        _mount("bind", str(project_dir / "uploads")),      # staging has no copy of it
        _mount("volume", "cache"), _mount("volume", "logs")])
    assert found == [StagingCopy("bind", "data-staging/db"),
                     StagingCopy("volume", "shop-staging_cache")]


def test_a_staging_volume_not_labelled_as_staging_s_is_refused(paths, monkeypatch) -> None:
    from boxmunge.commands import chown_staging
    monkeypatch.setattr(chown_staging, "slot_made", lambda p, n: ())
    monkeypatch.setattr(chown_staging, "project_containers", lambda p: [])
    monkeypatch.setattr(chown_staging, "volume_labels", lambda n: {})
    with pytest.raises(chown_staging.StagingChownRefused, match="not labelled"):
        chown_staging.staging_copies(paths, "shop", "app", [_mount("volume", "cache")])
