"""While the userns migration is in progress or stopped part-way, every
command that could change a project refuses, naming what finishes it."""
from __future__ import annotations

import pytest

from boxmunge.lifecycle import BlockReason, is_blocked, lifecycle_block
from boxmunge.userns.marker import clear_marker, migration_in_progress, set_marker

FINISH = "userns-migrate (to resume) or userns-rollback"


@pytest.fixture
def migrating(paths):
    project = paths.project_dir("shop")
    project.mkdir(parents=True)
    (project / "manifest.yml").write_text("project: shop\nhosts: [shop.example.com]\n")
    set_marker(paths, FINISH)
    return paths


def _refused(capsys) -> bool:
    err = capsys.readouterr().err
    return "user-namespace migration" in err and FINISH in err


def test_the_marker_blocks_every_project(migrating) -> None:
    block = is_blocked("shop", migrating)
    assert block.reason is BlockReason.MIGRATING and FINISH in block.refuse_message
    assert lifecycle_block("shop", migrating) is None  # the migration's own bring-up
    assert oct(migrating.userns_marker.stat().st_mode & 0o777) == "0o644"
    clear_marker(migrating)
    assert migration_in_progress(migrating) is None and is_blocked("shop", migrating) is None


def test_deploy_stage_promote_rollback_restore_refuse(migrating, capsys) -> None:
    from boxmunge.commands.deploy import deploy_eligible
    from boxmunge.commands.restore import restore_locked
    from boxmunge.commands.rollback import rollback_locked
    from boxmunge.commands.stage_cmd import stage_locked
    assert not deploy_eligible("shop", migrating) and _refused(capsys)
    assert stage_locked("shop", migrating) != 0 and _refused(capsys)
    assert rollback_locked("shop", migrating) != 0 and _refused(capsys)
    assert restore_locked("shop", migrating, None) != 0 and _refused(capsys)


def test_promote_refuses(migrating, capsys) -> None:
    from boxmunge.commands.promote_cmd import promote_locked
    assert promote_locked("shop", migrating) != 0 and _refused(capsys)


def test_resume_recover_and_security_resume_refuse(migrating, capsys) -> None:
    from boxmunge.commands.recover_cmd import recover_locked
    from boxmunge.commands.resume_cmd import resume_locked
    from boxmunge.commands.security_resume import security_resume_locked
    assert resume_locked("shop", migrating, skip_security_checks=True)[0] != 0
    assert _refused(capsys)
    assert recover_locked("shop", migrating) != 0 and _refused(capsys)
    assert security_resume_locked(migrating, "shop") != 0 and _refused(capsys)


def test_backups_refuse(migrating, capsys) -> None:
    from boxmunge.commands.backup_cmd import backup_locked
    assert backup_locked("shop", migrating) == 1 and _refused(capsys)


def test_container_update_and_self_test_refuse(migrating, capsys) -> None:
    from boxmunge.commands.container_update_cmd import run_container_update
    from boxmunge.commands.self_test_cmd import run_self_test
    assert run_container_update(migrating) == 1 and _refused(capsys)
    assert run_self_test(migrating) == 1 and _refused(capsys)


def test_data_adopt_and_chown_refuse(migrating) -> None:
    from boxmunge.commands.data_cmd import DataError, adopt_locked, chown_locked
    with pytest.raises(DataError, match="user-namespace migration"):
        adopt_locked(migrating, "shop", "db", "/data", "pgdata")
    with pytest.raises(DataError, match="user-namespace migration"):
        chown_locked(migrating, "shop", "db", (70, 70))


def test_legacy_stage_resolution_refuses(migrating, capsys) -> None:
    from boxmunge.commands.legacy_stage_cmd import legacy_stage_locked
    assert legacy_stage_locked(migrating, "shop", "discard", False) == 1 and _refused(capsys)


def test_after_a_reboot_the_timers_entry_points_leave_the_box_alone(migrating, capsys,
                                                                    monkeypatch) -> None:
    """A reboot during the downtime: the marker is still there, so whatever
    timer runs touches no project."""
    from boxmunge.commands import check as check_mod
    from boxmunge.commands.backup_cmd import run_backup_all
    from boxmunge.commands.security_actions import cmd_security_scan
    from boxmunge.project_registry import add_project
    add_project("shop", migrating)
    assert cmd_security_scan([], migrating) == 1 and _refused(capsys)
    monkeypatch.setattr("boxmunge.commands.backup_cmd.backup_locked",
                        lambda *a, **kw: pytest.fail("backed up"))
    run_backup_all(migrating)
    assert "a userns migration is in progress" in capsys.readouterr().out
    monkeypatch.setattr(check_mod, "run_check", lambda *a, **kw: pytest.fail("checked"))
    monkeypatch.setattr("boxmunge.health_checks.userns.alert_docker_userns",
                        lambda paths: type("C", (), {"status": "warn"})())
    check_mod.run_check_all(migrating, read_only=False)
