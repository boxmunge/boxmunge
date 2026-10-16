"""Rollback and unstage put an earlier release's files back; the start checks
must then compare against that release, not the one it replaced.

A bundle rollback with a data snapshot installs the previous release and
restores its data before starting it. restore's first step is the start
check, so the rolled-back release must be recorded first: with a differing
compose.yml (an image bump is enough) the check used to compare it with the
record of the release it had just replaced and refuse, leaving the old code
on disk under the newer containers (review of PR #67).
"""
from unittest.mock import patch

import yaml

from boxmunge.commands.restore import _compose_files
from boxmunge.commands.rollback import find_rollback_target, run_rollback
from boxmunge.compose_guard import ComposeRefused, check_start
from boxmunge.project_registry import add_project
from tests.test_commands import test_rollback as rb
from tests.test_commands.test_rollback import V1, V2, _deploy, _docker


def _compose(tag: str) -> str:
    return yaml.safe_dump({"services": {"web": {"image": f"nginx:{tag}"}}})


def test_rollback_with_a_snapshot_and_a_changed_compose_passes_restores_check(paths) -> None:
    add_project("myapp", paths)
    with patch("boxmunge.commands.backup_cmd.backup_locked",
               rb.TestRollbackRestoresData._fake_backup(paths)):
        _deploy(paths, V1, {"VERSION": "v1\n", "compose.yml": _compose("1.27-alpine")},
                backup="postgres")
        _deploy(paths, V2, {"VERSION": "v2\n", "compose.yml": _compose("1.28-alpine")},
                backup="postgres")
    assert find_rollback_target(paths, "myapp").snapshot
    checked: list[str] = []

    def restore_with_its_real_start_check(project_name, paths_, snapshot=None, txn=None):
        """The restore's own first step, then a restore that succeeds. The
        rollback passes its install transaction's id, as to the real one."""
        assert txn is not None
        try:
            check_start(paths_, project_name, component="restore",
                        compose_files=_compose_files(paths_, project_name), txn=txn)
        except ComposeRefused as e:
            checked.append(f"refused: {e}")
            return 1
        checked.append("passed")
        return 0

    sent: list[str] = []
    with patch("boxmunge.commands.rollback.restore_locked", restore_with_its_real_start_check), \
            _docker(), \
            patch("boxmunge.notify.send_notification",
                  lambda u, t, title, body, priority=0: sent.append(title) or True):
        assert run_rollback("myapp", paths, yes=True) == 0
    assert checked == ["passed"]
    assert sent == []
    assert (paths.project_dir("myapp") / "VERSION").read_text() == "v1\n"


def test_production_starts_again_after_an_unstage(paths) -> None:
    """unstage puts production's own files back, so production's record
    holds again; the next root start goes ahead."""
    from boxmunge.commands.stage_cmd import run_stage
    from boxmunge.commands.unstage_cmd import run_unstage
    from boxmunge.commands.upgrade_steps import restart_projects
    from tests.bundle_helpers import place_bundle
    from tests.test_commands.test_stage_promote_release import _docker as _stage_docker

    add_project("myapp", paths)
    _deploy(paths, V1, {"compose.yml": _compose("1.27-alpine")})
    place_bundle(paths, timestamp=V2, files={"compose.yml": _compose("1.28-alpine")})
    with _stage_docker():
        assert run_stage("myapp", paths, ref=V2) == 0
        assert restart_projects(paths, refused=()).start_refused == ["myapp"]
        assert run_unstage("myapp", paths) == 0
        restart = restart_projects(paths, refused=())
    assert restart.succeeded == ["myapp"] and restart.start_refused == []
