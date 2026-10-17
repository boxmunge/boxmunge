"""staging-teardown-all: D14, run by the shim before a platform rollback."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from boxmunge.commands.staging_teardown_cmd import cmd_staging_teardown_all, run_staging_teardown_all
from boxmunge.docker_run import DockerError
from boxmunge.fileutil import project_lock
from boxmunge.release_txn import open_txn
from boxmunge.staged_release import load_slot
from tests.stage_helpers import V1, prod_and_stage, staging_docker_off

DISCARDED_ALERT = "staged release discarded by the platform rollback; re-stage it"


def _alerts():
    sent: list[dict] = []

    def record(paths, title, body, **kw):
        sent.append({"title": title, "body": body, **kw})
        return True
    return sent, patch("boxmunge.commands.staging_teardown_cmd.notify", record)


def test_every_slot_is_torn_down_and_alerted(paths) -> None:
    prod_and_stage(paths)
    sent, notify = _alerts()
    with staging_docker_off(), notify:
        assert run_staging_teardown_all(paths, "platform-rollback") == 0
    assert load_slot(paths, "myapp") is None
    assert [a["body"] for a in sent] == [DISCARDED_ALERT]
    assert sent[0]["priority"] == 1 and sent[0]["project"] == "myapp"


def test_a_failure_alerts_with_the_manual_commands_and_never_blocks(paths) -> None:
    prod_and_stage(paths)
    sent, notify = _alerts()
    with staging_docker_off() as docker, notify:
        docker["down"].side_effect = DockerError("daemon gone")
        assert run_staging_teardown_all(paths, "platform-rollback") == 0
    assert load_slot(paths, "myapp") is not None
    assert len(sent) == 1 and sent[0]["priority"] == 1
    assert "--project-directory" in sent[0]["body"] and "rm -rf" in sent[0]["body"]


def test_a_busy_project_is_alerted_not_waited_for(paths) -> None:
    prod_and_stage(paths)
    sent, notify = _alerts()
    with project_lock("myapp", paths), notify:
        assert run_staging_teardown_all(paths, "platform-rollback") == 0
    assert load_slot(paths, "myapp") is not None
    assert len(sent) == 1 and "rm -rf" in sent[0]["body"]


def test_projects_without_a_slot_are_left_alone(paths) -> None:
    prod_and_stage(paths)
    sent, notify = _alerts()
    with staging_docker_off(), notify:
        assert run_staging_teardown_all(paths, "platform-rollback") == 0
        assert run_staging_teardown_all(paths, "platform-rollback") == 0
    assert len(sent) == 1


def test_one_failing_project_does_not_stop_the_next(paths) -> None:
    prod_and_stage(paths)
    other = paths.project_dir("other") / ".releases" / "staged"
    other.parent.mkdir(parents=True)
    other.symlink_to(paths.root)  # a planted link: the teardown refuses it
    sent, notify = _alerts()
    with staging_docker_off(), notify:
        assert run_staging_teardown_all(paths, "platform-rollback") == 0
    assert load_slot(paths, "myapp") is None
    bodies = {a["project"]: a["body"] for a in sent}
    assert bodies["myapp"] == DISCARDED_ALERT and "rm -rf" in bodies["other"]


def test_a_slot_an_open_promote_needs_is_kept_and_alerted(paths) -> None:
    prod_and_stage(paths)
    meta = load_slot(paths, "myapp")
    open_txn(paths, "myapp", source="staged", ref=meta.ref, replaced_ref=f"myapp-{V1}",
             staged_id=meta.id, snapshot="")
    sent, notify = _alerts()
    with staging_docker_off() as docker, notify:
        assert run_staging_teardown_all(paths, "platform-rollback") == 0
    docker["down"].assert_not_called()
    assert load_slot(paths, "myapp") == meta
    assert len(sent) == 1 and sent[0]["priority"] == 1
    body = sent[0]["body"]
    assert "being promoted from this staged release" in body
    assert "rerun 'promote myapp' to finish it" in body and "rm -rf" in body


def test_an_unreadable_install_record_keeps_the_slot(paths) -> None:
    prod_and_stage(paths)
    (paths.project_releases("myapp") / "install.json").write_text("{not json")
    sent, notify = _alerts()
    with staging_docker_off(), notify:
        assert run_staging_teardown_all(paths, "platform-rollback") == 0
    assert load_slot(paths, "myapp") is not None
    assert "install-txn myapp --drop" in sent[0]["body"]


def test_an_invalid_project_directory_is_reported_and_skipped(paths, capsys) -> None:
    prod_and_stage(paths)
    bad = paths.projects / "web-staging" / ".releases" / "staged"
    bad.mkdir(parents=True)
    sent, notify = _alerts()
    with staging_docker_off(), notify:
        assert run_staging_teardown_all(paths, "platform-rollback") == 0
    assert load_slot(paths, "myapp") is None
    assert [a["project"] for a in sent] == ["myapp"]
    assert "web-staging" in capsys.readouterr().err


@pytest.mark.parametrize("argv", [[], ["--reason", "whim"], ["--reason"]])
def test_the_reason_is_required(argv) -> None:
    with pytest.raises(SystemExit) as e:
        cmd_staging_teardown_all(argv)
    assert e.value.code == 2
