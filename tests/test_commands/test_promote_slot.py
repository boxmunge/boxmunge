"""promote deploys the slot's tree; deploys and rollbacks work during a stage."""
from __future__ import annotations

from boxmunge.commands.deploy import run_deploy
from boxmunge.commands.promote_cmd import run_promote
from boxmunge.commands.rollback import find_rollback_target, run_rollback
from boxmunge.docker_run import DockerError
from boxmunge.release_txn import load_txn
from boxmunge.staged_release import load_slot, slot_dir, update_meta
from tests.bundle_helpers import SAFE_COMPOSE, place_bundle
from tests.stage_helpers import V1, V2, V3, prod_and_stage, staging_docker_off
from tests.txn_helpers import crash_at, fake_backups, hook_manifest


def test_promote_installs_the_staged_release_and_drops_the_slot(paths) -> None:
    pdir = prod_and_stage(paths)
    with staging_docker_off():
        assert run_promote("myapp", paths) == 0
    assert (pdir / "VERSION").read_text() == "v2\n"
    assert load_slot(paths, "myapp") is None and load_txn(paths, "myapp") is None
    assert find_rollback_target(paths, "myapp").ref == f"myapp-{V1}"
    with staging_docker_off():
        assert run_rollback("myapp", paths, yes=True) == 0
    assert (pdir / "VERSION").read_text() == "v1\n"


def test_promote_refuses_a_stage_that_did_not_finish(paths, capsys) -> None:
    prod_and_stage(paths)
    update_meta(paths, "myapp", load_slot(paths, "myapp"), state="starting")
    with staging_docker_off():
        assert run_promote("myapp", paths) == 1
    assert "the stage did not finish; stage again or unstage" in capsys.readouterr().err


def test_promote_refuses_unreadable_meta(paths, capsys) -> None:
    """Review Focus 2."""
    prod_and_stage(paths)
    (slot_dir(paths, "myapp") / "meta.json").write_text("[]")
    with staging_docker_off():
        assert run_promote("myapp", paths) == 1
    assert "stage again" in capsys.readouterr().err.lower()


def test_interrupted_promote_is_finished_by_promote(paths) -> None:
    pdir = prod_and_stage(paths)
    with staging_docker_off():
        assert crash_at("txn.switching", lambda: run_promote("myapp", paths)) == 137
        assert load_txn(paths, "myapp").source == "staged"
        assert run_promote("myapp", paths) == 0
    assert (pdir / "VERSION").read_text() == "v2\n" and load_slot(paths, "myapp") is None


def test_retired_slot_only_needs_its_teardown(paths) -> None:
    prod_and_stage(paths)
    with staging_docker_off() as docker:
        assert crash_at("txn.switched", lambda: run_promote("myapp", paths)) == 137
        assert load_slot(paths, "myapp").state == "retired"
        docker["up"].reset_mock()
        assert run_promote("myapp", paths) == 0
        docker["up"].assert_not_called()   # retired: close and tear down only
    assert load_slot(paths, "myapp") is None and load_txn(paths, "myapp") is None


def test_prod_deploy_during_a_stage_then_promote(paths) -> None:
    pdir = prod_and_stage(paths)
    place_bundle(paths, timestamp=V3, files={"VERSION": "v1-hotfix\n"})
    with staging_docker_off():
        assert run_deploy("myapp", paths, ref=V3) == 0
        assert load_slot(paths, "myapp").state == "ready"
        assert run_promote("myapp", paths) == 0
    assert (pdir / "VERSION").read_text() == "v2\n"
    assert find_rollback_target(paths, "myapp").ref == f"myapp-{V3}"


def test_prod_deploy_mounting_a_staging_copy_is_refused(paths, capsys) -> None:
    prod_and_stage(paths, staged_files={"compose.yml": SAFE_COMPOSE + "    volumes: ['./uploads:/u']\n"})
    place_bundle(paths, timestamp=V3, files={
        "compose.yml": SAFE_COMPOSE + "    volumes: ['./uploads-staging:/u']\n"})
    with staging_docker_off():
        assert run_deploy("myapp", paths, ref=V3) == 1
    assert "share" in capsys.readouterr().err and load_txn(paths, "myapp") is None


def test_failed_promote_after_the_switch_keeps_staging_for_unstage(paths, capsys) -> None:
    prod_and_stage(paths, staged_files={"manifest.yml": hook_manifest("true")})
    with staging_docker_off() as docker:
        docker["up"].side_effect = DockerError("up failed")
        assert run_promote("myapp", paths) == 1
    assert load_slot(paths, "myapp").state == "retired"
    assert "unstage myapp" in capsys.readouterr().err


# -- beyond the brief ------------------------------------------------------

_SHARING = SAFE_COMPOSE + "    volumes: ['./uploads-staging:/u']\n"


def _stage_with_uploads(paths):
    return prod_and_stage(paths, prod_files={"compose.yml": SAFE_COMPOSE + "    volumes: ['./uploads:/u']\n"},
                          staged_files={"compose.yml": SAFE_COMPOSE + "    volumes: ['./uploads:/u']\n"})


def test_a_sharing_deploy_over_an_open_install_leaves_it_as_it_was(paths, capsys) -> None:
    """D8 runs before a fix-forward supersedes or closes anything."""
    _stage_with_uploads(paths)
    place_bundle(paths, timestamp=V3, files={"manifest.yml": hook_manifest("false")})
    with staging_docker_off():
        assert run_deploy("myapp", paths, ref=V3) == 1
    before = load_txn(paths, "myapp")
    assert before.phase == "hook_started"
    place_bundle(paths, timestamp="2026-10-16T120000000000", files={"compose.yml": _SHARING})
    with staging_docker_off():
        assert run_deploy("myapp", paths, ref="2026-10-16T120000000000") == 1
    assert "share" in capsys.readouterr().err
    assert load_txn(paths, "myapp") == before


def test_promote_fixes_forward_over_an_open_bundle_install(paths) -> None:
    """A deploy failed during the stage; promote supersedes it and keeps
    its rollback target (spec: who meets an open transaction)."""
    pdir = prod_and_stage(paths)
    place_bundle(paths, timestamp=V3, files={"manifest.yml": hook_manifest("false")})
    with staging_docker_off():
        assert run_deploy("myapp", paths, ref=V3) == 1
        assert load_txn(paths, "myapp").source == "bundle"
        assert run_promote("myapp", paths) == 0
    assert (pdir / "VERSION").read_text() == "v2\n"
    assert load_txn(paths, "myapp") is None and load_slot(paths, "myapp") is None
    assert find_rollback_target(paths, "myapp").ref == f"myapp-{V1}"


def test_rollback_during_a_stage_is_allowed(paths) -> None:
    pdir = _stage_with_uploads(paths)
    place_bundle(paths, timestamp=V3, files={"VERSION": "v3\n",
                                             "compose.yml": SAFE_COMPOSE + "    volumes: ['./uploads:/u']\n"})
    with staging_docker_off():
        assert run_deploy("myapp", paths, ref=V3) == 0
        assert run_rollback("myapp", paths, yes=True) == 0
    assert (pdir / "VERSION").read_text() == "v1\n"
    assert load_slot(paths, "myapp").state == "ready"


def test_rollback_to_a_release_sharing_with_staging_is_refused(paths, capsys) -> None:
    """The rollback target mounts what is staging's copy; production as it
    ran when the stage was proved did not."""
    from boxmunge.commands.stage_cmd import run_stage
    from boxmunge.project_registry import add_project
    add_project("myapp", paths)
    va, vb = "2026-10-16T080000000000", "2026-10-16T083000000000"
    place_bundle(paths, timestamp=va, files={"VERSION": "va\n", "compose.yml": _SHARING})
    place_bundle(paths, timestamp=vb, files={"VERSION": "vb\n"})
    place_bundle(paths, timestamp=V2, files={
        "compose.yml": SAFE_COMPOSE + "    volumes: ['./uploads:/u']\n"})
    with staging_docker_off():
        assert run_deploy("myapp", paths, ref=va) == 0
        assert run_deploy("myapp", paths, ref=vb) == 0
        assert run_stage("myapp", paths, ref=V2) == 0
        capsys.readouterr()
        assert run_rollback("myapp", paths, yes=True) == 1
    err = capsys.readouterr().err
    assert "share" in err and "Nothing was changed" in err
    assert load_txn(paths, "myapp") is None
    assert (paths.project_dir("myapp") / "VERSION").read_text() == "vb\n"
    assert find_rollback_target(paths, "myapp").ref == f"myapp-{va}"


def test_isolation_scratch_left_by_a_kill_is_swept_by_deploy_and_rollback(paths) -> None:
    prod_and_stage(paths)
    releases = paths.project_releases("myapp")
    (releases / ".isolation-killed").mkdir()
    place_bundle(paths, timestamp=V3, files={"VERSION": "v3\n"})
    with staging_docker_off():
        assert run_deploy("myapp", paths, ref=V3) == 0
    assert not list(releases.glob(".isolation-*"))
    (releases / ".isolation-killed").mkdir()
    with staging_docker_off():
        assert run_rollback("myapp", paths, yes=True) == 0
    assert not list(releases.glob(".isolation-*"))


def test_a_git_slot_is_refused_by_this_build(paths, capsys) -> None:
    prod_and_stage(paths)
    update_meta(paths, "myapp", load_slot(paths, "myapp"), kind="git")
    with staging_docker_off() as docker:
        assert run_promote("myapp", paths) == 1
        docker["up"].assert_not_called()
    assert "it is a git stage" in capsys.readouterr().err
    assert load_txn(paths, "myapp") is None


def test_a_candidate_using_include_is_refused_while_staged(paths, capsys) -> None:
    """Its include would be read from production's files, not its own."""
    prod_and_stage(paths)
    place_bundle(paths, timestamp=V3, files={
        "compose.yml": "include: [extra.yml]\n" + SAFE_COMPOSE,
        "extra.yml": "services:\n  side:\n    image: nginx\n"})
    with staging_docker_off():
        assert run_deploy("myapp", paths, ref=V3) == 1
    err = capsys.readouterr().err
    assert "Unstage first, or remove include/extends" in err
    assert load_txn(paths, "myapp") is None


# -- re-pinned from the old-layout end-to-end tests -----------------------

def test_promote_deploys_the_slot_never_a_newer_inbox_bundle(paths) -> None:
    pdir = prod_and_stage(paths)
    newer = place_bundle(paths, timestamp=V3, files={"VERSION": "v3\n"})
    with staging_docker_off():
        assert run_promote("myapp", paths) == 0
    assert (pdir / "VERSION").read_text() == "v2\n"
    assert newer.exists()


def test_the_displaced_release_becomes_the_rollback_target(paths) -> None:
    prod_and_stage(paths)
    with staging_docker_off():
        assert run_promote("myapp", paths) == 0
    previous = paths.project_releases("myapp") / "previous"
    assert (previous / "VERSION").read_text() == "v1\n"


def test_a_first_stage_then_promote_has_no_rollback_target(paths) -> None:
    from boxmunge.commands.rollback import RollbackUnavailable
    from boxmunge.commands.stage_cmd import run_stage
    from boxmunge.project_registry import add_project
    import pytest
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V2, files={"VERSION": "v2\n"})
    with staging_docker_off():
        assert run_stage("myapp", paths, ref=V2) == 0
        assert run_promote("myapp", paths) == 0
    assert (paths.project_dir("myapp") / "VERSION").read_text() == "v2\n"
    with pytest.raises(RollbackUnavailable, match="no previous release"):
        find_rollback_target(paths, "myapp")


def test_the_pre_promote_snapshot_uses_productions_manifest(paths) -> None:
    from tests.bundle_helpers import manifest_text
    prod_and_stage(paths, prod_files={"manifest.yml": manifest_text(backup="postgres")})
    taken: list[dict] = []
    with staging_docker_off(), fake_backups(taken):
        assert run_promote("myapp", paths) == 0
    assert [m["backup"]["type"] for m in taken] == ["postgres"]
    assert find_rollback_target(paths, "myapp").snapshot == "myapp-p1.tar.gz.age"


def test_a_failed_teardown_after_promote_says_to_unstage(paths, capsys) -> None:
    pdir = prod_and_stage(paths)
    with staging_docker_off() as docker:
        docker["down"].side_effect = DockerError("down failed")
        assert run_promote("myapp", paths) == 1
    err = capsys.readouterr().err
    assert "is live in production" in err and "Run 'unstage myapp' to finish" in err
    assert (pdir / "VERSION").read_text() == "v2\n"
    assert load_slot(paths, "myapp").state == "retired"


def test_dry_run_changes_nothing_even_for_a_retired_slot(paths, capsys) -> None:
    prod_and_stage(paths)
    with staging_docker_off() as docker:
        assert run_promote("myapp", paths, dry_run=True) == 0
        update_meta(paths, "myapp", load_slot(paths, "myapp"), state="retired", switch_rc=0)
        assert run_promote("myapp", paths, dry_run=True) == 0
        docker["up"].assert_not_called()
        docker["down"].assert_not_called()
    assert load_slot(paths, "myapp").state == "retired"
    assert "[DRY RUN] Would finish tearing down staging" in capsys.readouterr().out


# -- fix round 1 -----------------------------------------------------------

def _staged_with_hook_and_backups(paths, tmp_path):
    from tests.bundle_helpers import manifest_text
    from tests.txn_helpers import flaky_hook
    hook = flaky_hook(tmp_path, failures=0)
    return prod_and_stage(
        paths, prod_files={"manifest.yml": manifest_text(backup="postgres")},
        staged_files={"manifest.yml": manifest_text(backup="postgres")
                      + f"deploy:\n  pre_deploy: '{hook}'\n"})


def test_a_promote_killed_as_replace_release_returned_finishes_the_switch(
        paths, tmp_path) -> None:
    """No write separates replace_release returning from `retired`: the
    rerun finishes the switch as from `switching` (spec), once."""
    from tests.txn_helpers import hook_runs
    pdir = _staged_with_hook_and_backups(paths, tmp_path)
    taken: list[dict] = []
    with staging_docker_off() as docker, fake_backups(taken):
        assert crash_at("txn.replaced", lambda: run_promote("myapp", paths)) == 137
        assert load_txn(paths, "myapp").phase == "switching"
        assert load_slot(paths, "myapp").state == "ready"
        assert hook_runs(tmp_path) == 1
        docker["up"].reset_mock()
        assert run_promote("myapp", paths) == 0
        assert docker["up"].called      # the switch is finished
    assert hook_runs(tmp_path) == 1     # the hook is not run again
    assert len(list(paths.project_backups("myapp").glob("*"))) == 1  # one snapshot
    assert (pdir / "VERSION").read_text() == "v2\n"
    assert load_slot(paths, "myapp") is None and load_txn(paths, "myapp") is None


def test_a_promote_killed_after_retiring_only_closes_and_tears_down(paths, tmp_path) -> None:
    from boxmunge.commands import deploy as deploy_mod
    from unittest.mock import patch
    from tests.txn_helpers import hook_runs
    _staged_with_hook_and_backups(paths, tmp_path)
    taken: list[dict] = []
    with staging_docker_off() as docker, fake_backups(taken):
        assert crash_at("txn.switched", lambda: run_promote("myapp", paths)) == 137
        docker["up"].reset_mock()
        with patch.object(deploy_mod, "replace_release") as replace:
            assert run_promote("myapp", paths) == 0
        replace.assert_not_called()
        docker["up"].assert_not_called()
    assert hook_runs(tmp_path) == 1
    assert load_slot(paths, "myapp") is None and load_txn(paths, "myapp") is None


def test_a_rerun_after_a_failed_switch_does_not_claim_success(paths, capsys) -> None:
    prod_and_stage(paths)
    with staging_docker_off() as docker:
        docker["up"].side_effect = DockerError("up failed")
        assert run_promote("myapp", paths) == 1
        assert load_slot(paths, "myapp").switch_rc == 1
        docker["up"].side_effect = None
        capsys.readouterr()
        assert run_promote("myapp", paths) == 1
    out, err = capsys.readouterr()
    assert "promoted to production successfully" not in out
    assert "staging was torn down" in err and "failed after production was switched" in err
    assert "'rollback myapp' returns to" in err
    assert load_slot(paths, "myapp") is None


def test_a_rerun_after_a_successful_switch_reports_success(paths, capsys) -> None:
    prod_and_stage(paths)
    with staging_docker_off() as docker:
        docker["down"].side_effect = DockerError("down failed")
        assert run_promote("myapp", paths) == 1
        assert load_slot(paths, "myapp").switch_rc == 0
        docker["down"].side_effect = None
        capsys.readouterr()
        assert run_promote("myapp", paths) == 0
    assert "promoted to production successfully" in capsys.readouterr().out


def test_a_retired_slot_must_record_its_switch_result(paths) -> None:
    import json
    import pytest
    from boxmunge.staged_release import SlotError
    prod_and_stage(paths)
    meta = slot_dir(paths, "myapp") / "meta.json"
    doc = json.loads(meta.read_text())
    for state, rc in (("retired", None), ("ready", 0), ("retired", True), ("retired", "0")):
        meta.write_text(json.dumps({**doc, "state": state, "switch_rc": rc}))
        with pytest.raises(SlotError, match="switch_rc"):
            load_slot(paths, "myapp")


def test_an_unreadable_slot_under_an_open_promote_names_the_installs_options(
        paths, capsys) -> None:
    prod_and_stage(paths)
    with staging_docker_off():
        assert crash_at("txn.switching", lambda: run_promote("myapp", paths)) == 137
        (slot_dir(paths, "myapp") / "meta.json").write_text("[]")
        capsys.readouterr()
        assert run_promote("myapp", paths) == 1
    err = capsys.readouterr().err
    assert "Stage again" not in err
    assert "promote of myapp-" in err and "'rollback myapp' restores" in err


def test_a_refused_promote_leaves_upgrade_probation_alone(paths) -> None:
    from unittest.mock import patch
    from boxmunge.staging_isolation import StagingIsolationError
    from boxmunge.upgrade_state import read_probation, write_probation
    prod_and_stage(paths)
    write_probation(paths, "9.9.9", "a")
    with staging_docker_off(), patch("boxmunge.commands.deploy_tree.check_install_isolation",
                                     side_effect=StagingIsolationError("shared")):
        assert run_promote("myapp", paths) == 1
    assert read_probation(paths) is not None
    with staging_docker_off():
        assert run_promote("myapp", paths) == 0
    assert read_probation(paths) is None


def test_an_install_without_a_tree_is_refused_while_staged(paths, capsys) -> None:
    from boxmunge.commands.deploy_tree import TreeDeploy, deploy_tree_locked
    prod_and_stage(paths)
    req = TreeDeploy(tree=None, ref="myapp-x", source="bundle", manifest={})
    assert deploy_tree_locked("myapp", paths, req) == 1
    assert "should be unreachable" in capsys.readouterr().err
    assert load_txn(paths, "myapp") is None


def _git_project_with_a_slot(paths):
    import yaml
    from boxmunge.project_registry import add_project
    from boxmunge.staged_release import new_meta, write_meta
    from boxmunge.state import write_state
    add_project("myapp", paths)
    pdir = paths.project_dir("myapp")
    (pdir / "repo").mkdir(parents=True)
    (pdir / "manifest.yml").write_text(yaml.safe_dump({
        "project": "myapp", "hosts": ["myapp.example.com"],
        "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
        "backup": {"type": "none"}}))
    write_state(paths.project_deploy_state("myapp"), {
        "current_ref": "abc", "history": [{"ref": "def", "snapshot": ""}]})
    slot = slot_dir(paths, "myapp")
    (slot / "release").mkdir(parents=True)
    write_meta(slot, new_meta("bundle", "myapp-v2", None))


def test_a_git_deploy_is_refused_while_a_release_is_staged(paths, capsys) -> None:
    from unittest.mock import patch
    _git_project_with_a_slot(paths)
    with patch("boxmunge.commands.deploy.update_repo") as update:
        assert run_deploy("myapp", paths) == 1
    update.assert_not_called()
    assert ("unstage myapp first: git installs cannot yet prove isolation from a staged "
            "release") in capsys.readouterr().err


def test_a_git_rollback_is_refused_while_a_release_is_staged(paths, capsys) -> None:
    from unittest.mock import patch
    _git_project_with_a_slot(paths)
    with patch("boxmunge.commands.deploy.update_repo") as update:
        assert run_rollback("myapp", paths, yes=True) == 1
    update.assert_not_called()
    assert ("unstage myapp first: git installs cannot yet prove isolation from a staged "
            "release") in capsys.readouterr().err
