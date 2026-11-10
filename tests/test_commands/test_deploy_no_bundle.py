"""prod-deploy with no new bundle in the inbox is refused, not a silent
redeploy of the installed release; --redeploy asks for that on purpose."""
from __future__ import annotations

from boxmunge.commands.deploy import run_deploy
from boxmunge.commands.deploy_no_bundle import redeploy_problem
from boxmunge.project_registry import add_project
from boxmunge.state import read_state
from tests.bundle_helpers import place_bundle
from tests.stage_helpers import V1, V2, prod_and_stage, staging_docker_off
from tests.txn_helpers import docker_off


def _prod_v1(paths) -> None:
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1, files={"VERSION": "v1\n"})
    with docker_off():
        assert run_deploy("myapp", paths, ref=V1) == 0


def _current_ref(paths) -> str:
    return read_state(paths.project_deploy_state("myapp"))["current_ref"]


def test_after_a_stage_prod_deploy_names_promote_and_changes_nothing(paths, capsys) -> None:
    prod_and_stage(paths)
    capsys.readouterr()
    with staging_docker_off() as docker:
        assert run_deploy("myapp", paths) == 1
        docker["up"].assert_not_called()
    err = capsys.readouterr().err
    assert "No new bundle for 'myapp' in the inbox" in err
    assert f"myapp-{V2} is staged" in err and "'promote myapp'" in err
    assert "'prod-deploy myapp --redeploy'" in err and "Nothing was changed" in err
    assert _current_ref(paths) == f"myapp-{V1}"


def test_without_a_stage_it_names_the_upload_and_redeploy(paths, capsys) -> None:
    _prod_v1(paths)
    capsys.readouterr()
    with docker_off() as up:
        assert run_deploy("myapp", paths) == 1
        assert run_deploy("myapp", paths, dry_run=True) == 1
        up.assert_not_called()
    err = capsys.readouterr().err
    assert "upload its bundle" in err and f"(myapp-{V1})" in err
    assert "promote" not in err


def test_redeploy_deploys_the_installed_release_again(paths, capsys) -> None:
    _prod_v1(paths)
    with docker_off() as up:
        assert run_deploy("myapp", paths, redeploy=True) == 0
        up.assert_called()
    assert _current_ref(paths) == f"myapp-{V1}"
    assert "deployed successfully" in capsys.readouterr().out


def test_redeploy_leaves_a_waiting_bundle_in_the_inbox_and_says_so(paths, capsys) -> None:
    _prod_v1(paths)
    waiting = place_bundle(paths, timestamp=V2, files={"VERSION": "v2\n"})
    with docker_off():
        assert run_deploy("myapp", paths, redeploy=True) == 0
    assert waiting.exists()
    assert f"{waiting.name} is waiting in the inbox" in capsys.readouterr().out
    assert (paths.project_dir("myapp") / "VERSION").read_text() == "v1\n"


def test_redeploy_of_a_project_never_deployed_is_refused(paths, capsys) -> None:
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1)
    with docker_off():
        assert run_deploy("myapp", paths, redeploy=True) == 1
    assert "has none yet" in capsys.readouterr().err
    assert not (paths.project_dir("myapp") / "manifest.yml").exists()


def test_redeploy_with_a_ref_is_refused(paths, capsys) -> None:
    _prod_v1(paths)
    with docker_off():
        assert run_deploy("myapp", paths, ref=V1, redeploy=True) == 1
    assert f"'prod-deploy myapp --ref {V1}'" in capsys.readouterr().err


def test_redeploy_is_refused_for_a_git_project_naming_its_installed_commit(paths) -> None:
    from boxmunge.state import write_state
    (paths.project_dir("myapp") / "repo").mkdir(parents=True)
    write_state(paths.project_deploy_state("myapp"), {"current_ref": "a" * 40})
    problem = redeploy_problem("myapp", paths, git=True, ref=None)
    assert problem and "git project" in problem
    assert f"'prod-deploy myapp --ref {'a' * 40}'" in problem
    assert redeploy_problem("myapp", paths, git=False, ref=None) is None


def test_redeploy_before_a_first_deploy_names_the_waiting_bundle(paths, capsys) -> None:
    add_project("myapp", paths)
    waiting = place_bundle(paths, timestamp=V1)
    with docker_off():
        assert run_deploy("myapp", paths, redeploy=True) == 1
    err = capsys.readouterr().err
    assert f"{waiting.name}, is waiting in the inbox" in err and "'prod-deploy myapp'" in err
    assert "Upload its first bundle" not in err


def test_redeploy_finishes_an_open_first_install(paths, capsys) -> None:
    """A first install that stopped after its code was in place: there is
    no installed release yet, so --redeploy resumes it."""
    from tests.txn_helpers import crash_at
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1)
    with docker_off():
        assert crash_at("txn.installed", lambda: run_deploy("myapp", paths, ref=V1)) == 137
        assert run_deploy("myapp", paths, redeploy=True) == 0
    assert "--redeploy finishes it first" in capsys.readouterr().out
    assert _current_ref(paths) == f"myapp-{V1}"


def test_redeploy_with_an_open_non_bundle_install_does_not_claim_to_finish_it(
        paths, capsys) -> None:
    """--redeploy only finishes an open bundle install; with a rollback
    open it is refused, so it must not first say it will finish it."""
    from boxmunge.release_txn import open_txn
    _prod_v1(paths)
    open_txn(paths, "myapp", source="rollback", ref=f"myapp-{V1}", replaced_ref=None,
             staged_id=None, snapshot="")
    capsys.readouterr()
    with docker_off():
        assert run_deploy("myapp", paths, redeploy=True) == 1
    captured = capsys.readouterr()
    assert "finishes it first" not in captured.out
    assert captured.err


def test_a_refused_deploy_leaves_upgrade_probation_alone(paths, monkeypatch) -> None:
    _prod_v1(paths)
    cleared: list[str] = []
    monkeypatch.setattr("boxmunge.commands.deploy_steps.clear_probation_if_active",
                        lambda p, component: cleared.append(component))
    with docker_off():
        assert run_deploy("myapp", paths) == 1
        assert run_deploy("myapp", paths, redeploy=True, dry_run=True) == 0
        assert cleared == []
        assert run_deploy("myapp", paths, redeploy=True) == 0
    assert cleared == ["deploy"]
