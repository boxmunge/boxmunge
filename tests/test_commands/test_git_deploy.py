"""Git deploys: a resolved full SHA, one install transaction, the snapshot
taken with the live manifest before the checkout (spec 'Git-sourced
projects'; plan Task 30)."""
from __future__ import annotations

from boxmunge.commands.deploy import run_deploy
from boxmunge.commands.install_abandon import run_abandon
from boxmunge.commands.stage_cmd import run_stage
from boxmunge.release_txn import load_txn, options_text, stale_reason
from boxmunge.staged_release import load_slot
from boxmunge.state import read_state
from tests.bundle_helpers import SAFE_COMPOSE
from tests.git_helpers import commit, git
from tests.git_project_helpers import git_manifest, git_project
from tests.stage_helpers import staging_docker_off
from tests.txn_helpers import crash_at, fake_backups, flaky_hook, hook_runs


def _head(pdir) -> str:
    return git("rev-parse", "HEAD", cwd=pdir / "repo")


def test_deploys_the_remote_tip_as_a_full_sha(paths, tmp_path) -> None:
    pdir, work = git_project(paths, tmp_path)
    tip = commit(work, {"VERSION": "B\n"}, "B")
    with staging_docker_off():
        assert run_deploy("myapp", paths) == 0
    assert _head(pdir) == tip
    assert git("status", "--porcelain", cwd=pdir / "repo") == ""
    state = read_state(paths.project_deploy_state("myapp"))
    assert state["current_ref"] == tip and len(state["history"][0]["ref"]) == 40
    assert load_txn(paths, "myapp") is None


def test_an_abbreviated_sha_is_refused(paths, tmp_path, capsys) -> None:
    pdir, work = git_project(paths, tmp_path)
    before = _head(pdir)
    tip = commit(work, {"VERSION": "B\n"}, "B")
    with staging_docker_off():
        assert run_deploy("myapp", paths, ref=tip[:8]) == 1
    assert "40 characters" in capsys.readouterr().err and _head(pdir) == before


def test_a_dry_run_names_the_sha_and_changes_nothing(paths, tmp_path, capsys) -> None:
    pdir, work = git_project(paths, tmp_path)
    before = _head(pdir)
    tip = commit(work, {"VERSION": "B\n"}, "B")
    with staging_docker_off():
        assert run_deploy("myapp", paths, dry_run=True) == 0
    assert f"Would deploy myapp at main ({tip})" in capsys.readouterr().out
    assert _head(pdir) == before and load_txn(paths, "myapp") is None


def test_snapshot_uses_the_live_manifest_before_the_checkout(paths, tmp_path) -> None:
    pdir, work = git_project(paths, tmp_path, backup="postgres")
    commit(work, {"manifest.yml": git_manifest(tmp_path / "origin.git", backup="none")},
           "drop backups")
    taken: list[dict] = []
    with staging_docker_off(), fake_backups(taken):
        assert run_deploy("myapp", paths) == 0
    assert [m["backup"]["type"] for m in taken] == ["postgres"]


def test_abandon_checks_the_replaced_commit_out_again(paths, tmp_path, capsys) -> None:
    pdir, work = git_project(paths, tmp_path)
    before = _head(pdir)
    commit(work, {"VERSION": "B\n"}, "B")
    with staging_docker_off():
        assert crash_at("txn.installed", lambda: run_deploy("myapp", paths)) == 137
        assert run_abandon("myapp", paths) == 0
    assert _head(pdir) == before and load_txn(paths, "myapp") is None
    assert f"{before}'s files are back" in capsys.readouterr().out


def test_a_rerun_of_the_same_sha_resumes_without_a_second_snapshot(paths, tmp_path) -> None:
    pdir, work = git_project(paths, tmp_path, backup="postgres")
    tip = commit(work, {"VERSION": "B\n"}, "B")
    taken: list[dict] = []
    with staging_docker_off(), fake_backups(taken):
        assert crash_at("txn.installed", lambda: run_deploy("myapp", paths)) == 137
        txn = load_txn(paths, "myapp")
        assert txn.source == "git" and txn.ref == tip and txn.phase == "installed"
        assert f"'prod-deploy myapp --ref {tip}'" in options_text("myapp", txn)
        assert run_deploy("myapp", paths, ref=tip) == 0
    # The crashed child took the only snapshot (its list is the child's own).
    assert txn.snapshot and taken == []
    assert [p.name for p in paths.project_backups("myapp").iterdir()] == [txn.snapshot]
    assert _head(pdir) == tip and load_txn(paths, "myapp") is None
    assert read_state(paths.project_deploy_state("myapp"))["pre_deploy_snapshot"] == \
        txn.snapshot


def test_a_failed_hook_reruns_on_resume(paths, tmp_path) -> None:
    pdir, work = git_project(paths, tmp_path)
    origin = tmp_path / "origin.git"
    hook = flaky_hook(tmp_path, failures=1)
    tip = commit(work, {"manifest.yml": git_manifest(
        origin, extra=f"deploy:\n  pre_deploy: '{hook}'\n")}, "hooked")
    with staging_docker_off():
        assert run_deploy("myapp", paths) == 1
        assert load_txn(paths, "myapp").phase == "hook_started"
        assert run_deploy("myapp", paths, ref=tip) == 0
    assert hook_runs(tmp_path) == 2 and load_txn(paths, "myapp") is None


def test_a_different_commit_fixes_forward_and_inherits_the_pairing(paths, tmp_path) -> None:
    pdir, work = git_project(paths, tmp_path)
    a = _head(pdir)
    origin = tmp_path / "origin.git"
    commit(work, {"manifest.yml": git_manifest(origin, extra="deploy:\n  pre_deploy: 'false'\n")},
           "bad")
    with staging_docker_off():
        assert run_deploy("myapp", paths) == 1
        failed = load_txn(paths, "myapp")
        fix = commit(work, {"manifest.yml": git_manifest(origin)}, "fix")
        assert run_deploy("myapp", paths) == 0
    assert _head(pdir) == fix and load_txn(paths, "myapp") is None
    state = read_state(paths.project_deploy_state("myapp"))
    assert failed.replaced_ref == a and state["history"][0]["ref"] == a


def test_moved_head_makes_the_install_stale(paths, tmp_path) -> None:
    pdir, work = git_project(paths, tmp_path)
    b = commit(work, {"VERSION": "B\n"}, "B")
    c = commit(work, {"VERSION": "C\n"}, "C")
    with staging_docker_off():
        assert crash_at("txn.installed", lambda: run_deploy("myapp", paths, ref=b)) == 137
    git("checkout", "-q", "--detach", c, cwd=pdir / "repo")
    txn = load_txn(paths, "myapp")
    assert f"repo/ is checked out at {c}" in stale_reason(paths, "myapp", txn)
    with staging_docker_off():
        assert run_deploy("myapp", paths, ref=b) == 1
        assert run_abandon("myapp", paths) == 1
    assert _head(pdir) == c


def test_a_git_deploy_during_a_stage_proves_isolation_and_leaves_staging(paths,
                                                                        tmp_path) -> None:
    pdir, work = git_project(paths, tmp_path)
    staged = commit(work, {"VERSION": "staged\n"}, "staged")
    with staging_docker_off():
        assert run_stage("myapp", paths) == 0
        hotfix = commit(work, {"VERSION": "hotfix\n"}, "hotfix")
        assert run_deploy("myapp", paths) == 0
    assert _head(pdir) == hotfix
    meta = load_slot(paths, "myapp")
    assert meta.ref == staged and meta.state == "ready"
    assert not list(paths.project_releases("myapp").glob(".isolation-*"))


def test_a_git_deploy_sharing_with_staging_is_refused(paths, tmp_path, capsys) -> None:
    uploads = SAFE_COMPOSE + "    volumes: ['./uploads:/u']\n"
    pdir, work = git_project(paths, tmp_path, compose=uploads)
    before = _head(pdir)
    with staging_docker_off():
        assert run_stage("myapp", paths) == 0
        commit(work, {"compose.yml": SAFE_COMPOSE + "    volumes: ['./uploads-staging:/u']\n"},
               "share")
        assert run_deploy("myapp", paths) == 1
    err = capsys.readouterr().err
    assert "share" in err and "Nothing was changed" in err
    assert _head(pdir) == before and load_txn(paths, "myapp") is None


def test_a_commit_whose_manifest_is_a_link_is_not_deployed(paths, tmp_path, capsys) -> None:
    import os
    pdir, work = git_project(paths, tmp_path)
    before = _head(pdir)
    (work / "conf").mkdir()
    os.rename(work / "manifest.yml", work / "conf" / "manifest.yml")
    os.symlink("conf/manifest.yml", work / "manifest.yml")
    commit(work, {}, "linked manifest")
    with staging_docker_off():
        assert run_deploy("myapp", paths) == 1
        assert run_deploy("myapp", paths, dry_run=True) == 1
    assert "manifest.yml at" in capsys.readouterr().err
    assert _head(pdir) == before and load_txn(paths, "myapp") is None


def test_an_unreadable_record_during_a_stage_refuses_the_deploy_cleanly(paths, tmp_path,
                                                                        capsys) -> None:
    pdir, work = git_project(paths, tmp_path)
    before = _head(pdir)
    commit(work, {"VERSION": "staged\n"}, "staged")
    with staging_docker_off():
        assert run_stage("myapp", paths) == 0
    commit(work, {"VERSION": "hotfix\n"}, "hotfix")
    (pdir / ".releases" / "data-dirs.json").write_text("{not json")
    with staging_docker_off():
        assert run_deploy("myapp", paths) == 1
    err = capsys.readouterr().err
    assert "data-dirs.json" in err and "Nothing was changed" in err
    assert _head(pdir) == before and load_txn(paths, "myapp") is None


def test_a_quarantined_git_project_ships_its_fix_through_the_scan(paths, tmp_path, capsys,
                                                                  monkeypatch) -> None:
    """The git install core reaches the same scan (commands/quarantine_gate)
    before the hook: a refusal leaves the install abandonable at
    `installed`; a clean commit deploys and lifts the quarantine."""
    from boxmunge.commands import quarantine_gate
    from boxmunge.cve.quarantine import clear_quarantine_state, is_quarantined
    from tests.test_commands.cve_helpers import make_clearance, seed_quarantine
    pdir, work = git_project(paths, tmp_path)
    before = _head(pdir)
    seed_quarantine(paths, "myapp")
    bad = commit(work, {"VERSION": "bad\n"}, "still vulnerable")

    def scan(paths_, target, manifest, previous):
        if _head(pdir) == bad:
            raise quarantine_gate.QuarantineRefused(["CVE-2026-0001 in openssl, service web"])
        return make_clearance("myapp")
    monkeypatch.setattr("boxmunge.commands.release_config.clear_release", scan)
    monkeypatch.setattr("boxmunge.commands.deploy_tree.require_unchanged", lambda *a: None)
    monkeypatch.setattr(quarantine_gate, "_verify_running", lambda *a, **k: {})
    monkeypatch.setattr(quarantine_gate, "_release_policies", lambda *a: {})
    monkeypatch.setattr(quarantine_gate, "lift_quarantine",
                        lambda project, paths_, **kw: clear_quarantine_state(project, paths_))
    with staging_docker_off():
        assert run_deploy("myapp", paths) == 1
        assert "CVE-2026-0001 in openssl, service web" in capsys.readouterr().err
        assert load_txn(paths, "myapp").phase == "installed"
        assert run_abandon("myapp", paths) == 0
        assert _head(pdir) == before and is_quarantined("myapp", paths)
        fixed = commit(work, {"VERSION": "fixed\n"}, "fixed")
        assert run_deploy("myapp", paths) == 0
    assert _head(pdir) == fixed and not is_quarantined("myapp", paths)
    assert "lifted by deploying" in capsys.readouterr().out
