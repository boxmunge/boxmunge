"""A fix-forward carries what the attempts it replaced may have done; the
open install's other readers (backup, upgrade, bundle-less resume) respect it."""
from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from boxmunge.commands.deploy import run_deploy
from boxmunge.commands.install_abandon import run_abandon
from boxmunge.commands.rollback import run_rollback
from boxmunge.project_registry import add_project
from boxmunge.release_txn import load_txn, stale_reason
from boxmunge.state import read_state
from tests.bundle_helpers import manifest_text, place_bundle
from tests.txn_helpers import crash_at, docker_off, fake_backups, hook_manifest

V1, V2, V3, V4 = ("2026-10-16T090000000000", "2026-10-16T100000000000",
                  "2026-10-16T110000000000", "2026-10-16T120000000000")
P = "myapp"


def _rel(paths):
    return paths.project_releases(P)


def _version(paths) -> str:
    return (paths.project_dir(P) / "VERSION").read_text().strip()


def _v1_then(paths, v2_files):
    add_project(P, paths)
    place_bundle(paths, timestamp=V1, files={"VERSION": "v1\n",
                                             "manifest.yml": manifest_text(backup="postgres")})
    place_bundle(paths, timestamp=V2, files={"VERSION": "v2\n", **v2_files})
    place_bundle(paths, timestamp=V3, files={"VERSION": "v3\n",
                                             "manifest.yml": manifest_text(backup="postgres")})
    with docker_off(), fake_backups([]):
        assert run_deploy(P, paths, ref=V1) == 0


def _v3_install_fails(paths):
    with docker_off(), fake_backups([], prefix="v3-"), \
            patch("boxmunge.commands.deploy_tree.install_release",
                  side_effect=OSError("disk full")):
        assert run_deploy(P, paths, ref=V3) == 1


@pytest.mark.parametrize("how", ["hook_failed", "containers_started", "rollback_started"])
def test_a_fix_forward_after_data_may_have_changed_is_not_abandonable(paths, capsys, how) -> None:
    if how == "hook_failed":
        _v1_then(paths, {"manifest.yml": hook_manifest("false", "postgres")})
        with docker_off(), fake_backups([]):
            assert run_deploy(P, paths, ref=V2) == 1
    elif how == "containers_started":
        _v1_then(paths, {"manifest.yml": manifest_text(backup="postgres")})
        with docker_off(), fake_backups([]):
            assert crash_at("txn.replaced", lambda: run_deploy(P, paths, ref=V2)) == 137
    else:
        _v1_then(paths, {"manifest.yml": hook_manifest("false", "postgres")})
        with docker_off(), fake_backups([]):
            assert run_deploy(P, paths, ref=V2) == 1
            assert crash_at("rollback.committed",
                            lambda: run_rollback(P, paths, yes=True)) == 137
    _v3_install_fails(paths)
    assert load_txn(paths, P).ref == f"{P}-{V3}"
    capsys.readouterr()
    assert run_abandon(P, paths) == 1
    assert "rollback myapp" in capsys.readouterr().err
    assert load_txn(paths, P) is not None
    restored: list[str] = []
    with docker_off(), patch("boxmunge.commands.rollback.restore_locked",
                             lambda p, pa, snapshot, txn=None: restored.append(snapshot) or 0):
        assert run_rollback(P, paths, yes=True) == 0
    assert _version(paths) == "v1" and restored == [f"{P}-p1.tar.gz.age"]


def test_backups_skip_when_an_earlier_attempt_started_containers(paths) -> None:
    from boxmunge.backup_source import backup_source
    _v1_then(paths, {"manifest.yml": manifest_text(backup="postgres")})
    with docker_off(), fake_backups([]):
        assert crash_at("txn.replaced", lambda: run_deploy(P, paths, ref=V2)) == 137
    _v3_install_fails(paths)
    src = backup_source(paths, P)
    assert src.manifest is None and src.alert


def test_a_backup_during_an_install_execs_with_the_running_releases_compose(paths) -> None:
    from boxmunge.commands.backup_cmd import backup_locked
    _v1_then(paths, {"manifest.yml": manifest_text(backup="postgres")})
    with docker_off(), fake_backups([]):
        assert crash_at("txn.installed", lambda: run_deploy(P, paths, ref=V2)) == 137
    paths.backup_key.parent.mkdir(parents=True, exist_ok=True)
    paths.backup_key.write_text("key")
    seen: list[list[str]] = []

    def fake_run(cmd, **kw):
        seen.append(cmd)
        raise OSError("stop here")
    with patch("boxmunge.service_exec.subprocess.run", fake_run):
        assert backup_locked(P, paths) == 1
    cmd = seen[0]
    pdir = paths.project_dir(P)
    assert cmd[cmd.index("--project-directory") + 1] == str(pdir)
    assert cmd[cmd.index("-f") + 1] == str(_rel(paths) / "previous" / "compose.yml")


def test_a_bare_rerun_never_resumes_over_a_partial_abandon(paths, capsys) -> None:
    import boxmunge.commands.install_abandon as ia
    _v1_then(paths, {})
    with docker_off():
        assert crash_at("txn.installed", lambda: run_deploy(P, paths, ref=V2)) == 137
    real = ia.install_release

    def child():
        def half(tree, dest, *a, **k):
            real(tree, dest, *a, **k)
            os._exit(137)          # code back, live.json not yet
        with patch.object(ia, "install_release", half):
            run_abandon(P, paths)
    assert crash_at("never", child) == 137
    (paths.inbox / f"{P}-{V2}.tar.gz").unlink(missing_ok=True)
    with docker_off():
        assert run_deploy(P, paths) == 1
    assert read_state(paths.project_deploy_state(P))["current_ref"] == f"{P}-{V1}"
    assert "--abandon" in capsys.readouterr().err
    assert run_abandon(P, paths) == 0 and _version(paths) == "v1"


def test_abandon_through_a_supersede_chain_is_never_stale(paths) -> None:
    import boxmunge.commands.install_abandon as ia
    add_project(P, paths)
    for ts, v in ((V1, "v1"), (V2, "v2"), (V3, "v3"), (V4, "v4")):
        place_bundle(paths, timestamp=ts, files={"VERSION": v + "\n"})
    with docker_off():
        assert run_deploy(P, paths, ref=V1) == 0
        assert run_deploy(P, paths, ref=V2) == 0           # previous = v1
        assert crash_at("txn.previous_kept", lambda: run_deploy(P, paths, ref=V3)) == 137
        assert crash_at("txn.installed", lambda: run_deploy(P, paths, ref=V4)) == 137
    real = ia.discard_dir

    def child():
        def boom(p):
            if p.name == "incoming":
                os._exit(137)
            return real(p)
        with patch.object(ia, "discard_dir", boom):
            run_abandon(P, paths)
    assert crash_at("never", child) == 137
    assert stale_reason(paths, P, load_txn(paths, P)) is None
    assert run_abandon(P, paths) == 0
    assert _version(paths) == "v2"
    assert (_rel(paths) / "previous" / "VERSION").read_text() == "v1\n"


def test_over_a_rollback_a_crash_before_pairing_is_repaired(paths) -> None:
    """The fix-forward recorded its fresh snapshot, previous.json still
    names the rollback's: the next reader pairs them before using them."""
    import boxmunge.commands.deploy_tree as dt
    _v1_then(paths, {"manifest.yml": hook_manifest("false", "postgres")})
    with docker_off(), fake_backups([]):
        assert run_deploy(P, paths, ref=V2) == 1
    with docker_off(), patch("boxmunge.commands.rollback.restore_locked", lambda *a, **k: 0):
        assert crash_at("rollback.data_restored",
                        lambda: run_rollback(P, paths, yes=True)) == 137
    real = dt.ensure_kept_pairing

    def child():
        def boom(paths_, project, txn):
            if txn.source != "rollback":
                os._exit(137)
            return real(paths_, project, txn)
        with docker_off(), fake_backups([], prefix="fresh"), \
                patch.object(dt, "ensure_kept_pairing", boom):
            run_deploy(P, paths, ref=V3)
    assert crash_at("never", child) == 137
    assert load_txn(paths, P).snapshot == f"{P}-fresh1.tar.gz.age"
    restored: list[str] = []
    with docker_off(), patch("boxmunge.commands.rollback.restore_locked",
                             lambda p, pa, snapshot, txn=None: restored.append(snapshot) or 0):
        assert run_rollback(P, paths, yes=True) == 0
    assert restored == [f"{P}-fresh1.tar.gz.age"]


def test_the_upgrade_leaves_an_open_install_alone(paths) -> None:
    from boxmunge.commands.upgrade_steps import regenerate_configs, restart_projects
    _v1_then(paths, {"manifest.yml": hook_manifest("false", "postgres")})
    with docker_off(), fake_backups([]):
        assert run_deploy(P, paths, ref=V2) == 1
    overlay = paths.project_compose_override(P)
    before = overlay.read_text()
    with docker_off() as up, \
            patch("boxmunge.commands.upgrade_steps.prepare_compose_override") as regen_overlay:
        regen = regenerate_configs(paths)
        restart = restart_projects(paths, refused=regen.refused)
    regen_overlay.assert_not_called()
    up.assert_not_called()
    assert P in regen.install_open and restart.install_open == [P]
    assert restart.start_refused == [] and overlay.read_text() == before
