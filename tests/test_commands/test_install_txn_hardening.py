"""Install transaction edge cases from the review of PR A: crashes inside
abandon and rollback, inherited keep facts, and the commands that must wait."""
from __future__ import annotations

import os
import shutil
from unittest.mock import patch

import pytest

from boxmunge.commands.deploy import run_deploy
from boxmunge.commands.install_abandon import run_abandon
from boxmunge.commands.rollback import run_rollback
from boxmunge.project_registry import add_project
from boxmunge.release_txn import load_txn, options_text
from tests.bundle_helpers import manifest_text, place_bundle
from tests.txn_helpers import crash_at, docker_off, fake_backups, hook_manifest

V1, V2, V3 = ("2026-10-16T090000000000", "2026-10-16T100000000000",
              "2026-10-16T110000000000")
P = "myapp"


def _versions(paths, count=3, **files):
    add_project(P, paths)
    for ts, v in list(zip((V1, V2, V3), ("v1", "v2", "v3")))[:count]:
        place_bundle(paths, timestamp=ts, files={"VERSION": v + "\n", **files.get(v, {})})


def _version(paths) -> str:
    return (paths.project_dir(P) / "VERSION").read_text().strip()


def _rel(paths):
    return paths.project_releases(P)


def _failed_v2(paths):
    """Production v1; v2's hook failed, so its install is open at hook_started."""
    add_project(P, paths)
    place_bundle(paths, timestamp=V1, files={"VERSION": "v1\n",
                                             "manifest.yml": manifest_text(backup="postgres")})
    place_bundle(paths, timestamp=V2, files={"manifest.yml": hook_manifest("false", "postgres")})
    with docker_off(), fake_backups([]):
        assert run_deploy(P, paths, ref=V1) == 0
        assert run_deploy(P, paths, ref=V2) == 1


def _open_at_installed(paths):
    """v1 then v2 deployed (previous = v1); v3 crashed at installed."""
    _versions(paths)
    with docker_off():
        assert run_deploy(P, paths, ref=V1) == 0
        assert run_deploy(P, paths, ref=V2) == 0
        assert crash_at("txn.installed", lambda: run_deploy(P, paths, ref=V3)) == 137


# --- C1: stage and promote wait for an open install --------------------------

def test_stage_refused_while_an_install_is_open(paths, capsys) -> None:
    from boxmunge.commands.stage_cmd import run_stage
    _failed_v2(paths)
    place_bundle(paths, timestamp=V3, files={"VERSION": "v3\n"})
    before = load_txn(paths, P)
    with docker_off(), patch("boxmunge.commands.stage_cmd.caddy_reload"):
        assert run_stage(P, paths, ref=V3) == 1
    assert load_txn(paths, P) == before
    assert not (_rel(paths) / "prestage").exists()
    assert "is open at phase hook_started" in capsys.readouterr().err


def test_the_promote_core_refused_while_an_install_is_open(paths, capsys) -> None:
    from boxmunge.commands.promote_release import deploy_staged_locked
    _failed_v2(paths)
    assert deploy_staged_locked(P, paths).rc == 1
    assert "is open at phase hook_started" in capsys.readouterr().err


def test_options_offer_only_what_exists_in_this_release(paths) -> None:
    _failed_v2(paths)
    text = options_text(P, load_txn(paths, P))
    assert "staged release" not in text and "SHA" not in text
    assert "a different bundle" in text


def test_rerun_names_the_bundle_so_a_newer_one_cannot_take_over(paths) -> None:
    _failed_v2(paths)
    assert f"'prod-deploy {P} --ref {P}-{V2}'" in options_text(P, load_txn(paths, P))


# --- C2 / I3: abandon is idempotent across crashes ---------------------------

def test_abandon_rerun_after_a_crash_before_close(paths) -> None:
    import boxmunge.commands.install_abandon as ia
    _open_at_installed(paths)
    real = ia.discard_dir

    def child():
        def boom(p):
            if p.name == "incoming":
                os._exit(137)
            return real(p)
        with patch.object(ia, "discard_dir", boom):
            run_abandon(P, paths)
    assert crash_at("never", child) == 137
    assert run_abandon(P, paths) == 0
    assert _version(paths) == "v2"
    assert (_rel(paths) / "live.json").read_text() == f'{{"ref": "{P}-{V2}"}}\n'
    assert (_rel(paths) / "previous" / "VERSION").read_text() == "v1\n"


def test_abandon_rerun_after_a_crash_inside_the_restore(paths) -> None:
    import boxmunge.release_keep as rk
    _open_at_installed(paths)
    real = rk.durable_rename_dir

    def child():
        def boom(src, dest):
            if src.name == "previous.superseded":
                os._exit(137)
            return real(src, dest)
        with patch.object(rk, "durable_rename_dir", boom):
            run_abandon(P, paths)
    assert crash_at("never", child) == 137
    assert run_abandon(P, paths) == 0
    assert _version(paths) == "v2"
    assert (_rel(paths) / "previous" / "VERSION").read_text() == "v1\n"
    assert load_txn(paths, P) is None


# --- C3: a rollback that crashed after it succeeded is finished --------------

def test_rollback_rerun_finishes_one_that_crashed_before_closing(paths, capsys) -> None:
    _failed_v2(paths)

    def child():
        with docker_off(), patch("boxmunge.commands.rollback.restore_locked",
                                 lambda *a, **k: 0), \
                patch("boxmunge.commands.rollback.close_txn", lambda *a: os._exit(137)):
            run_rollback(P, paths, yes=True)
    assert crash_at("never", child) == 137
    assert load_txn(paths, P).source == "rollback"
    with docker_off():
        assert run_rollback(P, paths, yes=True) == 0
    assert load_txn(paths, P) is None and _version(paths) == "v1"
    assert not (_rel(paths) / "previous").exists()
    place_bundle(paths, timestamp=V3, files={"VERSION": "v3\n"})
    with docker_off():
        assert run_deploy(P, paths, ref=V3) == 0


def test_discarding_the_previous_release_drops_its_metadata_first(paths) -> None:
    from boxmunge.release import discard_previous_release
    _versions(paths, count=2)
    with docker_off():
        assert run_deploy(P, paths, ref=V1) == 0
        assert run_deploy(P, paths, ref=V2) == 0
    order: list[str] = []
    import boxmunge.release as rel_mod
    real = rel_mod.discard_dir
    with patch.object(rel_mod, "discard_dir",
                      lambda p: (order.append("dir" if (_rel(paths) / "previous.json").exists()
                                              else "dir-after-meta"), real(p))):
        discard_previous_release(paths, P)
    assert order == ["dir-after-meta"]
    assert not (_rel(paths) / "previous").exists()


# --- I1 / I2: what the keep found is carried, not re-read --------------------

def test_abandon_after_a_fix_forward_leaves_no_invented_rollback_target(paths) -> None:
    _versions(paths)
    with docker_off(), fake_backups([]):
        assert run_deploy(P, paths, ref=V1) == 0
        assert crash_at("txn.previous_kept", lambda: run_deploy(P, paths, ref=V2)) == 137
        assert crash_at("txn.installed", lambda: run_deploy(P, paths, ref=V3)) == 137
    assert run_abandon(P, paths) == 0
    assert _version(paths) == "v1"
    assert not (_rel(paths) / "previous").exists()
    assert not (_rel(paths) / "previous.json").exists()


def test_undoing_a_keep_drops_a_previous_dir_the_keep_built(paths) -> None:
    """previous.json without previous/ (a crash inside the old discard)."""
    import boxmunge.release_keep as rk
    _versions(paths)
    with docker_off():
        assert run_deploy(P, paths, ref=V1) == 0
        assert run_deploy(P, paths, ref=V2) == 0
    shutil.rmtree(_rel(paths) / "previous")
    before = (_rel(paths) / "previous.json").read_text()
    real = rk.atomic_write_text

    def failing(path, *a, **k):
        if path.name == "previous.json":
            raise OSError(28, "No space left on device")
        return real(path, *a, **k)
    with docker_off(), patch.object(rk, "atomic_write_text", failing):
        assert run_deploy(P, paths, ref=V3) == 1
    assert not (_rel(paths) / "previous").exists()
    assert (_rel(paths) / "previous.json").read_text() == before


# --- I5: installed code is synced before its phase is recorded ---------------

def test_installed_code_is_synced_before_the_phase_write(paths) -> None:
    import boxmunge.commands.deploy_tree as dt
    _versions(paths, count=2)
    with docker_off():
        assert run_deploy(P, paths, ref=V1) == 0
    events: list[str] = []
    real_sync, real_advance = dt.sync_release_code, dt.advance
    with docker_off(), \
            patch.object(dt, "sync_release_code",
                         lambda d: (events.append("sync"), real_sync(d))), \
            patch.object(dt, "advance",
                         lambda pa, p, t, ph: (events.append(ph), real_advance(pa, p, t, ph))[1]):
        assert run_deploy(P, paths, ref=V2) == 0
    assert events.index("sync") < events.index("installed")


def test_abandon_syncs_the_code_it_put_back(paths) -> None:
    import boxmunge.commands.install_abandon as ia
    _open_at_installed(paths)
    synced: list[str] = []
    real = ia.sync_release_code
    with patch.object(ia, "sync_release_code", lambda d: (synced.append(d.name), real(d))):
        assert run_abandon(P, paths) == 0
    assert synced == [P]


# --- I6: a missing live record is an error, not a traceback ------------------

def test_deploy_without_any_live_record_says_so(paths, capsys) -> None:
    _versions(paths, count=2)
    with docker_off():
        assert run_deploy(P, paths, ref=V1) == 0
    (_rel(paths) / "live.json").unlink()
    paths.project_deploy_state(P).unlink()
    with docker_off():
        assert run_deploy(P, paths, ref=V2) == 1
    assert "No record of which release is installed" in capsys.readouterr().err
    assert load_txn(paths, P) is None


def test_rollback_without_any_live_record_says_so(paths, capsys) -> None:
    _versions(paths, count=2)
    with docker_off():
        assert run_deploy(P, paths, ref=V1) == 0
        assert run_deploy(P, paths, ref=V2) == 0
    (_rel(paths) / "live.json").unlink()
    paths.project_deploy_state(P).unlink()
    with docker_off():
        assert run_rollback(P, paths, yes=True) == 1
    assert "No record of which release is installed" in capsys.readouterr().err
    assert load_txn(paths, P) is None


# --- minors -----------------------------------------------------------------

def test_bundle_gone_message_does_not_offer_a_rerun_that_cannot_work(paths, capsys) -> None:
    _versions(paths, count=2)
    bundle = paths.inbox / f"{P}-{V2}.tar.gz"
    with docker_off():
        assert run_deploy(P, paths, ref=V1) == 0
        assert crash_at("txn.committed", lambda: run_deploy(P, paths, ref=V2)) == 137
    bundle.unlink()
    capsys.readouterr()
    with docker_off():
        assert run_deploy(P, paths) == 1
    err = capsys.readouterr().err
    assert "Upload" in err and "--abandon" in err and "to finish it" not in err


def test_first_deploy_abandon_refusal_names_no_phantom_release(paths, capsys) -> None:
    add_project(P, paths)
    place_bundle(paths, timestamp=V1, files={"manifest.yml": hook_manifest("false")})
    with docker_off():
        assert run_deploy(P, paths, ref=V1) == 1
    capsys.readouterr()
    assert run_abandon(P, paths) == 1
    err = capsys.readouterr().err
    assert "None" not in err and "no snapshot" not in err and "deploy a fix" in err


def test_abandon_of_a_first_deploy_reports_the_code_removed(paths, capsys) -> None:
    add_project(P, paths)
    place_bundle(paths, timestamp=V1)
    with docker_off():
        assert crash_at("txn.installed", lambda: run_deploy(P, paths, ref=V1)) == 137
    assert run_abandon(P, paths) == 0
    out = capsys.readouterr().out
    assert "empty project" not in out and "removed" in out


def test_rollback_config_failure_leaves_it_open_and_says_so(paths, capsys) -> None:
    _failed_v2(paths)
    with docker_off(), patch("boxmunge.commands.rollback.restore_locked", lambda *a, **k: 0), \
            patch("boxmunge.commands.rollback.generate_release_config",
                  side_effect=OSError("disk full")):
        assert run_rollback(P, paths, yes=True) == 1
    assert load_txn(paths, P).source == "rollback"
    assert "disk full" in capsys.readouterr().err


def test_discarded_debris_is_swept_by_the_next_install(paths) -> None:
    _versions(paths, count=2)
    with docker_off():
        assert run_deploy(P, paths, ref=V1) == 0
    debris = _rel(paths) / "previous.superseded.discarded"
    debris.mkdir()
    (debris / "junk").write_text("x")
    with docker_off():
        assert run_deploy(P, paths, ref=V2) == 0
    assert not debris.exists()


def test_rollback_refused_before_the_prompt_while_an_install_is_open(paths, capsys) -> None:
    _versions(paths, count=2)
    with docker_off():
        assert run_deploy(P, paths, ref=V1) == 0
        assert crash_at("txn.installed", lambda: run_deploy(P, paths, ref=V2)) == 137
    with patch("builtins.input", side_effect=AssertionError("prompted")):
        assert run_rollback(P, paths, yes=False) == 1
    assert "nothing to roll back" in capsys.readouterr().err


def test_restore_refused_before_the_prompt_while_an_install_is_open(paths, capsys) -> None:
    from boxmunge.commands.restore import run_restore
    _failed_v2(paths)
    paths.backup_key.parent.mkdir(parents=True, exist_ok=True)
    paths.backup_key.write_text("key")    # everything a restore plan needs is there
    with patch("builtins.input", side_effect=AssertionError("prompted")):
        assert run_restore(P, paths, yes=False) == 1
    assert f"{P}-{V2}" in capsys.readouterr().err


@pytest.mark.parametrize("files", [{}, {"manifest.yml": hook_manifest("false")}])
def test_dry_run_says_what_a_bundle_less_rerun_would_do(paths, capsys, files) -> None:
    """A resumable install (hook failed after `installed`) would resume; one
    stopped before `installed` with its bundle gone would be refused."""
    _versions(paths, count=2, v2=files)
    with docker_off():
        assert run_deploy(P, paths, ref=V1) == 0
        if files:
            assert run_deploy(P, paths, ref=V2) == 1
        else:
            assert crash_at("txn.previous_kept", lambda: run_deploy(P, paths, ref=V2)) == 137
            (paths.inbox / f"{P}-{V2}.tar.gz").unlink()
    capsys.readouterr()
    rc = run_deploy(P, paths, dry_run=True)
    out = capsys.readouterr()
    if files:
        assert rc == 0 and "[DRY RUN] Would resume" in out.out
    else:
        assert rc == 1 and "Would resume" not in out.out and "cannot be resumed" in out.err


def test_rollback_syncs_the_code_it_installed_before_recording_it(paths) -> None:
    import boxmunge.commands.rollback as rb
    _failed_v2(paths)
    events: list[str] = []
    real_sync, real_advance = rb.sync_release_code, rb.advance
    with docker_off(), patch("boxmunge.commands.rollback.restore_locked", lambda *a, **k: 0), \
            patch.object(rb, "sync_release_code",
                         lambda d: (events.append("sync"), real_sync(d))), \
            patch.object(rb, "advance",
                         lambda pa, p, t, ph: (events.append(ph), real_advance(pa, p, t, ph))[1]):
        assert run_rollback(P, paths, yes=True) == 0
    assert events.index("sync") < events.index("installed")
