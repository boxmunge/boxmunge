# SPDX-License-Identifier: Apache-2.0
"""The apply leaves legacy, mid-install and busy projects exactly as they are."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from boxmunge.commands.upgrade_cmd import _run_apply, _run_dry
from boxmunge.commands.upgrade_steps import check_upgrade, restart_projects
from boxmunge.fileutil import project_lock
from boxmunge.manifest import ManifestError
from boxmunge.release_txn import open_txn
from boxmunge.upgrade_exclusions import Exclusions, apply_projects, notify_exclusions
from tests.bundle_helpers import tree_snapshot
from tests.legacy_helpers import legacy_bundle_stage
from tests.stage_helpers import V1, staging_docker_off

LEGACY_DRY_LINE = ("myapp: a release staged by boxmunge 0.10.1 (bundle) will be left as is; "
                   "after the upgrade, resolve it with boxmunge-server legacy-stage myapp")


def _deployed(paths) -> None:
    from boxmunge.commands.deploy import run_deploy
    from boxmunge.project_registry import add_project
    from tests.bundle_helpers import place_bundle
    from tests.txn_helpers import docker_off
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1)
    with docker_off():
        assert run_deploy("myapp", paths, ref=V1) == 0


def _open_install(paths):
    return open_txn(paths, "myapp", source="bundle", ref="myapp-x",
                    replaced_ref=f"myapp-{V1}", staged_id=None, snapshot="")


def test_legacy_project_left_byte_identical(paths) -> None:
    pdir = legacy_bundle_stage(paths)
    before = tree_snapshot(pdir)
    with staging_docker_off() as docker, \
            patch("boxmunge.legacy_stage.notify", return_value=True):
        migration, regen, excluded = apply_projects(paths)
        restart = restart_projects(paths, refused=regen.refused, excluded=excluded.names())
    assert excluded.legacy == {"myapp": "bundle"} and regen.processed == []
    assert migration.written == [] and restart.start_refused == []
    assert tree_snapshot(pdir) == before
    docker["up"].assert_not_called()


def test_open_install_excluded(paths) -> None:
    _deployed(paths)
    _open_install(paths)
    overlay = paths.project_compose_override("myapp")
    before = overlay.read_text()
    with patch("boxmunge.commands.upgrade_steps.prepare_compose_override") as regen_overlay:
        _m, regen, excluded = apply_projects(paths)
    regen_overlay.assert_not_called()
    assert "an install of myapp-x (bundle) is open" in excluded.install["myapp"]
    assert regen.processed == [] and overlay.read_text() == before


def test_busy_project_excluded_without_waiting(paths) -> None:
    legacy_bundle_stage(paths)
    with project_lock("myapp", paths):
        _m, _r, excluded = apply_projects(paths)
    assert excluded.busy == ["myapp"] and excluded.legacy == {}


def test_excluded_projects_are_not_restarted(paths) -> None:
    _deployed(paths)
    with staging_docker_off() as docker:
        restart = restart_projects(paths, refused={}, excluded={"myapp"})
    docker["up"].assert_not_called()
    assert restart.succeeded == [] and restart.start_refused == []


def test_each_legacy_project_is_alerted_once(paths) -> None:
    legacy_bundle_stage(paths)
    with patch("boxmunge.legacy_stage.notify", return_value=True) as alert, \
            patch("boxmunge.upgrade_exclusions.notify") as summary:
        for _ in range(2):
            notify_exclusions(paths, apply_projects(paths)[2])
    alert.assert_called_once()
    assert alert.call_args.kwargs["priority"] == 1
    assert "boxmunge-server legacy-stage myapp" in alert.call_args.args[2]
    summary.assert_not_called()


def test_install_and_busy_exclusions_are_alerted(paths) -> None:
    excluded = Exclusions(install={"a": "an install of a-x is open"}, busy=["b"])
    with patch("boxmunge.upgrade_exclusions.notify") as summary:
        notify_exclusions(paths, excluded)
    (install, _), (busy, _) = [(c.args, c.kwargs) for c in summary.call_args_list]
    assert "- a: an install of a-x is open" in install[2]
    assert summary.call_args_list[0].kwargs["priority"] == 1
    assert "b" in busy[2] and "next deploy, resume or recover" in busy[2]


def test_dry_run_reports_a_legacy_project_and_never_fails_on_it(paths, capsys) -> None:
    pdir = legacy_bundle_stage(paths)
    (pdir / "manifest.yml").write_text("not: [valid")      # the staged manifest is unreadable
    (pdir / "compose.yml").write_text("services: [")       # and so is its compose file
    assert _run_dry(paths) == 0
    assert LEGACY_DRY_LINE in capsys.readouterr().out


def test_dry_run_reports_an_open_install_and_leaves_it(paths) -> None:
    _deployed(paths)
    txn = _open_install(paths)
    report = check_upgrade(paths)
    assert report == [f"myapp: an install (myapp-x, {txn.phase}) is open; the project "
                      f"will be left as is"]


def test_apply_rewrites_the_stash_first(paths) -> None:
    order: list[str] = []
    with patch("boxmunge.commands.upgrade_cmd.sanitize_latest_stash",
               lambda p: order.append("stash") or type("R", (), {"changed": False, "dropped": [], "error": None})()), \
            patch("boxmunge.commands.upgrade_cmd.apply_projects",
                  side_effect=lambda p: order.append("apply") or _empty()), \
            patch("boxmunge.commands.upgrade_cmd.caddy_reload"), \
            patch("boxmunge.commands.upgrade_cmd.write_installed_version"):
        assert _run_apply(paths, "0.10.1", "0.11.0") == 0
    assert order[:2] == ["stash", "apply"]


def test_apply_passes_the_excluded_set_to_the_restart(paths) -> None:
    excluded = Exclusions(legacy={"a": "git"}, install={"b": "why"}, busy=["c"])
    seen = {}

    def restart(p, *, refused, excluded):
        from boxmunge.commands.upgrade_steps import Restart
        seen["excluded"] = set(excluded)
        return Restart()

    from boxmunge.commands.upgrade_steps import ManifestMigration, Regeneration
    with patch("boxmunge.commands.upgrade_cmd.sanitize_latest_stash"), \
            patch("boxmunge.commands.upgrade_cmd.apply_projects",
                  return_value=(ManifestMigration(), Regeneration(), excluded)), \
            patch("boxmunge.commands.upgrade_cmd.notify_exclusions"), \
            patch("boxmunge.commands.upgrade_cmd.restart_projects", restart), \
            patch("boxmunge.commands.upgrade_cmd.caddy_reload"), \
            patch("boxmunge.commands.upgrade_cmd.write_installed_version"):
        assert _run_apply(paths, "0.10.1", "0.11.0") == 0
    assert seen["excluded"] == {"a", "b", "c"}


def test_the_apply_log_tells_each_kind_of_exclusion_apart(paths) -> None:
    excluded = Exclusions(legacy={"a": "git"}, install={"b": "why"}, busy=["c"],
                          undetermined={"d": "cannot tell"})
    from boxmunge.commands.upgrade_steps import ManifestMigration, Regeneration, Restart
    with patch("boxmunge.commands.upgrade_cmd.sanitize_latest_stash"), \
            patch("boxmunge.commands.upgrade_cmd.apply_projects",
                  return_value=(ManifestMigration(), Regeneration(), excluded)), \
            patch("boxmunge.commands.upgrade_cmd.notify_exclusions"), \
            patch("boxmunge.commands.upgrade_cmd.restart_projects", return_value=Restart()), \
            patch("boxmunge.commands.upgrade_cmd.caddy_reload"), \
            patch("boxmunge.commands.upgrade_cmd.write_installed_version"), \
            patch("boxmunge.commands.upgrade_cmd.log_operation") as logged:
        assert _run_apply(paths, "0.10.1", "0.11.0") == 0
    assert logged.call_args.kwargs["detail"]["excluded"] == {
        "legacy_stage": ["a"], "undetermined": ["d"], "open_install": ["b"], "busy": ["c"]}


def _empty():
    from boxmunge.commands.upgrade_steps import ManifestMigration, Regeneration
    return ManifestMigration(), Regeneration(), Exclusions()


# -- Fix round 1 ---------------------------------------------------------------

def _apply(paths) -> int:
    with patch("boxmunge.commands.upgrade_cmd.caddy_reload"), \
            patch("boxmunge.commands.upgrade_cmd.write_installed_version"):
        return _run_apply(paths, "0.10.1", "0.11.0")


@pytest.mark.parametrize("damage", ["corrupt_record", "lock_is_a_directory"])
def test_a_legacy_alert_that_cannot_be_recorded_does_not_fail_the_apply(
        paths, capsys, damage) -> None:
    legacy_bundle_stage(paths)
    if damage == "corrupt_record":
        (paths.state / "legacy-stages.json").write_text("{not json")
    else:
        (paths.state / ".legacy-stages.lock").mkdir()
    with patch("boxmunge.legacy_stage.notify", return_value=True):
        assert _apply(paths) == 0
    assert "legacy-stages.json" in capsys.readouterr().err
    errors = [line for line in paths.log_file.read_text().splitlines()
              if '"error"' in line and "myapp" in line]
    assert any("legacy-stages.json" in line for line in errors)


def _dangle(pdir) -> None:
    (pdir / "manifest.yml").unlink()
    (pdir / "manifest.yml").symlink_to("repo/manifest.yml")


def test_dry_run_fails_on_a_dangling_manifest_link_with_the_fix(paths, capsys) -> None:
    _deployed(paths)
    _dangle(paths.project_dir("myapp"))
    with patch("boxmunge.commands.upgrade_cmd.get_build_version", return_value="0.11.0+abc"):
        assert _run_dry(paths) == 1
    err = capsys.readouterr().err
    assert "myapp: manifest.yml links to repo/manifest.yml, which does not exist" in err
    assert "restore it in repo/ or delete the project" in err
    assert "boxmunge-upgrade clear-blocklist 0.11.0" in err


def test_apply_fails_on_a_dangling_manifest_link_with_the_fix(paths) -> None:
    _deployed(paths)
    _dangle(paths.project_dir("myapp"))
    with pytest.raises(ManifestError, match="links to repo/manifest.yml, which does not exist"):
        apply_projects(paths)


def test_dry_run_passes_a_legacy_project_with_a_dangling_manifest_link(paths, capsys) -> None:
    _dangle(legacy_bundle_stage(paths))
    assert _run_dry(paths) == 0
    assert LEGACY_DRY_LINE in capsys.readouterr().out


def test_one_decision_names_why_a_project_is_left(paths) -> None:
    from boxmunge.commands.upgrade_steps import exclusion
    from boxmunge.data_dirs import ReleaseStateError
    from boxmunge.legacy_stage import LegacyStage
    from boxmunge.release_txn import InstallTxn, txn_path
    _deployed(paths)
    assert exclusion(paths, "myapp") is None
    _open_install(paths)
    assert isinstance(exclusion(paths, "myapp"), InstallTxn)
    txn_path(paths, "myapp").write_text("{not json")
    assert isinstance(exclusion(paths, "myapp"), ReleaseStateError)
    assert check_upgrade(paths)[0].endswith("; the project will be left as is")
    assert "Cannot read" in apply_projects(paths)[2].install["myapp"]
    (paths.project_dir("myapp") / ".releases" / "prestage").mkdir()
    assert exclusion(paths, "myapp") == LegacyStage("bundle")


def test_no_migrations_line_says_left_projects_are_not_migrated(paths, capsys) -> None:
    legacy_bundle_stage(paths)
    with patch("boxmunge.legacy_stage.notify", return_value=True):
        assert _apply(paths) == 0
    assert "No migrations needed (projects left as is are not migrated)." in \
        capsys.readouterr().out


# -- Fix round 2 ---------------------------------------------------------------

def _unreadable_live_json(paths) -> None:
    live = paths.project_releases("myapp") / "live.json"
    live.unlink()
    live.mkdir()


def test_an_open_install_with_unreadable_release_files_is_excluded_not_fatal(
        paths, capsys) -> None:
    _deployed(paths)
    _open_install(paths)
    _unreadable_live_json(paths)
    _m, _r, excluded = apply_projects(paths)
    assert "an install of myapp-x (bundle) is open" in excluded.install["myapp"]
    assert "IsADirectoryError" in excluded.install["myapp"]
    with patch("boxmunge.upgrade_exclusions.notify"):
        assert _apply(paths) == 0
    assert "LEFT AS IS: myapp:" in capsys.readouterr().out


def test_dry_run_reports_the_same_unreadable_release_files(paths, capsys) -> None:
    _deployed(paths)
    txn = _open_install(paths)
    _unreadable_live_json(paths)
    capsys.readouterr()
    assert _run_dry(paths) == 0
    line = next(l for l in capsys.readouterr().out.splitlines() if "myapp:" in l)
    assert f"myapp: an install (myapp-x, {txn.phase}) is open; the project will be left as is" in line
    assert "IsADirectoryError" in line


def test_a_summary_alert_that_raises_never_fails_the_apply(paths, capsys) -> None:
    excluded = Exclusions(install={"a": "why"}, busy=["b"])
    with patch("boxmunge.upgrade_exclusions.notify", side_effect=OSError("disk full")):
        notify_exclusions(paths, excluded)
    err = capsys.readouterr().err
    assert err.count("WARNING") == 2 and "disk full" in err
    errors = [l for l in paths.log_file.read_text().splitlines() if '"error"' in l]
    assert sum("disk full" in l for l in errors) == 2
