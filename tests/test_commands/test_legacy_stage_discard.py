# SPDX-License-Identifier: Apache-2.0
"""legacy-stage --discard puts production's release back (bundle and git)."""
from __future__ import annotations

import json
import os
import subprocess
from unittest.mock import patch

import pytest

from boxmunge.legacy_stage import get_record, legacy_stage, legacy_staging_state
from boxmunge.state import read_state, write_state
from tests.git_helpers import git
from tests.stage_helpers import V1
from tests.test_commands.legacy_cmd_helpers import legacy_run


def test_discard_of_an_untouched_stage_puts_production_back(paths, legacy) -> None:
    assert legacy_run(paths, "discard") == 0
    assert (legacy / "VERSION").read_text() == "v1\n"
    assert json.loads((legacy / ".releases" / "live.json").read_text())["ref"] == f"myapp-{V1}"
    assert legacy_stage(paths, "myapp") is None and get_record(paths, "myapp") is None
    assert not (legacy / "compose.staging-base.yml").exists()
    assert not (legacy / "compose.boxmunge-staging.yml").exists()
    assert not (legacy / ".releases" / "prestage").exists()
    assert not legacy_staging_state(paths, "myapp").exists()
    # Staging was taken down with the legacy files; production recreated on the overlay.
    assert legacy_run.down.call_args.kwargs["compose_files"] == [
        "compose.staging-base.yml", "compose.boxmunge-staging.yml"]
    assert legacy_run.down.call_args.kwargs["project_name"] == "myapp-staging"
    assert legacy_run.up.call_args.kwargs["compose_files"] == ["compose.yml", "compose.boxmunge.yml"]
    assert (legacy / "compose.boxmunge.yml").exists()
    assert read_state(paths.project_deploy_state("myapp"))["current_ref"] == f"myapp-{V1}"
    assert legacy_run.sent.call_args.kwargs["priority"] == 0
    assert "--discard" in legacy_run.sent.call_args.args[2]


def test_discard_removes_the_staging_site(paths, legacy) -> None:
    site = paths.project_staging_caddy_site("myapp")
    site.parent.mkdir(parents=True, exist_ok=True)
    site.write_text("staging.example.com {}\n")
    assert legacy_run(paths, "discard") == 0
    assert not site.exists()


def test_discard_of_a_recreated_stage_needs_confirmation(paths, legacy, capsys) -> None:
    snaps = paths.project_backups("myapp")
    snaps.mkdir(parents=True, exist_ok=True)
    (snaps / "myapp-2026-10-01T130000-predeploy.tar.gz.age").write_text("s")
    assert legacy_run(paths, "discard", created=(3,)) == 1
    err = capsys.readouterr().err
    assert "--confirm-recreated" in err and "myapp-2026-10-01T130000-predeploy" in err
    assert (get_record(paths, "myapp") or {}).get("choice") is None
    assert legacy_run(paths, "discard", confirm=True, created=(3,)) == 0
    assert (legacy / "VERSION").read_text() == "v1\n"


def test_confirmed_discard_still_warns_and_names_the_snapshot(paths, legacy, capsys) -> None:
    snaps = paths.project_backups("myapp")
    snaps.mkdir(parents=True, exist_ok=True)
    (snaps / "myapp-2026-10-01T130000-predeploy.tar.gz.age").write_text("s")
    assert legacy_run(paths, "discard", confirm=True, created=(3,)) == 0
    out = capsys.readouterr().out
    assert "data the staged code wrote stays" in out
    assert "myapp-2026-10-01T130000-predeploy" in out


def test_a_paused_project_is_resolved_but_not_started(paths, legacy, capsys) -> None:
    from boxmunge.pause import write_paused_state
    write_paused_state("myapp", paths)
    assert legacy_run(paths, "discard") == 0
    legacy_run.up.assert_not_called()
    assert "not started" in capsys.readouterr().out
    assert legacy_stage(paths, "myapp") is None


def test_root_discard_never_chowns_through_an_installed_link(paths, legacy, tmp_path,
                                                             monkeypatch) -> None:
    from tests.test_fileutil_tree import _inodes, _Swap
    outside = tmp_path / "etc"
    outside.mkdir()
    (outside / "passwd").write_text("root")
    os.symlink(outside, legacy / ".releases" / "prestage" / "release" / "x")
    rec = _Swap(monkeypatch)
    assert legacy_run(paths, "discard") == 0
    assert os.path.islink(legacy / "x")
    assert os.lstat(legacy / "x").st_ino in rec.inodes
    assert not rec.inodes & _inodes(outside)


def test_a_deployed_project_whose_manifest_went_missing_fails_loudly(paths, capsys) -> None:
    from boxmunge.commands.deploy import run_deploy
    from boxmunge.project_registry import add_project
    from tests.bundle_helpers import place_bundle
    from tests.txn_helpers import docker_off
    add_project("myapp", paths)
    place_bundle(paths, timestamp=V1)
    with docker_off():
        run_deploy("myapp", paths, ref=V1)
    pdir = paths.project_dir("myapp")
    (pdir / "compose.boxmunge-staging.yml").write_text("services: {}\n")
    (pdir / "manifest.yml").unlink()
    assert legacy_run(paths, "discard") == 1
    assert "manifest" in capsys.readouterr().err.lower()
    assert get_record(paths, "myapp")["choice"] == "discard"


@pytest.mark.parametrize("crash", [None, "_clean_up", "drop_stage_record"])
def test_discard_of_a_never_deployed_stage(paths, never_deployed, crash) -> None:
    pdir = never_deployed
    if crash:
        with patch(f"boxmunge.legacy_stage_ops.{crash}", side_effect=OSError("crash")):
            assert legacy_run(paths, "discard") == 1
    assert legacy_run(paths, "discard") == 0
    assert not (pdir / "manifest.yml").exists() and not (pdir / ".releases" / "live.json").exists()
    assert legacy_stage(paths, "myapp") is None and get_record(paths, "myapp") is None
    legacy_run.up.assert_not_called()


def test_git_discard_checks_out_the_deployed_commit(paths, legacy_git) -> None:
    a, _, repo, t = legacy_git
    assert legacy_run(paths, "discard", at=t, created=(-1,)) == 0
    assert git("rev-parse", "HEAD", cwd=repo) == a
    detached = subprocess.run(["git", "symbolic-ref", "-q", "HEAD"], cwd=repo)
    assert detached.returncode == 1
    assert legacy_stage(paths, "myapp") is None


def test_git_discard_with_an_unresolvable_deployed_commit_is_refused(paths, legacy_git,
                                                                     capsys) -> None:
    *_, t = legacy_git
    write_state(paths.project_deploy_state("myapp"), {"current_ref": "0" * 40})
    assert legacy_run(paths, "discard", confirm=True, at=t, created=(1,)) == 1
    assert "0" * 40 in capsys.readouterr().err
    assert legacy_stage(paths, "myapp") is not None


def test_never_deployed_git_discard_leaves_the_checkout(paths, legacy_git, capsys) -> None:
    _, b, repo, t = legacy_git
    write_state(paths.project_deploy_state("myapp"), {})
    assert legacy_run(paths, "discard", at=t, created=(-1,)) == 0
    assert git("rev-parse", "HEAD", cwd=repo) == b
    assert "never deployed" in capsys.readouterr().out
    assert legacy_stage(paths, "myapp") is None
    legacy_run.up.assert_not_called()


def test_clean_up_removes_only_copies_of_production_data(paths, legacy) -> None:
    """A 0.10.1 stage has no slot recording what staging made: its copy of
    production's data goes, a -staging entry that is no such copy stays."""
    from boxmunge.legacy_stage_ops import _clean_up
    (legacy / "data-staging").mkdir()
    own = legacy / "assets-staging"
    own.mkdir()
    (own / "keep.txt").write_text("code\n")
    _clean_up(paths, "myapp")
    assert not (legacy / "data-staging").exists()
    assert (own / "keep.txt").read_text() == "code\n"
