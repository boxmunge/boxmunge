"""A 0.10.1 git stage that changed no code needs no stage time (T).

0.10.1's add-git-project only clones, so repo/'s reflog may hold nothing
but a `clone:` entry (or nothing at all, when reflogs expired or are
off); `stage <p>` with no --ref then records "latest". T is only read to
classify the containers of a stage that changed the code."""
from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from boxmunge.backup_source import backup_source
from boxmunge.legacy_stage import (
    EvidenceError, LegacyStage, evidence, legacy_stage, legacy_staging_state,
)
from boxmunge.state import read_state, write_state
from tests.bundle_helpers import SAFE_COMPOSE, manifest_text
from tests.git_helpers import git, origin_with
from tests.test_commands.test_legacy_stage_cmd import _run

CREATED = "boxmunge.docker_containers.created_times"
NOT_ASKED = AssertionError("a stage that changed no code needs no container times")


@pytest.fixture(params=["clone-only", "no-reflog", "reflog-disabled"])
def cloned(request, paths, tmp_path):
    """0.10.1 add-git-project (a clone, nothing else), then `stage myapp`
    with no --ref. Returns repo/."""
    from boxmunge.project_registry import add_project
    add_project("myapp", paths)
    (tmp_path / "src").mkdir()
    origin, _ = origin_with(tmp_path / "src", {"manifest.yml": manifest_text(backup="postgres")})
    pdir = paths.project_dir("myapp")
    repo = pdir / "repo"
    config = (["--config", "core.logAllRefUpdates=false"]
              if request.param == "reflog-disabled" else [])
    git("clone", "-q", *config, str(origin), str(repo), cwd=tmp_path)
    reflog = repo / ".git" / "logs" / "HEAD"
    if request.param == "no-reflog":
        reflog.unlink()
    assert ("\tcheckout:" not in reflog.read_text()) if reflog.exists() else True
    (pdir / "compose.yml").write_text(SAFE_COMPOSE)
    (pdir / "manifest.yml").write_text(manifest_text(backup="postgres"))
    (pdir / "compose.boxmunge-staging.yml").write_text("services: {}\n")
    state = legacy_staging_state(paths, "myapp")
    state.parent.mkdir(parents=True, exist_ok=True)
    state.write_text(json.dumps({"active": True, "ref": "latest"}))
    assert legacy_stage(paths, "myapp") == LegacyStage("git")
    return repo


def _deploy_head(paths, repo) -> str:
    """As if 0.10.1 had deployed the cloned commit (a short SHA, as it recorded)."""
    head = git("rev-parse", "HEAD", cwd=repo)
    paths.project_deploy_state("myapp").parent.mkdir(parents=True, exist_ok=True)
    write_state(paths.project_deploy_state("myapp"), {"current_ref": head[:7]})
    return head


@pytest.mark.parametrize("deployed", [False, True])
def test_evidence_of_an_unchanged_stage_needs_no_stage_time(paths, cloned, deployed) -> None:
    if deployed:
        _deploy_head(paths, cloned)
    with patch(CREATED, side_effect=NOT_ASKED):
        ev = evidence(paths, "myapp", LegacyStage("git"))
    assert ev.classification == "untouched" and ev.t is None
    assert ev.describe()[0] == "stage made at: not needed: the stage changed no code"


def test_show_of_an_unchanged_stage(paths, cloned, capsys) -> None:
    assert _run(paths, None) == 0
    out = capsys.readouterr().out
    assert "untouched" in out and "not needed" in out and "Cannot tell" not in out


def test_discard_of_an_unchanged_never_deployed_stage(paths, cloned, capsys) -> None:
    head = git("rev-parse", "HEAD", cwd=cloned)
    assert _run(paths, "discard") == 0
    assert "never deployed" in capsys.readouterr().out
    assert git("rev-parse", "HEAD", cwd=cloned) == head
    assert legacy_stage(paths, "myapp") is None


def test_discard_of_an_unchanged_deployed_stage(paths, cloned) -> None:
    head = _deploy_head(paths, cloned)
    assert _run(paths, "discard") == 0
    assert git("rev-parse", "HEAD", cwd=cloned) == head
    assert legacy_stage(paths, "myapp") is None


def test_keep_staged_of_an_unchanged_never_deployed_stage(paths, cloned) -> None:
    head = git("rev-parse", "HEAD", cwd=cloned)
    with patch("boxmunge.commands.backup_cmd.backup_locked",
               side_effect=AssertionError("nothing was deployed to snapshot")):
        assert _run(paths, "keep-staged") == 0
    assert read_state(paths.project_deploy_state("myapp"))["current_ref"] == head
    assert legacy_stage(paths, "myapp") is None


def test_keep_staged_of_an_unchanged_deployed_stage(paths, cloned) -> None:
    from tests.txn_helpers import fake_backups
    head = _deploy_head(paths, cloned)
    taken: list[dict] = []
    with fake_backups(taken):
        assert _run(paths, "keep-staged") == 0
    assert taken[0]["backup"]["type"] == "postgres"
    state = read_state(paths.project_deploy_state("myapp"))
    assert state["current_ref"] == head and state["pre_deploy_snapshot"] == "myapp-p1.tar.gz.age"
    assert legacy_stage(paths, "myapp") is None


def test_backup_of_an_unchanged_deployed_stage_reads_the_running_commit(paths, cloned) -> None:
    _deploy_head(paths, cloned)
    with patch(CREATED, side_effect=NOT_ASKED):
        source = backup_source(paths, "myapp")
    assert source.manifest is not None and source.manifest["backup"]["type"] == "postgres"
    assert not source.alert


def test_backup_of_an_unchanged_never_deployed_stage_is_skipped_without_alert(
        paths, cloned) -> None:
    with patch(CREATED, side_effect=NOT_ASKED):
        source = backup_source(paths, "myapp")
    assert source.manifest is None and not source.alert
    assert "never deployed" in source.skip


@pytest.mark.parametrize("damage", ["missing", "no-checkout"])
def test_a_stage_that_changed_the_code_still_needs_its_stage_time(paths, legacy_git,
                                                                 damage) -> None:
    *_, repo, _ = legacy_git
    reflog = repo / ".git" / "logs" / "HEAD"
    if damage == "missing":
        reflog.unlink()
    else:
        reflog.write_text("".join(line + "\n" for line in reflog.read_text().splitlines()
                                  if "\tcheckout:" not in line))
    with patch(CREATED, return_value={}), pytest.raises(EvidenceError, match="logs/HEAD"):
        evidence(paths, "myapp", LegacyStage("git"))
    with patch(CREATED, return_value={}):
        assert backup_source(paths, "myapp").alert
