"""Evidence, the backup manifest, alerts and holds for a 0.10.1 stage."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from boxmunge.backup_source import backup_source
from boxmunge.docker_run import DockerError
from boxmunge.git_slot import GitRefError
from boxmunge.legacy_stage import (
    EvidenceError, LegacyStage, alert_legacy, drop_record, evidence, get_record, legacy_stage,
    stage_time, update_record,
)
from boxmunge.manifest import ManifestError
from boxmunge.state import StateError
from tests.git_helpers import git
from tests.legacy_helpers import (
    legacy_bundle_stage, legacy_git_stage, reflog_checkout_time, stamp,
)

T = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
CREATED = "boxmunge.docker_containers.created_times"


@pytest.fixture
def legacy(paths):
    pdir = legacy_bundle_stage(paths)
    stamp(pdir / ".releases" / "prestage" / "meta.json", T)
    return pdir


@pytest.fixture
def legacy_git(paths, tmp_path):
    (tmp_path / "src").mkdir()
    a, b = legacy_git_stage(paths, tmp_path / "src")
    repo = paths.project_dir("myapp") / "repo"
    return a, b, repo, reflog_checkout_time(repo)


def _created(*offsets_h, at=T):
    return {f"myapp-web-{i}": at + timedelta(hours=h) for i, h in enumerate(offsets_h, 1)}


# -- bundle evidence --------------------------------------------------------

def test_untouched_when_every_container_predates_the_stage(paths, legacy) -> None:
    with patch(CREATED, return_value=_created(-5)):
        ev = evidence(paths, "myapp", LegacyStage("bundle"))
    assert ev.classification == "untouched" and ev.t == T
    assert ev.production_ref == ev.current_ref and ev.staged_ref != ev.current_ref
    assert ev.describe()[-1] == "production's containers: untouched"


def test_untouched_when_production_has_no_containers(paths, legacy) -> None:
    with patch(CREATED, return_value={}):
        assert evidence(paths, "myapp", LegacyStage("bundle")).classification == "untouched"


def test_recreated_when_a_container_was_created_after_the_stage(paths, legacy) -> None:
    with patch(CREATED, return_value=_created(-5, 2)):
        assert evidence(paths, "myapp", LegacyStage("bundle")).classification == "recreated"


def test_recreated_when_the_deploy_state_names_the_staged_ref(paths, legacy) -> None:
    live = json.loads((legacy / ".releases" / "live.json").read_text())["ref"]
    paths.project_deploy_state("myapp").write_text(json.dumps({"current_ref": live}))
    with patch(CREATED, return_value=_created(-5)):
        assert evidence(paths, "myapp", LegacyStage("bundle")).classification == "recreated"


def test_docker_unavailable_is_an_evidence_error(paths, legacy) -> None:
    with patch(CREATED, side_effect=DockerError("no daemon")), \
            pytest.raises(EvidenceError, match="no daemon"):
        evidence(paths, "myapp", LegacyStage("bundle"))


def test_unreadable_prestage_is_an_evidence_error(paths, legacy) -> None:
    (legacy / ".releases" / "prestage" / "meta.json").unlink()
    with patch(CREATED, return_value={}), pytest.raises(EvidenceError, match="meta.json"):
        evidence(paths, "myapp", LegacyStage("bundle"))


def test_corrupt_deploy_state_is_an_evidence_error(paths, legacy) -> None:
    paths.project_deploy_state("myapp").write_text("{not json")
    with patch(CREATED, return_value={}), pytest.raises(EvidenceError):
        evidence(paths, "myapp", LegacyStage("bundle"))


# -- git evidence -----------------------------------------------------------

def test_git_stage_time_is_the_newest_reflog_checkout(paths, legacy_git) -> None:
    _, _, _, t = legacy_git
    assert stage_time(paths, "myapp", LegacyStage("git")) == t


def test_git_untouched_reports_full_shas_and_the_short_current_ref(paths, legacy_git) -> None:
    a, b, _, t = legacy_git
    with patch(CREATED, return_value=_created(-1, at=t)):
        ev = evidence(paths, "myapp", LegacyStage("git"))
    assert ev.classification == "untouched"
    assert ev.head == b and ev.staged_ref == b and ev.current_ref == a[:7]
    # A short recorded SHA is reported, never guessed at.
    assert ev.production_ref == "?" and any("short SHA" in n for n in ev.notes)


def test_git_recreated_when_a_container_postdates_the_checkout(paths, legacy_git) -> None:
    *_, t = legacy_git
    with patch(CREATED, return_value=_created(1, at=t)):
        assert evidence(paths, "myapp", LegacyStage("git")).classification == "recreated"


def test_git_staged_ref_equal_to_current_is_always_untouched(paths, legacy_git) -> None:
    a, _, _, t = legacy_git
    paths.project_deploy_state("myapp").write_text(json.dumps({"current_ref": a}))
    from boxmunge.legacy_stage import legacy_staging_state
    legacy_staging_state(paths, "myapp").write_text(json.dumps({"active": True, "ref": a}))
    with patch(CREATED, side_effect=AssertionError("containers need not be asked")):
        assert evidence(paths, "myapp", LegacyStage("git")).classification == "untouched"


def test_git_unresolvable_staged_ref_is_reported(paths, legacy_git) -> None:
    *_, t = legacy_git
    from boxmunge.legacy_stage import legacy_staging_state
    legacy_staging_state(paths, "myapp").write_text(json.dumps({"active": True, "ref": "gone"}))
    with patch(CREATED, return_value=_created(-1, at=t)):
        ev = evidence(paths, "myapp", LegacyStage("git"))
    assert any("gone does not resolve" in n for n in ev.notes)


def test_git_failure_is_an_evidence_error_not_an_unresolved_ref(paths, legacy_git) -> None:
    with patch("boxmunge.legacy_stage.rev_parse", side_effect=GitRefError("dubious ownership")), \
            patch(CREATED, return_value={}), \
            pytest.raises(EvidenceError, match="dubious ownership"):
        evidence(paths, "myapp", LegacyStage("git"))


def test_git_repo_that_is_not_a_repository_is_an_evidence_error(paths, legacy_git) -> None:
    *_, repo, _ = legacy_git
    (repo / ".git" / "HEAD").write_text("garbage\n")
    with patch(CREATED, return_value={}), pytest.raises(EvidenceError):
        evidence(paths, "myapp", LegacyStage("git"))


def test_git_reflog_without_a_checkout_is_an_evidence_error(paths, legacy_git) -> None:
    *_, repo, _ = legacy_git
    (repo / ".git" / "logs" / "HEAD").write_text("")
    with pytest.raises(EvidenceError, match="no checkout"):
        stage_time(paths, "myapp", LegacyStage("git"))


def _write_staging_state(paths, doc) -> None:
    from boxmunge.legacy_stage import legacy_staging_state
    legacy_staging_state(paths, "myapp").write_text(json.dumps(doc))


@pytest.mark.parametrize("doc", [None, {"active": False}, {"active": True}])
def test_git_unrecorded_staged_ref_is_classified_by_the_containers(
        paths, legacy_git, doc) -> None:
    # 0.10.1 checks out the staged ref before it writes the staging state:
    # a stage killed in between leaves no ref, or an earlier unstage's.
    from boxmunge.legacy_stage import legacy_staging_state
    *_, t = legacy_git
    if doc is None:
        legacy_staging_state(paths, "myapp").unlink()
    else:
        _write_staging_state(paths, doc)
    assert legacy_stage(paths, "myapp") == LegacyStage("git")
    with patch(CREATED, return_value=_created(1, at=t)):
        ev = evidence(paths, "myapp", LegacyStage("git"))
    assert ev.classification == "recreated"
    assert any("the staged ref is not recorded" in n for n in ev.notes)


@pytest.mark.parametrize("ref", ["latest", None])
def test_git_stage_of_the_checked_out_tree_is_untouched(paths, legacy_git, ref) -> None:
    _write_staging_state(paths, {"active": True, "ref": ref})
    with patch(CREATED, side_effect=AssertionError("containers need not be asked")):
        assert evidence(paths, "myapp", LegacyStage("git")).classification == "untouched"


@pytest.mark.parametrize("ref", [7, ["a"], {"x": 1}])
def test_a_ref_that_is_not_a_string_is_an_evidence_error(paths, legacy_git, ref) -> None:
    _write_staging_state(paths, {"active": True, "ref": ref})
    with pytest.raises(EvidenceError, match="not a string"):
        evidence(paths, "myapp", LegacyStage("git"))


def test_a_bundle_ref_that_is_not_a_string_is_an_evidence_error(paths, legacy) -> None:
    (legacy / ".releases" / "live.json").write_text(json.dumps({"ref": 3}))
    with patch(CREATED, return_value={}), pytest.raises(EvidenceError, match="not a string"):
        evidence(paths, "myapp", LegacyStage("bundle"))


def test_git_evidence_carries_and_describes_resolved_shas(paths, legacy_git) -> None:
    a, b, _, t = legacy_git
    paths.project_deploy_state("myapp").write_text(json.dumps({"current_ref": a}))
    _write_staging_state(paths, {"active": True, "ref": "main"})
    with patch(CREATED, return_value=_created(-1, at=t)):
        ev = evidence(paths, "myapp", LegacyStage("git"))
    assert ev.staged_ref == "main" and ev.staged_sha == b and ev.production_ref == a
    text = "\n".join(ev.describe())
    assert f"staged ref: main ({b})" in text and f"production's release: {a}" in text


def test_bundle_evidence_describes_the_kept_release(paths, legacy) -> None:
    with patch(CREATED, return_value=_created(-5)):
        ev = evidence(paths, "myapp", LegacyStage("bundle"))
    assert ev.staged_sha is None
    assert f"production's release: {ev.production_ref}" in ev.describe()


# -- backups ----------------------------------------------------------------

def test_backup_of_an_untouched_stage_uses_the_kept_production_manifest(paths, legacy) -> None:
    with patch(CREATED, return_value=_created(-5)):
        src = backup_source(paths, "myapp")
    assert src.manifest["backup"]["type"] == "postgres"
    assert src.compose_file == legacy / ".releases" / "prestage" / "release" / "compose.yml"


def test_backup_of_a_recreated_stage_uses_the_project_dir(paths, legacy) -> None:
    with patch(CREATED, return_value=_created(3)):
        src = backup_source(paths, "myapp")
    assert src.manifest["backup"]["type"] == "none" and src.compose_file is None


def test_backup_of_a_leftover_uses_the_project_dir(paths) -> None:
    from boxmunge.project_registry import add_project
    from tests.bundle_helpers import manifest_text
    add_project("myapp", paths)
    pdir = paths.project_dir("myapp")
    pdir.mkdir(parents=True, exist_ok=True)
    (pdir / "manifest.yml").write_text(manifest_text(backup="postgres"))
    (pdir / "compose.boxmunge-staging.yml").write_text("services: {}\n")
    assert legacy_stage(paths, "myapp") == LegacyStage("leftover")
    with patch(CREATED, side_effect=AssertionError("no evidence for a leftover")):
        assert backup_source(paths, "myapp").manifest["backup"]["type"] == "postgres"


def test_backup_skipped_with_an_alert_when_the_evidence_is_unreadable(paths, legacy) -> None:
    with patch(CREATED, side_effect=DockerError("down")):
        src = backup_source(paths, "myapp")
    assert src.manifest is None and src.alert and "down" in src.skip


def test_backup_of_an_untouched_stage_with_an_unreadable_kept_manifest_raises(
        paths, legacy) -> None:
    (legacy / ".releases" / "prestage" / "release" / "manifest.yml").write_text("- a list\n")
    with patch(CREATED, return_value=_created(-5)), pytest.raises(ManifestError):
        backup_source(paths, "myapp")


def test_backup_of_an_untouched_git_stage_reads_the_running_commit(paths, legacy_git) -> None:
    *_, t = legacy_git
    with patch(CREATED, return_value=_created(-1, at=t)):
        src = backup_source(paths, "myapp")
    # repo/'s work tree and <p>/manifest.yml hold the staged (backup: none) manifest.
    assert src.manifest["backup"]["type"] == "postgres" and src.compose_file is None


def test_backup_of_a_recreated_git_stage_uses_the_project_dir(paths, legacy_git) -> None:
    *_, t = legacy_git
    with patch(CREATED, return_value=_created(1, at=t)):
        assert backup_source(paths, "myapp").manifest["backup"]["type"] == "none"


def test_backup_skipped_with_an_alert_when_the_running_commit_is_gone(
        paths, legacy_git) -> None:
    *_, t = legacy_git
    paths.project_deploy_state("myapp").write_text(json.dumps({"current_ref": "0" * 40}))
    with patch(CREATED, return_value=_created(-1, at=t)):
        src = backup_source(paths, "myapp")
    assert src.manifest is None and src.alert and "0" * 40 in src.skip


def test_backup_of_an_untouched_git_stage_with_a_broken_manifest_raises(
        paths, legacy_git) -> None:
    a, _, repo, t = legacy_git
    git("-c", "user.name=t", "-c", "user.email=t@example.com", "checkout", "-q", a, cwd=repo)
    (repo / "manifest.yml").write_text("- a list\n")
    git("-c", "user.name=t", "-c", "user.email=t@example.com",
        "commit", "-q", "-am", "broken", cwd=repo)
    broken = git("rev-parse", "HEAD", cwd=repo)
    paths.project_deploy_state("myapp").write_text(json.dumps({"current_ref": broken}))
    t = reflog_checkout_time(repo)
    with patch(CREATED, return_value=_created(-1, at=t)), pytest.raises(ManifestError):
        backup_source(paths, "myapp")


# -- alerts and the record --------------------------------------------------

def test_alert_is_deduplicated_for_a_day(paths, legacy) -> None:
    sent: list[str] = []
    stage = legacy_stage(paths, "myapp")
    with patch("boxmunge.legacy_stage.notify", lambda *a, **k: sent.append(a[2]) or True):
        assert alert_legacy(paths, "myapp", stage, now=T)
        assert not alert_legacy(paths, "myapp", stage, now=T + timedelta(hours=23))
        assert alert_legacy(paths, "myapp", stage, now=T + timedelta(hours=25))
    assert len(sent) == 2
    assert "keeps running its current containers" in sent[0]
    assert "boxmunge-server legacy-stage myapp" in sent[0]
    rec = get_record(paths, "myapp")
    assert rec["kind"] == "bundle" and rec["first_seen"] == T.isoformat()
    assert rec["last_alert"] == (T + timedelta(hours=25)).isoformat()


def test_an_undelivered_alert_is_retried_on_the_next_tick(paths, legacy) -> None:
    stage = legacy_stage(paths, "myapp")
    with patch("boxmunge.legacy_stage.notify", return_value=False):
        assert not alert_legacy(paths, "myapp", stage, now=T)
    with patch("boxmunge.legacy_stage.notify", return_value=True) as alert:
        assert alert_legacy(paths, "myapp", stage, now=T + timedelta(minutes=5))
    assert alert.call_args.kwargs["priority"] == 1


def test_record_fields_are_kept_and_dropped(paths) -> None:
    assert get_record(paths, "myapp") is None
    assert update_record(paths, "myapp", choice="discard") == {"choice": "discard"}
    assert update_record(paths, "myapp", snapshot="s1") == {"choice": "discard",
                                                             "snapshot": "s1"}
    update_record(paths, "other", choice="keep-staged")
    drop_record(paths, "myapp")
    assert get_record(paths, "myapp") is None and get_record(paths, "other")
    assert (paths.state / "legacy-stages.json").stat().st_mode & 0o777 == 0o644


@pytest.mark.parametrize("text", ["{nope", "[1, 2]", '{"myapp": [1]}',
                                  '{"myapp": {"last_alert": "yesterday"}}'])
def test_a_corrupt_record_is_a_state_error_naming_the_file(paths, legacy, text) -> None:
    # StateError is a per-project input error: check-all reports it and
    # carries on with the other projects.
    paths.state.mkdir(parents=True, exist_ok=True)
    (paths.state / "legacy-stages.json").write_text(text)
    with pytest.raises(StateError, match="legacy-stages.json"):
        alert_legacy(paths, "myapp", legacy_stage(paths, "myapp"), now=T)


# -- the tick and the quarantine hold ---------------------------------------

def test_tick_runs_no_smoke_for_a_legacy_project(paths, legacy, capsys) -> None:
    from boxmunge.commands.check import _check_one
    with patch("boxmunge.commands.check.run_check") as check, \
            patch("boxmunge.legacy_stage.notify", return_value=True) as alert:
        assert _check_one("myapp", paths, read_only=False) == 1
    check.assert_not_called()
    assert alert.called
    assert "myapp: legacy-stage (bundle)" in capsys.readouterr().out


def test_read_only_tick_sends_no_alert(paths, legacy) -> None:
    from boxmunge.commands.check import _check_one
    with patch("boxmunge.commands.check.run_check") as check, \
            patch("boxmunge.legacy_stage.notify") as alert:
        assert _check_one("myapp", paths, read_only=True) == 1
    check.assert_not_called()
    alert.assert_not_called()
    assert get_record(paths, "myapp") is None


def _headline(cve="CVE-1"):
    return (object(), type("D", (), {"finding": type("F", (), {"cve_id": cve})()})())


def test_quarantine_held_for_a_legacy_project(paths, legacy) -> None:
    from boxmunge.commands import security_enforce
    with patch.object(security_enforce, "quarantine_project") as quarantine, \
            patch("boxmunge.commands.security_enforce.notify") as alert:
        result = security_enforce.enforce(paths, "myapp", hosts=[], compose_files=[],
                                          headline=_headline(), in_grace=False)
    quarantine.assert_not_called()
    assert result.held == "CVE-1" and not result.landed
    assert alert.call_args.kwargs["priority"] == 1 and "CVE-1" in alert.call_args.args[2]


def _quarantine_record(paths, *, complete: bool) -> None:
    path = paths.project_quarantine_state("myapp")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"cve_id": "CVE-9", "action_complete": complete}))


@pytest.mark.parametrize("complete", [False, True])
def test_quarantine_reassertion_held_for_a_legacy_project(paths, legacy, complete) -> None:
    # Re-asserting stops the containers again: production, for this project.
    from boxmunge.commands import security_enforce
    _quarantine_record(paths, complete=complete)
    with patch.object(security_enforce, "reassert_quarantine") as reassert, \
            patch("boxmunge.commands.security_enforce.notify") as alert:
        result = security_enforce.enforce(paths, "myapp", hosts=[], compose_files=[],
                                          headline=None, in_grace=False)
    reassert.assert_not_called()
    assert result.held == "CVE-9" and not result.landed and result.error is None
    assert alert.call_args.kwargs["priority"] == 1 and "CVE-9" in alert.call_args.args[2]


def test_reassertion_hold_of_a_record_without_a_cve_fails_loudly(paths, legacy) -> None:
    from boxmunge.commands import security_enforce
    path = paths.project_quarantine_state("myapp")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"action_complete": False}))
    with patch.object(security_enforce, "reassert_quarantine") as reassert, \
            patch("boxmunge.commands.security_enforce.notify"):
        result = security_enforce.enforce(paths, "myapp", hosts=[], compose_files=[],
                                          headline=None, in_grace=False)
    reassert.assert_not_called()
    assert result.held is None and "names no cve_id" in result.error


def test_quarantine_not_held_during_grace(paths, legacy) -> None:
    from boxmunge.commands import security_enforce
    with patch.object(security_enforce, "quarantine_project") as quarantine, \
            patch("boxmunge.commands.security_enforce.notify") as alert:
        result = security_enforce.enforce(paths, "myapp", hosts=[], compose_files=[],
                                          headline=_headline(), in_grace=True)
    quarantine.assert_not_called()
    alert.assert_not_called()
    assert result.held is None
