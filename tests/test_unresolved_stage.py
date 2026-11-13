# SPDX-License-Identifier: Apache-2.0
"""The upgrade refuses, before it changes anything, while a project holds a
stage boxmunge 0.10.1 or earlier made and no release has resolved."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from boxmunge import unresolved_stage
from boxmunge.commands import upgrade_cmd
from boxmunge.commands.upgrade_cmd import run_upgrade
from boxmunge.commands.upgrade_report import check_upgrade
from boxmunge.commands.upgrade_steps import UpgradeGateError
from boxmunge.manifest import CURRENT_SCHEMA_VERSION
from boxmunge.paths import BoxPaths
from boxmunge.upgrade_exclusions import apply_projects
from boxmunge.version import write_installed_version
from tests.deploy_helpers import mark_deployed

RUNS = "0.11.6"


@pytest.fixture
def box(tmp_path: Path) -> BoxPaths:
    paths = BoxPaths(root=tmp_path / "bm")
    for d in ["config", "projects", "state/deploy", "stashes", "logs",
              "caddy/sites", "upgrade-state"]:
        (paths.root / d).mkdir(parents=True)
    paths.config_file.write_text("hostname: test\nadmin_email: t@t\n")
    write_installed_version(paths, RUNS, "abc1234")
    return paths


def _project(paths: BoxPaths, name: str, *, live: bool = True) -> Path:
    pdir = paths.project_dir(name)
    pdir.mkdir(parents=True)
    (pdir / "manifest.yml").write_text(yaml.dump({
        "schema_version": CURRENT_SCHEMA_VERSION, "project": name,
        "id": "01HZZZZZZZZZZZZZZZZZZZZZZZ",
        "source": "bundle", "hosts": [f"{name}.test"],
        "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
    }))
    (pdir / "compose.yml").write_text("services:\n  web:\n    image: nginx:1.25\n")
    paths.project_caddy_site(name).write_text(f"# live config for {name}\n")
    mark_deployed(paths, name)
    if live:
        (pdir / ".releases").mkdir(exist_ok=True)
        (pdir / ".releases" / "live.json").write_text("{}\n")
    return pdir


def _staging_files(pdir: Path) -> None:
    (pdir / "compose.staging-base.yml").write_text("services: {}\n")
    (pdir / "compose.boxmunge-staging.yml").write_text("services: {}\n")


def _record(paths: BoxPaths, **projects: dict) -> None:
    (paths.state / "legacy-stages.json").write_text(json.dumps(projects))


def _bundle(paths: BoxPaths, name: str = "shop") -> None:
    (_project(paths, name) / ".releases" / "prestage").mkdir()


def _git(paths: BoxPaths, name: str = "shop") -> None:
    pdir = _project(paths, name)
    (pdir / "repo").mkdir()
    state = paths.state / "staging" / f"{name}.json"
    state.parent.mkdir(parents=True)
    state.write_text(json.dumps({"active": True, "ref": "abc1234"}))


def _leftover(paths: BoxPaths, name: str = "shop") -> None:
    _staging_files(_project(paths, name))


def _pre0101(paths: BoxPaths, name: str = "shop") -> None:
    _staging_files(_project(paths, name, live=False))


def _refusal(paths: BoxPaths, installed: str = RUNS) -> str | None:
    names = sorted(p.name for p in paths.projects.iterdir())
    return unresolved_stage.refusal(paths, names, installed)


class TestEachKind:
    @pytest.mark.parametrize("make, kind, by", [
        (_bundle, "bundle", "boxmunge 0.10.1"),
        (_git, "git", "boxmunge 0.10.1"),
        (_leftover, "leftover", "boxmunge 0.10.1"),
        (_pre0101, "pre0101", "a boxmunge release before 0.10.1"),
    ])
    def test_an_unresolved_stage_refuses_and_names_legacy_stage(self, box, make, kind, by):
        make(box)
        text = _refusal(box)
        assert text is not None
        assert (f"  - shop: a release staged by {by} is unresolved ({kind}); run "
                f"`boxmunge-server legacy-stage shop` and take one of the choices it "
                f"shows") in text.splitlines()

    def test_a_stage_state_file_that_cannot_be_parsed_is_a_stage(self, box):
        _project(box, "shop")
        state = box.state / "staging" / "shop.json"
        state.parent.mkdir(parents=True)
        state.write_text("not json")
        assert "shop: a release staged by boxmunge 0.10.1 is unresolved" in _refusal(box)

    def test_a_stage_state_file_that_is_a_link_is_a_stage_and_is_not_followed(
            self, box, tmp_path):
        """Deploy can write state/staging: a link there to a file that says
        inactive is not read as that file."""
        _project(box, "shop")
        elsewhere = tmp_path / "inactive.json"
        elsewhere.write_text(json.dumps({"active": False}))
        state = box.state / "staging" / "shop.json"
        state.parent.mkdir(parents=True)
        state.symlink_to(elsewhere)
        assert "shop: a release staged by boxmunge 0.10.1 is unresolved" in _refusal(box)

    def test_an_inactive_stage_state_file_is_no_stage(self, box):
        _project(box, "shop")
        state = box.state / "staging" / "shop.json"
        state.parent.mkdir(parents=True)
        state.write_text(json.dumps({"active": False}))
        assert _refusal(box) is None

    def test_a_started_resolution_names_its_own_choice(self, box):
        _bundle(box)
        _record(box, shop={"kind": "bundle", "choice": "keep-staged"})
        assert ("  - shop: the resolution of a release staged by boxmunge 0.10.1 was "
                "started with --keep-staged and is not finished; run `boxmunge-server "
                "legacy-stage shop --keep-staged`") in _refusal(box).splitlines()


class TestAfterTheStageIsNoLongerDetected:
    def test_a_resolution_missing_its_last_step_refuses(self, box):
        """After step 6 nothing is detected, but the release that runs is
        not built, named or started yet: an upgrade's restart would run the
        other release's images over these files."""
        _project(box, "shop")
        _record(box, shop={"kind": "git", "choice": "discard"})
        assert ("  - shop: the resolution of a release staged by boxmunge 0.10.1 was "
                "started with --discard and is not finished; run `boxmunge-server "
                "legacy-stage shop --discard`") in _refusal(box).splitlines()

    @pytest.mark.parametrize("kind", ["pre0101", "leftover"])
    def test_awaiting_a_deploy_refuses_and_names_prod_deploy(self, box, kind):
        """A discarded stage made before 0.10.1 leaves the staged files in
        the project directory until a deploy replaces them. 0.11.5 recorded
        such a discard as a leftover's."""
        _project(box, "shop", live=False)
        _record(box, shop={"kind": kind, "choice": "discard"})
        assert ("  - shop: its directory holds the files of a stage that legacy-stage "
                "discarded, and no deploy has replaced them; upload the bundle of the "
                "release production should run, then run `prod-deploy shop`"
                ) in _refusal(box).splitlines()

    def test_a_discarded_stage_a_deploy_replaced_is_clean(self, box):
        _project(box, "shop")
        _record(box, shop={"kind": "pre0101", "choice": "discard"})
        assert _refusal(box) is None

    def test_an_alert_record_alone_is_clean(self, box):
        _project(box, "shop")
        _record(box, shop={"kind": "bundle", "choice": None, "last_alert": "x"})
        assert _refusal(box) is None

    def test_a_live_json_that_is_not_a_file_is_not_a_deploy(self, box):
        pdir = _project(box, "shop", live=False)
        (pdir / ".releases").mkdir()
        (pdir / ".releases" / "live.json").symlink_to(pdir / "manifest.yml")
        _record(box, shop={"kind": "pre0101", "choice": "discard"})
        assert "then run `prod-deploy shop`" in _refusal(box)


class TestAChoiceLegacyStageDoesNotOfferForTheKind:
    """0.11.6 offers a leftover or pre0101 stage --discard alone, and refuses
    that while another choice is recorded; with no stage on disk its
    --keep-staged keeps a pre0101 record for good. Such a record (planted,
    or edited by hand) is cleared by removing it."""

    def _line(self, box, kind: str) -> str:
        return (f"  - shop: its record says a resolution was started with --keep-staged, "
                f"which legacy-stage does not offer for a {kind} stage; remove shop's "
                f"entry from {box.state / 'legacy-stages.json'}, then run `boxmunge-server "
                f"legacy-stage shop`, which shows what is left to resolve, if anything")

    @pytest.mark.parametrize("kind", ["pre0101", "leftover"])
    def test_with_no_stage_on_disk_the_entry_is_removed(self, box, kind):
        _project(box, "shop")
        _record(box, shop={"kind": kind, "choice": "keep-staged"})
        assert self._line(box, kind) in _refusal(box).splitlines()
        _record(box)
        assert _refusal(box) is None

    @pytest.mark.parametrize("make, kind", [(_leftover, "leftover"), (_pre0101, "pre0101")])
    def test_with_the_stage_on_disk_the_entry_is_removed(self, box, make, kind):
        make(box)
        _record(box, shop={"kind": "bundle", "choice": "keep-staged"})
        assert self._line(box, kind) in _refusal(box).splitlines()
        _record(box)
        assert f"is unresolved ({kind}); run `boxmunge-server legacy-stage shop`" in _refusal(box)

    @pytest.mark.parametrize("make", [_bundle, _git])
    def test_a_kind_that_offers_keep_staged_still_names_it(self, box, make):
        make(box)
        _record(box, shop={"kind": "leftover", "choice": "keep-staged"})
        assert "run `boxmunge-server legacy-stage shop --keep-staged`" in _refusal(box)


class TestShapesThatMustNotReadClean:
    @pytest.mark.parametrize("choice", [["discard"], {"a": 1}, 1, 0, False, "", "bogus"])
    def test_a_recorded_choice_that_is_not_a_choice_refuses(self, box, choice):
        """0.11.6 names --<choice> back for whatever is recorded, so it can
        resolve none of these: never "nothing was started"."""
        _project(box, "shop")
        _record(box, shop={"kind": "bundle", "choice": choice})
        text = _refusal(box)
        assert text.startswith("Cannot tell which projects hold a release")
        assert (f"(ValueError: shop's recorded choice {choice!r} is not null or one of "
                f"('discard', 'keep-staged'))") in text

    def test_such_a_record_of_a_project_that_is_gone_is_not_read(self, box):
        _project(box, "shop")
        _record(box, gone={"kind": "bundle", "choice": ["discard"]})
        assert _refusal(box) is None

    def test_a_releases_that_is_a_file_refuses(self, box):
        pdir = _project(box, "shop", live=False)
        (pdir / ".releases").write_text("x")
        text = _refusal(box)
        assert text.startswith("Cannot tell which projects hold a release")
        assert f"(NotADirectoryError: [Errno 20] Not a directory: '{pdir / '.releases'}" in text

    def test_a_state_staging_that_is_a_file_refuses(self, box):
        _project(box, "shop")
        (box.state / "staging").write_text("x")
        text = _refusal(box)
        assert text.startswith("Cannot tell which projects hold a release")
        assert f"(NotADirectoryError: [Errno 20] Not a directory: '{box.state / 'staging'}" in text

    def test_a_project_directory_that_is_gone_holds_no_stage(self, box):
        _project(box, "shop")
        assert unresolved_stage.refusal(box, ["gone", "shop"], RUNS) is None


class TestTheWholeRefusal:
    def test_names_every_project_and_how_to_go_on(self, box):
        _bundle(box, "alpha")
        _project(box, "beta")
        _project(box, "gamma", live=False)
        _record(box, gamma={"kind": "pre0101", "choice": "discard"})
        lines = _refusal(box).splitlines()
        assert lines[0] == (
            "2 projects (alpha, gamma) hold a release that boxmunge 0.10.1 or earlier staged over "
            "production's files, and it is not resolved. An upgrade restarts every "
            "project, and this release neither starts a project from staged files nor "
            "has the legacy-stage command that resolves them. On this box, on the "
            "release it runs now (boxmunge 0.11.6):")
        assert [line.split(":")[0] for line in lines[1:-1]] == ["  - alpha", "  - gamma"]
        assert lines[-1] == "Then retry the upgrade."

    @pytest.mark.parametrize("installed", ["0.11.0", "0.11.5+abc1234"])
    def test_a_box_below_0_11_6_is_sent_there_first(self, box, installed):
        """Only 0.11.6 tells a stage made before 0.10.1 from a 0.10.1
        leftover: an earlier legacy-stage --discard starts production from
        the staged files."""
        _pre0101(box)
        lines = _refusal(box, installed).splitlines()
        assert lines[0].endswith(
            f"This box runs boxmunge {installed.split('+')[0]}, which does not resolve "
            f"every such stage safely (before 0.11.6, legacy-stage --discard starts "
            f"production from the files of a stage made before 0.10.1). Upgrade it to 0.11.6 "
            f"first, with `sudo /opt/boxmunge/bin/boxmunge-upgrade target 0.11.6`. There, a "
            f"`legacy-stage` choice waits for that upgrade's probation to end (six hours). "
            f"Then, on 0.11.6:")
        assert "`boxmunge-server legacy-stage shop`" in lines[1]

    @pytest.mark.parametrize("installed", ["0.11.7", "0.11.7+abc1234", "0.12.0", "1.0.0"])
    def test_a_box_that_already_runs_a_release_without_legacy_stage_is_not_checked(
            self, box, installed):
        """No such box can hold one (this refusal let none through), and it
        has none of the commands the refusal would name."""
        _bundle(box)
        assert _refusal(box, installed) is None

    @pytest.mark.parametrize("installed", [
        "", "0.0.0", "garbage", "0.11.7rc1", "0.11.7-rc1", "v0.11.7", "0.11.6rc1"])
    def test_an_installed_version_that_is_no_plain_release_is_checked(self, box, installed):
        """Refused all the same, but never told it is below 0.11.6: it
        may not be."""
        _bundle(box)
        lines = _refusal(box, installed).splitlines()
        assert lines[0].endswith(
            "them. This box runs a release it has no record of (`boxmunge-server version` "
            "shows which). The commands below are those boxmunge 0.11.6 accepts; a "
            "release before it does not resolve every such stage safely, and is upgraded "
            "to 0.11.6 first:")
        assert "boxmunge-upgrade target" not in lines[0]
        assert "`boxmunge-server legacy-stage shop`" in lines[1]

    def test_a_clean_box_is_not_refused(self, box):
        _project(box, "alpha")
        _project(box, "beta")
        assert _refusal(box) is None

    def test_a_record_that_cannot_be_read_refuses(self, box):
        _project(box, "shop")
        (box.state / "legacy-stages.json").write_text("{not json")
        text = _refusal(box)
        assert text.startswith("Cannot tell which projects hold a release that boxmunge "
                               "0.10.1 or earlier staged over production's files (JSONDecodeError")
        assert f"legacy-stage's record of them is {box.state / 'legacy-stages.json'}" in text
        assert text.endswith("then retry the upgrade.")

    def test_a_project_that_cannot_be_examined_refuses(self, box, monkeypatch):
        _project(box, "shop")

        def denied(path, *a, **k):
            raise PermissionError(13, "Permission denied", str(path))
        monkeypatch.setattr(unresolved_stage.os, "lstat", denied)
        text = _refusal(box)
        assert "(PermissionError: [Errno 13] Permission denied: " in text
        assert str(box.project_dir("shop")) in text


@pytest.fixture
def alerts(monkeypatch) -> list[dict]:
    """What the dry run of a build of 0.11.7 alerts."""
    sent: list[dict] = []

    def notify(paths, title, body, **kwargs):
        sent.append({"title": title, "body": body, **kwargs})
        return True
    monkeypatch.setattr("boxmunge.notify.notify", notify)
    monkeypatch.setattr(upgrade_cmd, "get_build_version", lambda: "0.11.7+abc1234")
    return sent


RETRY = ("The upgrade shim blocklists this version after a failed dry run: once it is fixed, "
         "run `sudo /opt/boxmunge/bin/boxmunge-upgrade clear-blocklist 0.11.7` and retry.")


class TestTheUpgrade:
    def test_the_dry_run_refuses_and_says_how_to_retry(self, box, capsys, alerts):
        _pre0101(box)
        before = sorted(p for p in box.root.rglob("*") if box.logs not in p.parents)
        assert run_upgrade(box, dry_run=True) == 1
        err = capsys.readouterr().err
        assert "ERROR: 1 project (shop) holds a release that boxmunge 0.10.1 or earlier" in err
        assert "`boxmunge-server legacy-stage shop`" in err
        assert RETRY in err
        assert sorted(p for p in box.root.rglob("*") if box.logs not in p.parents) == before

    def test_the_refused_dry_run_alerts_once_naming_the_projects_and_the_release(
            self, box, alerts):
        """The shims of 0.11.0 to 0.11.6 alert nothing for a failed dry run,
        and deploy can plant what refuses it: someone has to be told."""
        _project(box, "shop")
        state = box.state / "staging" / "shop.json"
        state.parent.mkdir(parents=True)
        state.write_text(json.dumps({"active": True}))
        assert run_upgrade(box, dry_run=True) == 1
        [alert] = alerts
        assert alert["title"] == "upgrade to 0.11.7 refused — unresolved stage"
        assert alert["priority"] == 1 and alert["component"] == "upgrade"
        assert alert["body"] == (
            "The upgrade to boxmunge 0.11.7 was refused before it changed anything.\n"
            + unresolved_stage.refusal(box, ["shop"], RUNS) + "\n" + RETRY)
        assert "1 project (shop) holds" in alert["body"]

    def test_the_refusal_is_in_the_log_the_alert_points_at(self, box, alerts):
        """Pushover cuts a long alert and says to see the boxmunge log."""
        _bundle(box)
        run_upgrade(box, dry_run=True)
        [entry] = [json.loads(line) for line in box.log_file.read_text().splitlines()]
        assert entry["level"] == "error" and entry["component"] == "upgrade"
        assert entry["msg"].startswith("Upgrade to 0.11.7 refused: 1 project (shop) holds")
        assert "`boxmunge-server legacy-stage shop`" in entry["msg"]

    def test_a_dry_run_that_cannot_tell_alerts_that(self, box, alerts):
        _project(box, "shop")
        (box.state / "legacy-stages.json").write_text("garbage")
        assert run_upgrade(box, dry_run=True) == 1
        [alert] = alerts
        assert "0.11.7" in alert["title"] and alert["priority"] == 1
        assert "\nCannot tell which projects hold a release" in alert["body"]

    def test_a_dry_run_failing_for_anything_else_does_not_alert(self, box, alerts, capsys):
        _project(box, "shop")
        (box.project_dir("shop") / "manifest.yml").write_text("- not a manifest\n")
        assert run_upgrade(box, dry_run=True) == 1
        assert alerts == []
        assert RETRY in capsys.readouterr().err

    def test_a_clean_dry_run_does_not_alert(self, box, alerts):
        _project(box, "shop")
        assert run_upgrade(box, dry_run=True) == 0
        assert alerts == []

    def test_check_upgrade_raises_before_reading_any_project(self, box):
        _project(box, "alpha")
        (box.project_dir("alpha") / "manifest.yml").write_text("- not a manifest\n")
        _bundle(box, "shop")
        with pytest.raises(UpgradeGateError, match="legacy-stage shop"):
            check_upgrade(box)

    def test_the_apply_refuses_before_it_touches_a_project(self, box):
        _project(box, "alpha")
        _project(box, "shop", live=False)
        _record(box, shop={"kind": "pre0101", "choice": "discard"})
        site = box.project_caddy_site("alpha").read_text()
        with pytest.raises(UpgradeGateError, match="prod-deploy shop"):
            apply_projects(box)
        assert box.project_caddy_site("alpha").read_text() == site
        assert not box.project_compose_override("alpha").exists()

    def test_a_clean_box_passes_the_dry_run(self, box):
        _project(box, "alpha")
        assert [line.text for line in check_upgrade(box)] == ["alpha: configs render OK"]
