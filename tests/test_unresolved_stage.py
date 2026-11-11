# SPDX-License-Identifier: Apache-2.0
"""The upgrade refuses, before it changes anything, while a project holds a
stage boxmunge 0.10.1 or earlier made and no release has resolved."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from boxmunge import unresolved_stage
from boxmunge.commands.upgrade_cmd import run_upgrade
from boxmunge.commands.upgrade_steps import UpgradeGateError, check_upgrade
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


class TestTheWholeRefusal:
    def test_names_every_project_and_how_to_go_on(self, box):
        _bundle(box, "alpha")
        _project(box, "beta")
        _project(box, "gamma", live=False)
        _record(box, gamma={"kind": "pre0101", "choice": "discard"})
        lines = _refusal(box).splitlines()
        assert lines[0] == (
            "2 projects hold a release that boxmunge 0.10.1 or earlier staged over "
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
            f"first, with `sudo /opt/boxmunge/bin/boxmunge-upgrade target 0.11.6`. Then, on "
            f"0.11.6:")
        assert "`boxmunge-server legacy-stage shop`" in lines[1]

    @pytest.mark.parametrize("installed", ["0.11.7", "0.11.7+abc1234", "0.12.0", "1.0.0"])
    def test_a_box_that_already_runs_a_release_without_legacy_stage_is_not_checked(
            self, box, installed):
        """No such box can hold one (this refusal let none through), and it
        has none of the commands the refusal would name."""
        _bundle(box)
        assert _refusal(box, installed) is None

    @pytest.mark.parametrize("installed", ["", "0.0.0", "garbage"])
    def test_an_unknown_installed_version_is_checked(self, box, installed):
        _bundle(box)
        text = _refusal(box, installed)
        assert "This box runs a release it has no record of, which does not" in text
        assert "legacy-stage shop" in text

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


class TestTheUpgrade:
    def test_the_dry_run_refuses_and_says_how_to_retry(self, box, capsys):
        _pre0101(box)
        before = sorted(p for p in box.root.rglob("*"))
        assert run_upgrade(box, dry_run=True) == 1
        err = capsys.readouterr().err
        assert "ERROR: 1 project holds a release that boxmunge 0.10.1 or earlier" in err
        assert "`boxmunge-server legacy-stage shop`" in err
        assert "boxmunge-upgrade clear-blocklist" in err
        assert sorted(p for p in box.root.rglob("*")) == before

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
        assert check_upgrade(box) == ["alpha: configs render OK"]
