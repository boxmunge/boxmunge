# SPDX-License-Identifier: Apache-2.0
"""A project whose compose.yml the new release's validator refuses.

Such a compose predates a validator fix. The upgrade must not hand it a new
overlay, and must not rebuild or re-run it as root either: the project keeps
its old configs and its running containers, untouched. The refusal is named
in the upgrade output, logged, and alerted, and the dry run reports it in
advance.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from boxmunge.commands.upgrade_cmd import run_upgrade
from boxmunge.commands.upgrade_steps import regenerate_configs, restart_projects
from boxmunge.version import read_installed_version
from tests.test_commands.test_upgrade_dry_run_and_pause import _project, _setup, _snapshot

OLD_OVERLAY = "# overlay written by the previous release\n"
HOSTILE = "services:\n  web:\n    image: nginx:1.25\n    privileged: true\n"


@pytest.fixture
def paths(tmp_path: Path):
    paths = _setup(tmp_path)
    paths.config_file.write_text(
        "hostname: test\nadmin_email: t@t\n"
        "pushover:\n  user_key: u\n  app_token: t\n"
    )
    _project(paths, "good")
    _project(paths, "bad")
    paths.project_compose("bad").write_text(HOSTILE)
    paths.project_compose_override("bad").write_text(OLD_OVERLAY)
    return paths


def _log_entries(paths) -> list[dict]:
    return [json.loads(line) for line in paths.log_file.read_text().splitlines()]


def test_regenerate_leaves_refused_project_on_its_old_configs(paths) -> None:
    site_before = paths.project_caddy_site("bad").read_text()
    with patch("boxmunge.caddy.caddy_config_lock"):
        regen = regenerate_configs(paths)
    assert regen.processed == ["good"]
    assert list(regen.refused) == ["bad"]
    assert "privileged" in regen.refused["bad"]
    assert paths.project_compose_override("bad").read_text() == OLD_OVERLAY
    assert paths.project_caddy_site("bad").read_text() == site_before
    refusals = [e for e in _log_entries(paths)
                if e.get("project") == "bad" and e["level"] == "error"]
    assert refusals and "privileged" in refusals[0]["msg"]


def test_restart_skips_refused_projects(paths) -> None:
    with patch("boxmunge.commands.upgrade_steps.compose_up") as up:
        succeeded, failed, skipped = restart_projects(paths, refused={"bad": "x"})
    assert [c.kwargs["project_name"] for c in up.call_args_list] == ["good"]
    assert (succeeded, failed, skipped) == (["good"], [], [])


@patch("boxmunge.commands.upgrade_cmd.caddy_reload")
@patch("boxmunge.notify.send_notification", return_value=True)
@patch("boxmunge.commands.upgrade_steps.compose_up")
def test_apply_does_not_rebuild_or_rerun_refused_project(
    up, pushover, _reload, paths, capsys,
) -> None:
    assert run_upgrade(paths, apply_only=True) == 0

    assert [c.kwargs["project_name"] for c in up.call_args_list] == ["good"]
    assert paths.project_compose_override("bad").read_text() == OLD_OVERLAY
    assert read_installed_version(paths) != "0.2.0+abc1234"

    out = capsys.readouterr().out
    assert "REFUSED" in out and "bad" in out and "privileged" in out

    assert pushover.call_count == 1
    _, _, title, body = pushover.call_args.args
    assert "refused" in title.lower()
    assert "bad" in body and "good" not in body
    assert pushover.call_args.kwargs["priority"] == 1

    done = [e for e in _log_entries(paths) if e["msg"].startswith("Apply ")]
    assert done[-1]["detail"]["refused"] == ["bad"]


@patch("boxmunge.commands.upgrade_cmd.caddy_reload")
@patch("boxmunge.notify.send_notification", return_value=True)
@patch("boxmunge.commands.upgrade_steps.compose_up")
def test_no_alert_when_nothing_is_refused(up, pushover, _reload, paths) -> None:
    paths.project_compose("bad").write_text("services:\n  web:\n    image: nginx:1.25\n")
    assert run_upgrade(paths, apply_only=True) == 0
    pushover.assert_not_called()
    assert len(up.call_args_list) == 2


@patch("boxmunge.notify.send_notification", return_value=True)
@patch("boxmunge.commands.upgrade_steps.compose_up")
def test_dry_run_reports_projects_the_new_validator_refuses(
    up, pushover, paths, capsys,
) -> None:
    before = _snapshot(paths.root)

    assert run_upgrade(paths, dry_run=True) == 0

    out = capsys.readouterr().out
    bad = [line for line in out.splitlines() if line.strip().startswith("bad:")]
    assert bad and "would be refused" in bad[0] and "privileged" in bad[0]
    assert any(line.strip() == "good: configs render OK" for line in out.splitlines())
    assert _snapshot(paths.root) == before
    up.assert_not_called()
    pushover.assert_not_called()
