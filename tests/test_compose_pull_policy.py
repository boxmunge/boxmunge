# SPDX-License-Identifier: Apache-2.0
"""A `pull_policy` that would pull or build at every start is refused where a
release is judged (deploy, stage, validate) and warned about where an
installed project is acted on (its starts, the upgrade, a rollback), whose
starts run local images only."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from boxmunge.commands.validate import run_validate
from boxmunge.compose_guard import compose_up_checked
from boxmunge.compose_validate import ComposeSecurityError, validate_user_compose
from tests.deploy_helpers import mark_deployed
from tests.test_commands.test_validate import VALID_MANIFEST, _setup_project


def _compose(tmp_path: Path, frontend: str) -> Path:
    path = tmp_path / "compose.yml"
    path.write_text(f"services:\n  frontend:\n{frontend}  db:\n    image: postgres:16\n")
    return path


@pytest.mark.parametrize("frontend, what", [
    ("    image: nginx:1.27\n    pull_policy: always\n", "pull"),
    ("    image: nginx:1.27\n    pull_policy: daily\n", "pull"),
    ("    build: .\n    pull_policy: build\n", "build"),
], ids=["always", "daily", "build"])
def test_a_policy_that_fetches_at_every_start_is_refused(tmp_path, paths, frontend,
                                                         what) -> None:
    with pytest.raises(ComposeSecurityError,
                       match=rf"service frontend: pull_policy: .* would {what} a new image "
                             r"at every start.*Remove it"):
        validate_user_compose(_compose(tmp_path, frontend), paths, project_name="myapp")


@pytest.mark.parametrize("policy", ["missing", "if_not_present", "never"])
def test_a_policy_that_uses_the_local_image_is_fine(tmp_path, paths, policy) -> None:
    compose = _compose(tmp_path, f"    image: nginx:1.27\n    pull_policy: {policy}\n")
    validate_user_compose(compose, paths, project_name="myapp")


def test_an_installed_project_is_warned_not_refused(tmp_path, paths, capsys) -> None:
    compose = _compose(tmp_path, "    image: nginx:1.27\n    pull_policy: always\n")
    validate_user_compose(compose, paths, project_name="myapp", lenient_values=True)
    assert "its starts do not apply it" in capsys.readouterr().out
    assert "pull_policy: always" in paths.log_file.read_text()


def test_validate_reports_it_as_an_error(paths, capsys) -> None:
    _setup_project(paths, "myapp", VALID_MANIFEST)
    (paths.project_dir("myapp") / "compose.yml").write_text(
        "services:\n  frontend:\n    image: nginx\n    pull_policy: always\n")
    assert run_validate("myapp", paths) == 1
    assert "pull_policy: always would pull" in capsys.readouterr().err


def test_a_start_warns_and_goes_ahead_without_applying_it(paths, capsys) -> None:
    """The start's re-validation is lenient; the start itself pulls nothing."""
    paths.config.mkdir(parents=True, exist_ok=True)
    paths.config_file.write_text(yaml.safe_dump({"hostname": "box.example.com",
                                                 "admin_email": "ops@example.com"}))
    _setup_project(paths, "myapp", VALID_MANIFEST)
    (paths.project_dir("myapp") / "compose.yml").write_text(
        "services:\n  frontend:\n    image: nginx\n    pull_policy: always\n")
    mark_deployed(paths, "myapp")
    with patch("boxmunge.compose_guard.compose_up") as up:
        compose_up_checked(paths, "myapp", component="upgrade", compose_files=["compose.yml"])
    assert up.call_args.kwargs["pinned"] is True
    assert "its starts do not apply it" in capsys.readouterr().out
