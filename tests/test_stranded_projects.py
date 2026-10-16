"""A project created before its name was reserved (`<x>-staging`, `caddy`,
`system`) can no longer be managed. Fleet loops must report it loudly and
carry on with every other project, not fail the whole run."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from boxmunge.container_update_targets import build_targets
from boxmunge.fleet import PROJECT_INPUT_ERRORS
from boxmunge.paths import BoxPaths, InvalidProjectName, validate_project_name

_MANIFEST = (
    "schema_version: 3\nid: 01TESTULID0000000000000000\nproject: {name}\n"
    "source: bundle\nhosts: [{name}.example.com]\n"
    "services:\n  web:\n    port: 80\n    routes: [{{path: /}}]\n"
)


def _project(paths: BoxPaths, name: str) -> None:
    project_dir = paths.projects / name  # built by hand: the name may be reserved
    project_dir.mkdir(parents=True)
    (project_dir / "manifest.yml").write_text(_MANIFEST.format(name=name))
    (project_dir / "compose.yml").write_text("services:\n  web:\n    image: nginx\n")


@pytest.mark.parametrize("name", ["shop-staging", "caddy", "system"])
def test_reserved_name_raises_a_project_input_error(name: str) -> None:
    with pytest.raises(InvalidProjectName):
        validate_project_name(name)
    assert issubclass(InvalidProjectName, PROJECT_INPUT_ERRORS)
    assert issubclass(InvalidProjectName, ValueError)


def test_container_update_reports_stranded_project_and_continues(
    paths: BoxPaths, capsys,
) -> None:
    _project(paths, "shop")
    _project(paths, "shop-staging")
    names = [t.name for t in build_targets(paths, {})]
    assert names == ["caddy", "shop"]
    assert "container-update: shop-staging: Invalid project name" in capsys.readouterr().err


def test_container_update_reports_unreadable_manifest(paths: BoxPaths, capsys) -> None:
    _project(paths, "shop")
    _project(paths, "broken")
    (paths.projects / "broken" / "manifest.yml").write_text("- not a mapping\n")
    names = [t.name for t in build_targets(paths, {})]
    assert names == ["caddy", "shop"]
    assert "container-update: broken:" in capsys.readouterr().err


def test_upgrade_restart_skips_stranded_project(paths: BoxPaths, capsys) -> None:
    from boxmunge.commands.upgrade_steps import restart_projects

    _project(paths, "shop")
    _project(paths, "system")
    with patch("boxmunge.commands.upgrade_steps.compose_up") as up:
        succeeded, failed, _ = restart_projects(paths, refused=())
    assert succeeded == ["shop"] and failed == []
    assert up.call_args.kwargs["project_name"] == "shop"
    assert "upgrade: system: Invalid project name" in capsys.readouterr().err


def test_upgrade_regenerate_skips_stranded_project(paths: BoxPaths, capsys) -> None:
    from boxmunge.commands.upgrade_steps import regenerate_configs

    _project(paths, "shop")
    _project(paths, "shop-staging")
    with patch("boxmunge.caddy.caddy_config_lock"):
        processed = regenerate_configs(paths).processed
    assert processed == ["shop"]
    assert "upgrade: shop-staging:" in capsys.readouterr().err
