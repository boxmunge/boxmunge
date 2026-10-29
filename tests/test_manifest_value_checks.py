# SPDX-License-Identifier: Apache-2.0
"""Manifest values that were accepted but wrong: each is an error at
deploy/stage/validate time and only a warning where an installed project is re-checked (upgrade, start, rollback)."""
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from boxmunge.commands.upgrade_steps import check_upgrade, restart_projects
from boxmunge.manifest import validate_manifest
from boxmunge.paths import BoxPaths
from boxmunge.upgrade_exclusions import apply_projects
from boxmunge.version import write_installed_version
from tests.deploy_helpers import mark_deployed


def _manifest(**over) -> dict:
    m = {
        "schema_version": 3, "project": "shop", "id": "01HZZZZZZZZZZZZZZZZZZZZZZZ",
        "source": "bundle", "hosts": ["shop.example.com"],
        "services": {"web": {"port": 80, "routes": [{"path": "/"}], "smoke": "s.sh",
                             "limits": {"memory": "1g"}}},
    }
    m.update(over)
    return m


def _internal_with_routes() -> dict:
    return _manifest(services={"web": {
        "port": 80, "internal": True, "routes": [{"path": "/"}], "smoke": "s.sh"}})


PROBLEMS = {
    "internal-routes": (_internal_with_routes(), "internal: true but has routes"),
    "strategy": (_manifest(container_updates={"strategy": "rollback"}), "container_updates.strategy"),
    "updates-shape": (_manifest(container_updates="on"), "'container_updates' must be a mapping"),
    "type": (_manifest(backup={"type": False}), "backup.type must be a non-empty string"),
    "retention": (_manifest(backup={"type": "none", "retention": "7"}), "backup.retention"),
    "retention-zero": (_manifest(backup={"type": "none", "retention": 0}), "backup.retention"),
}


@pytest.mark.parametrize("key", PROBLEMS)
def test_deploy_time_rejects_it(key) -> None:
    manifest, says = PROBLEMS[key]
    errors, _ = validate_manifest(manifest, "shop")
    assert any(says in e for e in errors), errors


@pytest.mark.parametrize("key", PROBLEMS)
def test_an_upgrade_only_warns(key) -> None:
    manifest, says = PROBLEMS[key]
    errors, warnings = validate_manifest(manifest, "shop", lenient_values=True)
    assert errors == [], errors
    assert any(says in w for w in warnings), warnings


def test_valid_values_pass() -> None:
    manifest = _manifest(
        container_updates={"strategy": "rollback_to_previous"},
        backup={"type": "db-dump", "retention": 14, "dump_command": "d", "restore_command": "r"},
    )
    errors, _ = validate_manifest(manifest, "shop")
    assert errors == []


def test_a_routeless_internal_service_is_still_fine() -> None:
    manifest = _manifest(services={
        "web": _manifest()["services"]["web"], "db": {"internal": True}})
    errors, _ = validate_manifest(manifest, "shop")
    assert errors == []


def test_backup_command_shares_the_retention_check(tmp_path) -> None:
    from boxmunge.manifest_fields import retention_problem
    assert retention_problem(7) is None
    for bad in (0, -1, True, "7", 1.5, None):
        assert retention_problem(bad), bad


def _box(tmp_path: Path) -> BoxPaths:
    paths = BoxPaths(root=tmp_path / "bm")
    for d in ["config", "projects", "state/deploy", "stashes", "logs",
              "caddy/sites", "upgrade-state"]:
        (paths.root / d).mkdir(parents=True)
    paths.config_file.write_text("hostname: test\nadmin_email: t@t\n")
    write_installed_version(paths, "0.11.0", "abc1234")
    return paths


@patch("boxmunge.compose_guard.compose_up")
def test_upgrade_leaves_a_project_with_every_new_problem_running(mock_up, tmp_path) -> None:
    paths = _box(tmp_path)
    # schema 1, so the upgrade migrates and validates it: the one path that
    # would have raised and rolled the whole box back.
    manifest = _manifest(
        schema_version=1,
        services={"web": {"port": 80, "internal": True, "routes": [{"path": "/"}],
                          "smoke": "s.sh", "limits": {"memory": "1g"}}},
        container_updates={"strategy": "rollback"},
        backup={"type": False, "retention": 0},
    )
    pdir = paths.project_dir("shop")
    pdir.mkdir(parents=True)
    (pdir / "manifest.yml").write_text(yaml.dump(manifest))
    (pdir / "compose.yml").write_text("services:\n  web:\n    image: nginx:1.25\n")
    mark_deployed(paths, "shop")

    assert any("shop" in line for line in check_upgrade(paths))
    migration, regen, excluded = apply_projects(paths)
    restart = restart_projects(paths, refused=regen.refused, excluded=excluded.names())

    assert migration.written == ["shop"] and not excluded.names() and not regen.refused
    assert restart.succeeded == ["shop"] and restart.failed == []
    after = yaml.safe_load((pdir / "manifest.yml").read_text())
    assert after["services"] == manifest["services"]
    assert after["container_updates"] == manifest["container_updates"]
    assert after["backup"] == manifest["backup"]
