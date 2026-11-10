# SPDX-License-Identifier: Apache-2.0
"""A caddy.override.conf the upgrade cannot use refuses that project only.

prepare_caddy_config's refusal of a planted override (a link out of the
project, a FIFO, an oversized file) used to raise through
_regenerate_project's catch-all, abort the upgrade and blocklist the
release for the whole fleet, and the dry run did not predict it. It is now
a per-project refusal, as a compose refusal is: the project keeps its
current site file and containers and is not restarted, the log names the
fix, and the dry run says the same.
"""
from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch


from boxmunge.commands.upgrade_steps import check_upgrade, restart_projects
from boxmunge.paths import BoxPaths
from boxmunge.upgrade_exclusions import apply_projects
from boxmunge.version import write_installed_version
from tests.bundle_helpers import manifest_text
from tests.deploy_helpers import mark_deployed

OLD_SITE = "shop.example.com {\n    respond old\n}\n"


def _box(tmp_path: Path, before_deploy=lambda paths: None) -> BoxPaths:
    paths = BoxPaths(root=tmp_path / "bm")
    for d in ["config", "projects", "state/deploy", "stashes", "logs",
              "caddy/sites", "upgrade-state"]:
        (paths.root / d).mkdir(parents=True)
    paths.config_file.write_text("hostname: test\nadmin_email: t@t\n")
    write_installed_version(paths, "0.11.0", "abc1234")
    pdir = paths.project_dir("shop")
    pdir.mkdir(parents=True)
    (pdir / "manifest.yml").write_text(manifest_text("shop"))
    (pdir / "compose.yml").write_text("services:\n  web:\n    image: nginx:1.25\n")
    paths.project_caddy_site("shop").write_text(OLD_SITE)
    before_deploy(paths)
    mark_deployed(paths, "shop")
    return paths


def _lines(paths: BoxPaths) -> list[str]:
    return [ln for ln in check_upgrade(paths)
            if ln.startswith("shop:") and "migration" not in ln]


@patch("boxmunge.compose_guard.compose_up")
def test_an_override_this_release_refuses_refuses_that_project_only(mock_up, tmp_path) -> None:
    """An override 0.11.5 used (here, one over the new 1 MB cap, recorded
    at its deploy, so the kept-file check passes) no longer aborts the
    upgrade for every project."""
    from boxmunge.caddy_journal import MAX_SITE_BYTES

    def oversized(paths: BoxPaths) -> None:
        paths.project_caddy_override("shop").write_text("#" * (MAX_SITE_BYTES + 1))

    paths = _box(tmp_path, oversized)
    [line] = _lines(paths)
    assert "would be left on its current configs" in line and "larger than" in line

    migration, regen, excluded = apply_projects(paths)  # no UpgradeGateError
    assert "larger than" in regen.refused["shop"]
    assert paths.project_caddy_site("shop").read_text() == OLD_SITE
    restart = restart_projects(paths, refused=regen.refused, excluded=excluded.names())
    assert "shop" not in restart.succeeded
    assert "fix the override, then prod-deploy shop --redeploy" in paths.log_file.read_text()


@patch("boxmunge.compose_guard.compose_up")
def test_an_override_linked_out_of_the_project_is_refused_unread(mock_up, tmp_path) -> None:
    paths = _box(tmp_path)
    secret = tmp_path / "root-only"
    secret.write_text("ROOT SECRET\n")
    paths.project_caddy_override("shop").symlink_to(secret)

    [line] = _lines(paths)
    assert "would be left on its current configs" in line and "outside the project" in line
    _, regen, _ = apply_projects(paths)  # no UpgradeGateError
    assert "outside the project" in regen.refused["shop"]
    assert paths.project_caddy_site("shop").read_text() == OLD_SITE
    assert "ROOT SECRET" not in paths.log_file.read_text()


@patch("boxmunge.compose_guard.compose_up")
def test_an_override_linked_into_the_repo_is_used(mock_up, tmp_path) -> None:
    """A git operator may keep the override in the repository and link it,
    the way boxmunge links compose.yml: a link that stays in the project."""
    def link(paths: BoxPaths) -> None:
        repo = paths.project_dir("shop") / "repo"
        repo.mkdir()
        (repo / "caddy.override.conf").write_text("shop.example.com {\n    respond new\n}\n")
        paths.project_caddy_override("shop").symlink_to("repo/caddy.override.conf")

    paths = _box(tmp_path, link)
    assert _lines(paths) == ["shop: configs render OK"]
    _, regen, _ = apply_projects(paths)
    assert regen.refused == {}
    assert "respond new" in paths.project_caddy_site("shop").read_text()


def test_a_dangling_override_link_is_refused_in_the_dry_run(tmp_path) -> None:
    paths = _box(tmp_path)
    paths.project_caddy_override("shop").symlink_to("repo/caddy.override.conf")
    [line] = _lines(paths)
    assert "does not exist" in line


def test_a_fifo_override_is_refused_in_the_dry_run(tmp_path) -> None:
    paths = _box(tmp_path)
    os.mkfifo(paths.project_caddy_override("shop"))
    [line] = _lines(paths)
    assert "not a regular file" in line
