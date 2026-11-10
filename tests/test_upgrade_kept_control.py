"""D-02, the regeneration half: an upgrade checks a project's control files
against its record before it regenerates anything from them. A project
whose manifest or caddy.override.conf changed since its deploy is refused
and keeps the Caddy site and overlay it had, so the reload serves its old
routing."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from boxmunge.paths import BoxPaths
from boxmunge.upgrade_exclusions import apply_projects
from tests.deploy_helpers import mark_deployed

_MANIFEST = (
    "schema_version: 3\nid: 01TESTULID0000000000000000\nproject: shop\n"
    "source: bundle\nhosts: [{host}]\n"
    "services:\n  web:\n    port: 80\n    routes: [{{path: /}}]\n"
)


def _apply(paths: BoxPaths):
    with patch("boxmunge.caddy.caddy_config_lock"):
        return apply_projects(paths)[1]


def _shop(paths: BoxPaths, *, override: bool):
    project_dir = paths.projects / "shop"
    project_dir.mkdir(parents=True)
    (project_dir / "manifest.yml").write_text(_MANIFEST.format(host="shop.example.com"))
    (project_dir / "compose.yml").write_text("services:\n  web:\n    image: nginx\n")
    if override:
        (project_dir / "caddy.override.conf").write_text("shop.example.com {\n  respond ok\n}\n")
    mark_deployed(paths, "shop")
    assert _apply(paths).processed == ["shop"]
    return project_dir


@pytest.mark.parametrize("override, edit, changed", [
    (False, lambda d: (d / "manifest.yml").write_text(_MANIFEST.format(host="evil.example.com")),
     "manifest.yml"),
    (True, lambda d: (d / "caddy.override.conf").write_text("evil.example.com {\n  respond x\n}\n"),
     "caddy.override.conf"),
])
def test_a_project_edited_since_its_deploy_keeps_its_generated_files(
        paths: BoxPaths, override, edit, changed) -> None:
    shop = _shop(paths, override=override)
    site = paths.project_caddy_site("shop")
    overlay = paths.project_compose_override("shop")
    before = (site.read_text(), overlay.read_text())
    assert "shop.example.com" in before[0]
    edit(shop)
    regen = _apply(paths)
    assert regen.processed == []
    assert f"control file {changed} changed" in regen.refused["shop"]
    assert (site.read_text(), overlay.read_text()) == before
