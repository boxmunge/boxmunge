# SPDX-License-Identifier: Apache-2.0
"""Staging and production share no resource: real `docker compose config`.

Codebase review findings 03 and 12. A stage is run for real (containers are
not started); then both environments' models are resolved the way they run,
`-p <project>` against `-p <project>-staging`, and every volume, network,
alias, container name and bind source is compared. Production's mounts of
release code must still show production's release while the staged one is
installed in the project dir, and staging's must show the staged release.
"""
from __future__ import annotations

import shutil
import uuid
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from boxmunge.commands.deploy import run_deploy
from boxmunge.commands.stage_cmd import run_stage
from boxmunge.commands.unstage_cmd import run_unstage
from boxmunge.project_registry import add_project
from boxmunge.staging_isolation import (
    identities, overlaps, production_model, staging_model,
)
from tests.bundle_helpers import manifest_text, place_bundle

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which("docker") is None, reason="docker CLI not on PATH"),
    # Copies, placeholders and cleanup run in the data helper.
    pytest.mark.usefixtures("helper_image"),
]

V1 = "2026-10-13T090000000000"
V2 = "2026-10-13T100000000000"


def _compose(project: str) -> str:
    return yaml.safe_dump({
        "services": {
            "web": {
                "image": "nginx",
                "networks": ["internal"], "configs": ["appconf"],
                "volumes": ["data:/var/data", "./appconfig:/etc/app:ro",
                            "./site.conf:/etc/site.conf:ro", "./uploads:/uploads"],
            },
            "db": {"image": "postgres", "networks": ["internal"],
                   "volumes": ["./dbdata/pg:/var/lib/postgresql/data"]},
        },
        # Explicit own names: allowed by validation, the same as Compose's.
        "volumes": {"data": {"name": f"{project}_data"}},
        "configs": {"appconf": {"file": "./conf/app.conf"}},
        "networks": {"internal": {"name": f"{project}_internal"}},
    })


@contextmanager
def _no_containers():
    with patch("boxmunge.compose_guard.compose_up"), \
            patch("boxmunge.commands.deploy.caddy_reload"), \
            patch("boxmunge.commands.stage_cmd.caddy_reload"), \
            patch("boxmunge.commands.unstage_cmd.compose_down"), \
            patch("boxmunge.commands.unstage_cmd.caddy_reload"):
        yield


def _manifest(project: str) -> str:
    manifest = yaml.safe_load(manifest_text(project))
    manifest["schema_version"] = 3
    manifest["services"]["web"]["writable"] = {"external": True}
    return yaml.safe_dump(manifest)


def _release(project: str, version: str) -> dict[str, str]:
    return {"manifest.yml": _manifest(project), "compose.yml": _compose(project),
            "appconfig/settings": f"{version}-config",
            "site.conf": f"{version}-site", "uploads/.keep": "",
            "conf/app.conf": f"{version}-conf"}


@pytest.fixture
def staged(paths):
    project = f"bmst{uuid.uuid4().hex[:8]}"
    add_project(project, paths)
    place_bundle(paths, project, V1, {**_release(project, "prod")})
    place_bundle(paths, project, V2, {**_release(project, "staged")})
    with _no_containers():
        assert run_deploy(project, paths, ref=V1) == 0
        assert run_stage(project, paths, ref=V2) == 0
    return project


def _source(model: dict, service: str, target: str) -> Path:
    entry, = [v for v in model["services"][service]["volumes"] if v["target"] == target]
    return Path(entry["source"])


def test_production_and_staging_share_nothing(paths, staged) -> None:
    project_dir = paths.project_dir(staged)
    prod, staging = production_model(paths, staged), staging_model(paths, staged)
    prod_ids = identities(prod, staged, project_dir)
    staging_ids = identities(staging, f"{staged}-staging", project_dir)
    assert overlaps(prod_ids, staging_ids) == []
    assert staging_ids.volumes >= {f"{staged}-staging_data"}
    assert staging_ids.networks >= {f"{staged}-staging_internal"}
    assert f"{staged}-web-1" in prod_ids.containers
    assert f"{staged}-staging-web-1" in staging_ids.containers
    assert _source(staging, "db", "/var/lib/postgresql/data") == \
        project_dir / "dbdata-staging" / "pg"


def test_production_keeps_reading_its_own_release(paths, staged) -> None:
    """Review finding 12: stage installed V2 in the project dir, yet what
    production mounts is V1, and staging gets V2 without copy_data."""
    project_dir = paths.project_dir(staged)
    assert (project_dir / "appconfig" / "settings").read_text() == "staged-config"
    prod, staging = production_model(paths, staged), staging_model(paths, staged)
    assert (_source(prod, "web", "/etc/app") / "settings").read_text() == "prod-config"
    assert _source(prod, "web", "/etc/site.conf").read_text() == "prod-site"
    assert (_source(staging, "web", "/etc/app") / "settings").read_text() == "staged-config"
    assert _source(staging, "web", "/etc/site.conf").read_text() == "staged-site"
    assert Path(prod["configs"]["appconf"]["file"]).read_text() == "prod-conf"
    assert Path(staging["configs"]["appconf"]["file"]).read_text() == "staged-conf"
    # Data is never copied: production writes the real directory.
    assert _source(prod, "web", "/uploads") == project_dir / "uploads"


def test_unstage_leaves_production_reading_its_release(paths, staged) -> None:
    with _no_containers():
        assert run_unstage(staged, paths) == 0
    prod = production_model(paths, staged)
    assert (_source(prod, "web", "/etc/app") / "settings").read_text() == "prod-config"


def test_a_stage_beside_an_older_production_overlay_is_refused(paths, capsys) -> None:
    """Production's overlay predates its own copies: it mounts ./appconfig
    from the project dir, which staging would replace. Refused before
    anything is installed, naming that mount and nothing else."""
    project = f"bmst{uuid.uuid4().hex[:8]}"
    add_project(project, paths)
    place_bundle(paths, project, V1, {**_release(project, "prod")})
    place_bundle(paths, project, V2, {**_release(project, "staged")})
    with _no_containers():
        assert run_deploy(project, paths, ref=V1) == 0
    overlay = paths.project_compose_override(project)
    doc = yaml.safe_load(overlay.read_text())
    for svc in doc["services"].values():
        svc["volumes"] = [v for v in svc.get("volumes", [])
                          if ".releases/live-mounts" not in str(v)]
    overlay.write_text(yaml.safe_dump(doc))
    with _no_containers():
        assert run_stage(project, paths, ref=V2) == 1
    err = capsys.readouterr().err
    assert "generated by an older boxmunge" in err and "appconfig" in err
    assert "whole project directory" not in err
    assert "Nothing was changed" in err
    pdir = paths.project_dir(project)
    assert (pdir / "appconfig" / "settings").read_text() == "prod-config"
    assert not (pdir / ".releases" / "prestage").exists()


def test_a_whole_project_mount_is_refused_before_install(paths, capsys) -> None:
    project = f"bmst{uuid.uuid4().hex[:8]}"
    add_project(project, paths)
    staged = _release(project, "staged")
    doc = yaml.safe_load(staged["compose.yml"])
    doc["services"]["web"]["volumes"].append(".:/srv/all:ro")
    staged["compose.yml"] = yaml.safe_dump(doc)
    place_bundle(paths, project, V1, _release(project, "prod"))
    place_bundle(paths, project, V2, staged)
    with _no_containers():
        assert run_deploy(project, paths, ref=V1) == 0
        assert run_stage(project, paths, ref=V2) == 1
    err = capsys.readouterr().err
    assert "staging web:/srv/all mounts the whole project directory" in err
    assert "older boxmunge" not in err
    pdir = paths.project_dir(project)
    assert (pdir / "appconfig" / "settings").read_text() == "prod-config"
    assert not (pdir / ".releases" / "prestage").exists()
