# SPDX-License-Identifier: Apache-2.0
"""The deployed inventory joins the resolved model with labelled containers.

Real resolution (include, extends, interpolation, profiles) is covered in
tests/integration/test_scan_inventory.py; here conftest's literal stand-in
for `docker compose config` supplies the model.
"""
from __future__ import annotations

import pytest

from boxmunge import docker
from boxmunge.deployed_inventory import InventoryError, load_deployed_inventory

_IMG = "sha256:" + "1" * 64


def _write(tmp_path, compose: str):
    (tmp_path / "compose.yml").write_text(compose)
    return tmp_path


def test_services_profiles_and_containers(tmp_path, fake_containers):
    project = _write(tmp_path, (
        "services:\n"
        "  web:\n    image: nginx:1\n"
        "  app:\n    build: .\n"
        "  dev:\n    image: dev:1\n    profiles: [dev]\n"))
    web = fake_containers.run("demo", "web", _IMG, name="custom-web")
    leftover = fake_containers.run("demo", "retired", _IMG)

    inv = load_deployed_inventory(project, ["compose.yml"], "demo")

    assert list(inv.services) == ["web", "app", "dev", "retired"]
    assert (inv.services["web"].image, inv.services["web"].expected) == ("nginx:1", True)
    assert inv.services["web"].containers == (web,)
    assert inv.services["app"].buildable and inv.services["app"].containers == ()
    assert not inv.services["dev"].expected
    assert inv.services["retired"].containers == (leftover,)
    assert not inv.services["retired"].expected


def test_unresolvable_model_is_an_inventory_error(tmp_path):
    with pytest.raises(InventoryError, match="demo"):
        load_deployed_inventory(tmp_path, ["compose.yml"], "demo")


def test_docker_failure_is_an_inventory_error(tmp_path, monkeypatch):
    project = _write(tmp_path, "services:\n  web:\n    image: nginx:1\n")

    def down(project_name):
        raise docker.DockerError("Cannot connect to the Docker daemon")

    monkeypatch.setattr("boxmunge.docker_containers.project_containers", down)
    with pytest.raises(InventoryError, match="Cannot connect"):
        load_deployed_inventory(project, ["compose.yml"], "demo")


def test_both_profile_views_are_resolved_from_every_deployed_file(tmp_path, monkeypatch):
    calls = []

    def config(project_dir, compose_files=None, *, project_name, all_profiles=False):
        calls.append((compose_files, project_name, all_profiles))
        return '{"services": {}}'

    monkeypatch.setattr(docker, "compose_config", config)
    load_deployed_inventory(tmp_path, ["compose.yml", "compose.boxmunge.yml"], "demo")
    assert calls == [(["compose.yml", "compose.boxmunge.yml"], "demo", False),
                     (["compose.yml", "compose.boxmunge.yml"], "demo", True)]
