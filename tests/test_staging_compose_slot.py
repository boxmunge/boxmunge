# SPDX-License-Identifier: Apache-2.0
"""Each row of the spec's 'How each path in the staged compose.yml resolves'."""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from boxmunge.compose import ComposeError
from boxmunge.staging_compose import generate_staging_compose_base

P = Path("/opt/boxmunge/projects/myapp")
BOX = {"uploads", "data", "secrets.env", "backups", ".releases"}


def _base(tmp_path, doc) -> dict:
    path = tmp_path / "compose.yml"
    path.write_text(yaml.safe_dump(doc))
    return yaml.safe_load(generate_staging_compose_base(path, BOX, P))


def _web(tmp_path, **svc) -> dict:
    return _base(tmp_path, {"services": {"web": {"image": "x", **svc}}})["services"]["web"]


@pytest.mark.parametrize("source,want", [
    ("./appconfig", "./appconfig"),                        # release code: resolves in the slot
    ("./uploads/img", f"{P}/uploads-staging/img"),          # box state: staging's copy, absolute
    ("./data", f"{P}/data-staging"),
    ("../shared", f"{P.parent}/shared-staging"),            # leaves the project
    (f"{P}/uploads", f"{P}/uploads-staging"),
])
def test_bind_sources(tmp_path, source, want) -> None:
    vols = _web(tmp_path, volumes=[f"{source}:/m", {"type": "bind", "source": source,
                                                   "target": "/n"}])["volumes"]
    assert vols[0].split(":")[0] == want and vols[1]["source"] == want


def test_config_and_secret_files(tmp_path) -> None:
    doc = _base(tmp_path, {"services": {"web": {"image": "x"}},
                           "configs": {"c": {"file": "./conf/app.conf"}},
                           "secrets": {"s": {"file": "./data/key"}}})
    assert doc["configs"]["c"]["file"] == "./conf/app.conf"
    assert doc["secrets"]["s"]["file"] == f"{P}/data-staging/key"


def test_env_files(tmp_path) -> None:
    web = _web(tmp_path, env_file=["./app.env", "./secrets.env", {"path": "../x.env"}])
    assert web["env_file"] == ["./app.env", f"{P}/secrets.env", {"path": f"{P.parent}/x.env"}]


def test_build_contexts(tmp_path) -> None:
    assert _web(tmp_path, build=".")["build"] == "."
    assert _web(tmp_path, build={"context": "../lib"})["build"]["context"] == f"{P.parent}/lib"


def test_names_ports_and_container_names_dropped(tmp_path) -> None:
    doc = _base(tmp_path, {"services": {"web": {"image": "x", "ports": ["80:80"],
                                                "container_name": "w"}},
                           "volumes": {"d": {"name": "myapp_d"}},
                           "networks": {"n": {"name": "myapp_n"}}})
    assert "ports" not in doc["services"]["web"] and "container_name" not in doc["services"]["web"]
    assert "name" not in doc["volumes"]["d"] and "name" not in doc["networks"]["n"]


@pytest.mark.parametrize("doc", [{"include": ["a.yml"], "services": {}},
                                 {"services": {"w": {"extends": {"file": "b.yml", "service": "s"}}}}])
def test_other_files_refused(tmp_path, doc) -> None:
    with pytest.raises(ComposeError, match="Move those services into compose.yml"):
        _base(tmp_path, doc)


def test_validator_resolves_the_base_from_the_slot(paths, tmp_path, monkeypatch) -> None:
    from boxmunge import docker
    from boxmunge.compose_validate import validate_user_compose
    slot = paths.project_releases("myapp") / "staged"
    (slot / "release").mkdir(parents=True)
    (slot / "compose.staging-base.yml").write_text("services:\n  web:\n    image: nginx\n")
    seen: list[dict] = []
    real = docker.compose_config
    monkeypatch.setattr(docker, "compose_config",
                        lambda *a, **k: (seen.append(k), real(*a, **k))[1])
    validate_user_compose(slot / "compose.staging-base.yml", paths, project_name="myapp",
                          project_directory=slot / "release")
    assert seen[0]["project_directory"] == slot / "release"


def test_validator_protects_the_env_files_the_slot_base_reads(paths) -> None:
    """Compose reads a relative env_file from the project directory (the
    staged release), so that is the file no container may write."""
    from boxmunge.compose_validate import ComposeSecurityError, validate_user_compose
    slot = paths.project_releases("myapp") / "staged"
    (slot / "release").mkdir(parents=True)
    (slot / "release" / "app.env").write_text("A=1\n")
    (slot / "compose.staging-base.yml").write_text(yaml.safe_dump({"services": {"web": {
        "image": "nginx", "env_file": ["./app.env"], "volumes": ["./app.env:/app.env"]}}}))
    with pytest.raises(ComposeSecurityError, match="rewrite app.env"):
        validate_user_compose(slot / "compose.staging-base.yml", paths, project_name="myapp",
                              project_directory=slot / "release")
