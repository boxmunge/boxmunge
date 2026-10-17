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


def test_names_and_ports_dropped(tmp_path) -> None:
    doc = _base(tmp_path, {"services": {"web": {"image": "x", "ports": ["80:80"]}},
                           "volumes": {"d": {"name": "myapp_d"}},
                           "networks": {"n": {"name": "myapp_n"}}})
    assert "ports" not in doc["services"]["web"]
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


def test_reference_walk_reads_relative_files_from_the_project_directory(tmp_path) -> None:
    """Compose reads a relative env_file from the project directory (the
    staged release), so that is the file the own-file rules protect."""
    from boxmunge.compose_resolve import walk_references
    release = tmp_path / "release"
    release.mkdir()
    base = tmp_path / "compose.staging-base.yml"
    base.write_text(yaml.safe_dump({"services": {"web": {
        "image": "nginx", "env_file": ["./app.env"], "label_file": "./labels"}}}))
    problems, files = walk_references(base, (release, tmp_path), base=release)
    assert problems == [] and {release / "app.env", release / "labels"} <= set(files)


def _validate_slot_base(paths, doc: dict) -> None:
    from boxmunge.compose_validate import validate_user_compose
    slot = paths.project_releases("myapp") / "staged"
    (slot / "release").mkdir(parents=True)
    (slot / "compose.staging-base.yml").write_text(yaml.safe_dump(doc))
    validate_user_compose(slot / "compose.staging-base.yml", paths, project_name="myapp",
                          project_directory=slot / "release")


def test_validator_refuses_a_writable_mount_of_the_slots_release(paths) -> None:
    """Staging runs the release where it is, in the slot: a container that
    could write it would plant files promote carries into production."""
    from boxmunge.compose_validate import ComposeSecurityError
    with pytest.raises(ComposeSecurityError, match=r"rewrite \.releases"):
        _validate_slot_base(paths, {"services": {"web": {
            "image": "nginx", "volumes": ["./src:/x"]}}})


def test_validator_locates_slot_and_project_paths_in_one_space(paths) -> None:
    """The release's appconfig/x is not inside production's appconfig."""
    prod = paths.project_dir("myapp")
    _validate_slot_base(paths, {"services": {"web": {"image": "nginx", "volumes": [
        f"{prod}/appconfig:/a", "./appconfig/x:/b:ro"]}}})


def test_label_files_resolve_like_env_files(tmp_path) -> None:
    web = _web(tmp_path, label_file=["./labels", "../l", "./data/l"])
    assert web["label_file"] == ["./labels", f"{P.parent}/l", f"{P}/data/l"]
    assert _web(tmp_path, label_file="../l")["label_file"] == [f"{P.parent}/l"]


def test_additional_contexts_that_leave_the_project_are_made_absolute(tmp_path) -> None:
    build = _web(tmp_path, build={"context": ".", "additional_contexts": {
        "a": "../lib", "b": "./vendor", "c": "docker-image://alpine", "d": "service:base"}})["build"]
    assert build["additional_contexts"] == {"a": f"{P.parent}/lib", "b": "./vendor",
                                            "c": "docker-image://alpine", "d": "service:base"}
    listed = _web(tmp_path, build={"context": ".", "additional_contexts": ["a=../lib"]})["build"]
    assert listed["additional_contexts"] == [f"a={P.parent}/lib"]


@pytest.mark.parametrize("build", [
    "./data", {"context": f"{P}/uploads/x"},
    {"context": ".", "additional_contexts": {"a": "./data/src"}},
])
def test_box_state_build_contexts_are_refused(tmp_path, build) -> None:
    with pytest.raises(ComposeError, match="Build from release code"):
        _web(tmp_path, build=build)
