# SPDX-License-Identifier: Apache-2.0
"""Each row of the spec's 'How each path in the staged compose.yml resolves'."""
from __future__ import annotations

import os
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


@pytest.mark.parametrize("build,want", [
    (f"{P}/src", "./src"),
    ({"context": f"{P}"}, {"context": "."}),
    ({"context": f"{P}/src/"}, {"context": "./src"}),
    ({"context": ".", "dockerfile": f"{P}/docker/Dockerfile"},
     {"context": ".", "dockerfile": "docker/Dockerfile"}),
    ({"context": f"{P}/src", "dockerfile": f"{P}/docker/Dockerfile"},   # relative to the context
     {"context": "./src", "dockerfile": "../docker/Dockerfile"}),
    ({"dockerfile": f"{P}/Dockerfile"}, {"dockerfile": "Dockerfile"}),  # context defaults to "."
    ({"context": "./src", "dockerfile": "Dockerfile.prod"},
     {"context": "./src", "dockerfile": "Dockerfile.prod"}),
    ({"context": "./src", "additional_contexts": {"v": f"{P}/vendor", "r": f"{P}"}},
     {"context": "./src", "additional_contexts": {"v": "./vendor", "r": "."}}),
    ({"context": ".", "additional_contexts": [f"v={P}/vendor"]},
     {"context": ".", "additional_contexts": ["v=./vendor"]}),
])
def test_absolute_release_code_build_inputs_resolve_in_the_staged_release(tmp_path, build,
                                                                          want) -> None:
    """Production's own copy of release code is never what staging builds."""
    assert _web(tmp_path, build=build)["build"] == want


@pytest.mark.parametrize("build,want", [
    ({"context": ".", "dockerfile": "../shared/Dockerfile"},       # leaves the project
     {"context": ".", "dockerfile": f"{P.parent}/shared/Dockerfile"}),
    ({"context": "../lib", "dockerfile": "Dockerfile"},
     {"context": f"{P.parent}/lib", "dockerfile": "Dockerfile"}),
    ({"context": ".", "dockerfile": "/srv/Dockerfile"}, {"context": ".", "dockerfile": "/srv/Dockerfile"}),
    ({"context": "https://example.com/r.git", "dockerfile": "Dockerfile"},
     {"context": "https://example.com/r.git", "dockerfile": "Dockerfile"}),
])
def test_dockerfiles_outside_the_project_keep_their_production_meaning(tmp_path, build,
                                                                       want) -> None:
    assert _web(tmp_path, build=build)["build"] == want


@pytest.mark.parametrize("build", [
    {"context": ".", "dockerfile": "data/Dockerfile"},
    {"context": "./src", "dockerfile": "../uploads/Dockerfile"},
    {"context": ".", "dockerfile": f"{P}/data/Dockerfile"},
    {"context": "./data/x", "dockerfile": "../../src/Dockerfile"},
])
def test_box_state_dockerfiles_are_refused(tmp_path, build) -> None:
    with pytest.raises(ComposeError, match="Build from release code"):
        _web(tmp_path, build=build)


@pytest.mark.parametrize("build,named", [
    ({"context": f"{P}/.releases/previous/src"}, f"{P}/.releases/previous/src"),
    ({"context": "./.releases/previous"}, "./.releases/previous"),
    ({"context": ".", "additional_contexts": {"a": f"{P}/repo/lib"}}, f"{P}/repo/lib"),
    ({"context": ".", "dockerfile": f"{P}/.releases/staged/release/Dockerfile"},
     f"{P}/.releases/staged/release/Dockerfile"),
    # Release code, but no path relative to staging's context reaches it.
    ({"context": "../lib", "dockerfile": f"{P}/Dockerfile"}, f"{P}/Dockerfile"),
    ({"context": "https://example.com/r.git", "dockerfile": f"{P}/Dockerfile"}, f"{P}/Dockerfile"),
])
def test_unmappable_build_inputs_in_the_project_are_refused(tmp_path, build, named) -> None:
    with pytest.raises(ComposeError, match="relative to the release") as e:
        _web(tmp_path, build=build)
    assert named in str(e.value)



@pytest.mark.parametrize("build,want", [
    ({"context": "../myapp/src"}, {"context": "./src"}),           # leaves and re-enters
    ({"context": "../myapp"}, {"context": "."}),
    ({"context": "./src", "dockerfile": "../../myapp/docker/Dockerfile"},
     {"context": "./src", "dockerfile": "../docker/Dockerfile"}),
    ({"context": ".", "additional_contexts": {"v": "../myapp/vendor"}},
     {"context": ".", "additional_contexts": {"v": "./vendor"}}),
])
def test_paths_that_reenter_the_project_are_written_canonically(tmp_path, build, want) -> None:
    assert _web(tmp_path, build=build)["build"] == want


def test_a_path_reentering_the_project_into_box_state_is_refused(tmp_path) -> None:
    with pytest.raises(ComposeError, match="Build from release code"):
        _web(tmp_path, build={"context": "../myapp/data"})


@pytest.mark.parametrize("build", [
    {"context": "git@example.com:r.git", "dockerfile": "Dockerfile"},
    {"context": "ssh://git@example.com/r.git", "dockerfile": "Dockerfile"},
    {"context": ".", "additional_contexts": {"s": "service:base", "g": "git@example.com:r.git"}},
])
def test_remote_contexts_are_left_as_compose_build_reads_them(tmp_path, build) -> None:
    assert _web(tmp_path, build=build)["build"] == build


def test_an_in_project_dockerfile_with_an_ssh_context_is_refused(tmp_path) -> None:
    with pytest.raises(ComposeError, match="relative to the release"):
        _web(tmp_path, build={"context": "git@example.com:r.git", "dockerfile": f"{P}/Dockerfile"})


def test_relative_inputs_are_judged_on_the_literal_path(tmp_path) -> None:
    """Production's src -> data link does not make the release's src box state."""
    project = tmp_path / "myapp"
    (project / "data").mkdir(parents=True)
    (project / "src").symlink_to(project / "data")
    compose = tmp_path / "compose.yml"
    compose.write_text(yaml.safe_dump({"services": {"web": {"build": {
        "context": ".", "dockerfile": "src/Dockerfile"}}}}))
    base = yaml.safe_load(generate_staging_compose_base(compose, {"data"}, project))
    assert base["services"]["web"]["build"] == {"context": ".", "dockerfile": "src/Dockerfile"}


def test_project_relative_is_deterministic_and_literal_on_request(tmp_path) -> None:
    """Spelled forms win over resolved ones whatever the hash seed."""
    import subprocess
    import sys
    project = tmp_path / "myapp"
    (project / "data").mkdir(parents=True)
    (project / "link").symlink_to(project / "data")
    code = ("import sys; from pathlib import Path; from boxmunge.bind_mounts import "
            "project_relative as r; p = Path(sys.argv[1]); "
            "print(r(str(p / 'link/x'), p), r(str(p / 'link/x'), p, literal=True))")
    seen = {subprocess.run([sys.executable, "-c", code, str(project)], check=True, text=True,
                           capture_output=True, env={**os.environ, "PYTHONHASHSEED": str(seed)}
                           ).stdout.strip() for seed in range(6)}
    assert seen == {"link/x link/x"}
