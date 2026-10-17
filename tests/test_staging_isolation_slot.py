# SPDX-License-Identifier: Apache-2.0
"""Isolation against production as it runs and as it would after promote; I3; D8."""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from boxmunge.staging_isolation import (
    StagingIsolationError, check_isolation, separation_problems,
)

P = Path("/opt/boxmunge/projects/myapp")
RELEASE = P / ".releases" / "staged" / "release"


def _svc(*vols) -> dict:
    return {"services": {"web": {"image": "boxmunge.invalid/myapp-staging/web",
                                 "volumes": list(vols)}}}


def _bind(src: str, ro: bool = False) -> dict:
    return {"type": "bind", "source": src, "target": "/m", "read_only": ro}


def test_separation_allows_the_slot_read_only_and_staging_copies(paths) -> None:
    model = _svc(_bind(str(RELEASE / "appconfig"), ro=True), _bind(str(P / "uploads-staging")))
    assert separation_problems(model, P, RELEASE) == []


def test_separation_refuses_production_paths_and_a_writable_slot(paths) -> None:
    model = _svc(_bind(str(P / "uploads")), _bind(str(RELEASE / "cache")))
    problems = separation_problems(model, P, RELEASE)
    assert any("production's" in p for p in problems)
    assert any("read-write" in p for p in problems)


def test_overlap_with_production_after_promote_is_refused(paths) -> None:
    staging = _svc(_bind(str(P / "uploads-staging")))
    after = {"services": {"web": {"image": "boxmunge.invalid/myapp/web",
                                  "volumes": [_bind(str(P / "uploads-staging"))]}}}
    with pytest.raises(StagingIsolationError, match="production after promoting"):
        check_isolation(paths, "myapp", staging,
                        [("production after promoting this release", after)])


def test_disjoint_models_pass(paths) -> None:
    staging = _svc(_bind(str(P / "uploads-staging")))
    prod = {"services": {"web": {"image": "boxmunge.invalid/myapp/web",
                                 "volumes": [_bind(str(P / "uploads"))]}}}
    check_isolation(paths, "myapp", staging, [("production", prod)])


def test_install_isolation_without_a_slot_is_a_no_op(paths, tmp_path) -> None:
    from boxmunge.staging_isolation import check_install_isolation
    check_install_isolation(paths, "myapp", tmp_path, {"project": "myapp"})


# -- beyond the brief ------------------------------------------------------

def test_separation_reads_short_syntax_and_config_files(paths) -> None:
    model = {"services": {"web": {"volumes": [f"{RELEASE}/conf:/c:ro", f"{RELEASE}/x:/x"]}},
             "configs": {"c": {"file": str(P / "appconfig" / "c.conf")}}}
    problems = separation_problems(model, P, RELEASE)
    assert len(problems) == 2
    assert "service web mounts the staged release" in problems[0]
    assert f"config c mounts {P}/appconfig/c.conf, which is production's" in problems[1]


def test_a_whole_project_mount_is_refused_for_each_environment(paths) -> None:
    project_dir = paths.project_dir("myapp")
    whole = {"services": {"web": {"volumes": [_bind(str(project_dir), ro=True)]}}}
    with pytest.raises(StagingIsolationError) as e:
        check_isolation(paths, "myapp", whole, [("production", whole)])
    assert "staging web:/m mounts the whole project directory" in str(e.value)
    assert "production web:/m mounts the whole project directory" in str(e.value)


def test_production_model_needs_a_deployed_project(paths) -> None:
    from boxmunge.staging_isolation import production_model
    project_dir = paths.project_dir("myapp")
    project_dir.mkdir(parents=True)
    assert production_model(paths, "myapp") is None
    (project_dir / "manifest.yml").write_text("project: myapp\n")
    with pytest.raises(StagingIsolationError, match="Redeploy production first"):
        production_model(paths, "myapp")


def test_production_model_is_read_from_the_project_dir(paths) -> None:
    from boxmunge.staging_isolation import production_model
    project_dir = paths.project_dir("myapp")
    project_dir.mkdir(parents=True)
    (project_dir / "manifest.yml").write_text("project: myapp\n")
    (project_dir / "compose.yml").write_text(yaml.safe_dump(
        {"services": {"web": {"image": "nginx"}}}))
    paths.project_compose_override("myapp").write_text("services: {}\n")
    assert production_model(paths, "myapp")["services"] == {"web": {"image": "nginx"}}


def test_candidate_model_ignores_the_candidates_env_and_label_files(paths, tmp_path) -> None:
    """They are release code the project dir does not have before the install,
    which Compose 2.35 refuses to resolve even with --no-env-resolution."""
    from boxmunge.staging_isolation import candidate_model
    project_dir = paths.project_dir("myapp")
    project_dir.mkdir(parents=True)
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "compose.yml").write_text(yaml.safe_dump({"services": {"web": {
        "image": "nginx", "env_file": ["./app.env"], "label_file": "./labels",
        "volumes": ["./appconfig:/a:ro"]}}}))
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    model = candidate_model(paths, "myapp", tree, {"project": "myapp", "services": {}}, scratch)
    assert model["services"]["web"] == {"image": "nginx", "volumes": ["./appconfig:/a:ro"]}
    assert yaml.safe_load((tree / "compose.yml").read_text())["services"]["web"]["env_file"]


def test_an_install_sharing_with_the_slots_staging_is_refused(paths, tmp_path) -> None:
    from boxmunge.staged_release import new_meta, slot_dir, write_meta
    from boxmunge.staging_isolation import check_install_isolation
    project_dir = paths.project_dir("myapp")
    slot = slot_dir(paths, "myapp")
    (slot / "release").mkdir(parents=True)
    write_meta(slot, new_meta("bundle", "myapp-v2", None))
    (slot / "compose.staging-base.yml").write_text(yaml.safe_dump(
        {"services": {"web": {"image": "nginx",
                              "volumes": [f"{project_dir}/uploads-staging:/u"]}}}))
    (slot / "compose.boxmunge-staging.yml").write_text("services: {}\n")
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "compose.yml").write_text(yaml.safe_dump(
        {"services": {"web": {"image": "nginx", "volumes": ["./uploads-staging:/u"]}}}))
    with pytest.raises(StagingIsolationError, match="share these with production after this"):
        check_install_isolation(paths, "myapp", tree, {"project": "myapp", "services": {}})
    assert not list(paths.project_releases("myapp").glob(".isolation-*"))
