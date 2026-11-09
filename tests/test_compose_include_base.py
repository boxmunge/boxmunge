"""Files reached through `include:` resolve their relative paths the way
Compose does: against the include entry's project_directory, or else the
directory of the entry's FIRST path, not the included file's own directory.

Checked against `docker compose config` (Compose v2/v5):
  - include {path: sub/deep/inc.yml, project_directory: sub}: inc.yml's
    env_file, label_file, extends file and nested include paths resolve
    against sub/.
  - include {path: [a/x.yml, b/deep/y.yml]}: y.yml's paths resolve against a/.
  - an extends file's own paths resolve against the extended file's directory.
  - an include entry's path, env_file and project_directory resolve against
    the including file's base; the included project's .env is read from the
    entry's base.
tests/integration/test_compose_include_base.py runs the real command.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from boxmunge import compose_resolve, docker
from boxmunge.compose_guard import ComposeRefused, compose_up_checked
from boxmunge.compose_validate import ComposeSecurityError, validate_user_compose
from boxmunge.paths import BoxPaths

PROJDIR = {"include": [{"path": "sub/deep/inc.yml", "project_directory": "sub"}]}
MULTI = {"include": [{"path": ["a/x.yml", "b/deep/y.yml"]}]}


def _tree(root: Path, files: dict[str, object]) -> Path:
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content if isinstance(content, str) else yaml.safe_dump(content))
    return root / "compose.yml"


def _services(**svcs) -> dict:
    return {"services": svcs}


# Each escape plants a decoy inside the project where a file-relative walk
# would look, so only the base Compose really uses shows the escape.
ESCAPES = {
    "project_directory env_file": (PROJDIR, "sub/deep/inc.yml", _services(
        leak={"image": "x", "env_file": "../../victim/secrets.env"})),
    "project_directory env_file long syntax": (PROJDIR, "sub/deep/inc.yml", _services(
        leak={"image": "x", "env_file": [{"path": "../../victim/secrets.env"}]})),
    "project_directory label_file": (PROJDIR, "sub/deep/inc.yml", _services(
        leak={"image": "x", "label_file": "../../victim/secrets.env"})),
    "project_directory extends": (PROJDIR, "sub/deep/inc.yml", _services(
        leak={"extends": {"file": "../../victim/ext.yml", "service": "base"}})),
    "project_directory nested include": (PROJDIR, "sub/deep/inc.yml", {
        "include": ["../../victim/ext.yml"]}),
    "multi-path env_file": (MULTI, "b/deep/y.yml", _services(
        leak={"image": "x", "env_file": "../../victim/secrets.env"})),
    "multi-path extends": (MULTI, "b/deep/y.yml", _services(
        leak={"extends": {"file": "../../victim/ext.yml", "service": "base"}})),
}


def _escape_project(project_dir: Path, top: dict, inc: str, inc_doc: dict) -> Path:
    return _tree(project_dir, {
        "compose.yml": {**top, "services": {"web": {"image": "nginx"}}},
        inc: inc_doc,
        "a/x.yml": _services(xa={"image": "x"}),
        "victim/secrets.env": "X=decoy\n",
        "victim/ext.yml": _services(base={"image": "x"}),
    })


@pytest.mark.parametrize("top,inc,inc_doc", ESCAPES.values(), ids=ESCAPES.keys())
def test_walk_resolves_included_paths_against_the_entry_base(
    tmp_path: Path, top: dict, inc: str, inc_doc: dict,
) -> None:
    project_dir = tmp_path / "projects" / "evil"
    compose = _escape_project(project_dir, top, inc, inc_doc)
    problems, _ = compose_resolve.walk_references(compose, (project_dir,))
    assert problems and "outside the project directory" in problems[0]
    assert str(tmp_path / "projects" / "victim") in problems[0]


@pytest.mark.parametrize("top,inc,inc_doc", ESCAPES.values(), ids=ESCAPES.keys())
def test_validation_refuses_the_escape_and_names_the_fix(
    paths: BoxPaths, top: dict, inc: str, inc_doc: dict,
) -> None:
    compose = _escape_project(paths.project_dir("myapp"), top, inc, inc_doc)
    with pytest.raises(ComposeSecurityError, match=r"outside the project.*prod-deploy myapp"):
        validate_user_compose(compose, paths, project_name="myapp")


def test_walk_reads_the_files_compose_reads_through_project_directory(tmp_path: Path) -> None:
    compose = _tree(tmp_path, {
        "compose.yml": {**PROJDIR, "services": {}},
        "sub/deep/inc.yml": {"include": ["n/nest.yml"], **_services(
            a={"image": "x", "env_file": "x.env", "label_file": "l.txt"},
            b={"extends": {"file": "e/ext.yml", "service": "base"}})},
        "sub/n/nest.yml": _services(nest={"image": "x", "env_file": "x.env"}),
        "sub/e/ext.yml": _services(base={"image": "x", "env_file": "x.env"}),
    })
    _, files = compose_resolve.walk_references(compose, (tmp_path,))
    for rel in ("sub/deep/inc.yml", "sub/x.env", "sub/l.txt", "sub/.env",
                "sub/n/nest.yml", "sub/n/x.env", "sub/e/ext.yml", "sub/e/x.env"):
        assert tmp_path / rel in files, rel
    for rel in ("sub/deep/x.env", "sub/deep/n/nest.yml", "sub/deep/e/ext.yml"):
        assert tmp_path / rel not in files, rel


def test_walk_reads_the_files_compose_reads_through_a_path_list(tmp_path: Path) -> None:
    compose = _tree(tmp_path, {
        "compose.yml": {**MULTI, "services": {}},
        "a/x.yml": _services(xa={"image": "x"}),
        "b/deep/y.yml": _services(yb={"image": "x", "env_file": "y.env"}),
    })
    _, files = compose_resolve.walk_references(compose, (tmp_path,))
    assert {tmp_path / "a/x.yml", tmp_path / "b/deep/y.yml",
            tmp_path / "a/y.env", tmp_path / "a/.env"} <= set(files)
    assert tmp_path / "b/deep/y.env" not in files


def test_nested_include_entry_resolves_against_the_including_base(tmp_path: Path) -> None:
    """An include entry's path, env_file and project_directory inside an
    included file resolve against that file's base, not its directory."""
    compose = _tree(tmp_path, {
        "compose.yml": {"include": [{"path": "p/deep/inc.yml", "project_directory": "p",
                                     "env_file": "top.env"}], "services": {}},
        "p/deep/inc.yml": {"include": [{"path": "q/deep2/inc2.yml", "project_directory": "q",
                                        "env_file": "v.env"}], "services": {}},
        "p/q/deep2/inc2.yml": _services(g2={"image": "x", "env_file": "x.env"}),
    })
    _, files = compose_resolve.walk_references(compose, (tmp_path,))
    for rel in ("top.env", "p/v.env", "p/q/deep2/inc2.yml", "p/q/x.env", "p/q/.env"):
        assert tmp_path / rel in files, rel


def test_same_file_included_with_two_bases_is_walked_for_each(tmp_path: Path) -> None:
    """../x.env is inside from shared/, outside from the project root."""
    compose = _tree(tmp_path, {
        "compose.yml": {"include": [
            {"path": "shared/inc.yml"},
            {"path": "shared/inc.yml", "project_directory": "."},
        ], "services": {}},
        "shared/inc.yml": _services(s={"image": "x", "env_file": "../x.env"}),
    })
    problems, _ = compose_resolve.walk_references(compose, (tmp_path,))
    assert len(problems) == 1 and "outside the project directory" in problems[0]


# ---------------------------------------------------------------------------
# The service-name census follows includes from the same base
# ---------------------------------------------------------------------------

def _resolved_as(monkeypatch, services: dict) -> None:
    model = {"name": "myapp", "services": services}
    monkeypatch.setattr(docker, "compose_config", lambda *a, **kw: json.dumps(model))


def _nested_census_project(paths: BoxPaths) -> Path:
    return _tree(paths.project_dir("myapp"), {
        "compose.yml": {**PROJDIR, "services": {"web": {"image": "nginx"}}},
        "sub/deep/inc.yml": {"include": ["n/nest.yml"]},
        "sub/n/nest.yml": _services(nest={"image": "x"}),
        "sub/deep/n/nest.yml": _services(decoy={"image": "x"}),
    })


def test_service_census_reads_nested_includes_from_the_entry_base(
    paths: BoxPaths, monkeypatch,
) -> None:
    compose = _nested_census_project(paths)
    _resolved_as(monkeypatch, {"web": {"image": "nginx"}, "nest": {"image": "x"}})
    compose_resolve.resolve_compose_config(compose, "myapp")


def test_service_census_still_fails_closed_through_nested_includes(
    paths: BoxPaths, monkeypatch,
) -> None:
    compose = _nested_census_project(paths)
    _resolved_as(monkeypatch, {"web": {"image": "nginx"}})
    with pytest.raises(compose_resolve.ComposeResolveError, match="left out service.s. nest"):
        compose_resolve.resolve_compose_config(compose, "myapp")


# ---------------------------------------------------------------------------
# Belt and braces: the resolved model's env files must lie inside the project
# ---------------------------------------------------------------------------

def test_model_env_file_outside_the_project_is_refused(paths: BoxPaths, monkeypatch) -> None:
    """Whatever the literal walk concluded, the model Compose will run is
    checked too: an env_file it reads from elsewhere is refused."""
    compose = _tree(paths.project_dir("myapp"), {"compose.yml": _services(web={"image": "x"})})
    outside = paths.project_dir("victim") / "secrets.env"
    _resolved_as(monkeypatch, {"web": {"image": "x", "env_file": [{"path": str(outside)}]}})
    with pytest.raises(ComposeSecurityError, match=r"env_file .*victim/secrets.env.*outside"):
        validate_user_compose(compose, paths, project_name="myapp")


def test_model_env_file_inside_the_project_is_accepted(paths: BoxPaths, monkeypatch) -> None:
    project_dir = paths.project_dir("myapp")
    compose = _tree(project_dir, {"compose.yml": _services(web={"image": "x"})})
    _resolved_as(monkeypatch, {"web": {"image": "x", "env_file": [
        {"path": str(project_dir / "sub" / "x.env"), "required": False}]}})
    validate_user_compose(compose, paths, project_name="myapp")


def test_model_env_files_are_listed_absolute(tmp_path: Path) -> None:
    model = {"services": {"web": {"env_file": [{"path": "/abs/a.env"}, "rel.env"]},
                          "db": {"image": "x"}}}
    assert compose_resolve.model_env_files(model, tmp_path) == [
        Path("/abs/a.env"), tmp_path / "rel.env"]


@pytest.fixture
def shop(paths: BoxPaths, monkeypatch) -> Path:
    """A deployable project whose starts run no Docker."""
    for d in (paths.config, paths.deploy_state, paths.logs):
        d.mkdir(parents=True, exist_ok=True)
    project_dir = paths.project_dir("shop")
    _tree(project_dir, {
        "manifest.yml": {"schema_version": 2, "id": "01HZZZZZZZZZZZZZZZZZZZZZZZ",
                         "project": "shop", "source": "bundle", "hosts": ["shop.example.com"],
                         "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}}},
        "compose.yml": _services(web={"image": "nginx:1.27"}),
    })
    monkeypatch.setattr("boxmunge.compose_guard.compose_up", lambda *a, **kw: None)
    monkeypatch.setattr("boxmunge.notify.send_notification", lambda *a, **kw: True)
    return project_dir


def _start(paths: BoxPaths, *, record: bool = False) -> None:
    compose_up_checked(paths, "shop", component="deploy" if record else "upgrade",
                       compose_files=["compose.yml"], record=record)


def test_start_record_hashes_the_env_files_the_model_reads(
    paths: BoxPaths, shop: Path, monkeypatch,
) -> None:
    """The control record covers the files the resolved model reads, not
    only those the literal walk found: rewriting one after deploy refuses
    the next start."""
    _tree(shop, {"hidden/x.env": "A=1\n"})
    model = {"services": {"web": {"image": "nginx:1.27",
                                  "env_file": [{"path": str(shop / "hidden/x.env")}]}}}
    monkeypatch.setattr(compose_resolve, "resolve_deployed_config", lambda *a, **kw: model)
    _start(paths, record=True)
    record = json.loads(paths.project_bind_record("shop").read_text())
    assert "hidden/x.env" in record["control"]
    (shop / "hidden/x.env").write_text("A=2\n")
    with pytest.raises(ComposeRefused, match="hidden/x.env changed"):
        _start(paths)


def test_deployed_project_with_an_include_escape_is_refused_with_the_fix(
    paths: BoxPaths, shop: Path,
) -> None:
    """A project deployed before this fix with an escaping include is
    refused at its next start (upgrade, container update, recover), and the
    refusal names the way out."""
    _start(paths, record=True)
    _escape_project(shop, *ESCAPES["project_directory env_file"])
    with pytest.raises(ComposeRefused, match=r"inside the project\. Then deploy "
                       r"the fixed release: prod-deploy shop\. Nothing was started"):
        _start(paths)
