"""`include:` is confined to a subset whose path resolution is checked
against Compose (boxmunge.compose_references): an entry is a path or a list
of paths naming existing files inside the project, nested at most two
levels. An included file's relative paths resolve against the directory of
its entry's FIRST path, as Compose resolves them. project_directory and
env_file on an entry, deeper nesting, missing targets and remotes are
refused. tests/integration/test_compose_include_base.py runs real Compose.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml

from boxmunge import bind_sources, compose_references, compose_resolve, docker
from boxmunge.bind_sources import BindSourceError
from boxmunge.compose_guard import ComposeRefused, compose_up_checked
from boxmunge.compose_validate import ComposeSecurityError, validate_user_compose
from boxmunge.paths import BoxPaths

MULTI = {"include": [{"path": ["a/x.yml", "b/deep/y.yml"]}]}


def _tree(root: Path, files: dict[str, object]) -> Path:
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content if isinstance(content, str) else yaml.safe_dump(content))
    return root / "compose.yml"


def _services(**svcs) -> dict:
    return {"services": svcs}


def _top(include: list) -> dict:
    return {"include": include, "services": {"web": {"image": "nginx"}}}


# Shapes refused whatever they point at. The first five are the residual
# cases of the second review (each made real Compose read another
# project's file while the first fix accepted it); `victim/` inside the
# project is the decoy a file-relative reading would find.
REFUSED = {
    "project_directory that does not exist": ({
        "compose.yml": _top([{"path": "sub/inc.yml", "project_directory": "nonexist"}]),
        "sub/inc.yml": _services(leak={"image": "x", "label_file": "../victim/secrets.env"}),
        "victim/secrets.env": "X=decoy\n",
    }, "sets project_directory"),
    "include env_file three levels deep": ({
        "compose.yml": _top(["p/inc.yml"]),
        "p/inc.yml": {"include": ["q/inc2.yml"]},
        "p/q/inc2.yml": {"include": [{"path": "i3.yml", "env_file": "../../victim/secrets.env"}]},
        "p/q/i3.yml": _services(leak={"image": "x"}),
        "p/victim/secrets.env": "X=decoy\n",
    }, "sets env_file|deeper than 2"),
    "project_directory chain to another project's .env": ({
        "compose.yml": _top([{"path": "p/deep/inc.yml", "project_directory": "p"}]),
        "p/deep/inc.yml": {"include": [{"path": "q/deep2/inc2.yml", "project_directory": "q"}]},
        "p/q/deep2/inc2.yml": {"include": [{"path": "../../victim/i3.yml",
                                            "project_directory": "../../victim"}]},
        "victim/i3.yml": _services(leak={"image": "x"}),
    }, "sets project_directory"),
    "project_directory chain shifting a depth-4 path": ({
        "compose.yml": _top([{"path": "p/deep/inc.yml", "project_directory": "p"}]),
        "p/deep/inc.yml": {"include": [{"path": "q/deep2/inc2.yml", "project_directory": "q"}]},
        "p/q/deep2/inc2.yml": {"include": [{"path": "r/i3.yml", "project_directory": "r"}]},
        "p/q/r/i3.yml": {"include": ["../../../victim/inc.yml"]},
        "victim/inc.yml": _services(foreign={"image": "x"}),
    }, "sets project_directory"),
    "scp-style git remote include": ({
        "compose.yml": _top(["bob@192.0.2.1:repo.git"]),
    }, "is remote"),
    "scp-style git remote extends": ({
        "compose.yml": _services(web={"extends": {"file": "bob@192.0.2.1:repo.git",
                                                  "service": "a"}}),
    }, "is remote"),
    "hosted git path include": ({"compose.yml": _top(["github.com/acme/stack"])}, "is remote"),
    "oci include": ({"compose.yml": _top(["oci://registry.example.com/x:1"])}, "is remote"),
    "project_directory inside the project": ({
        "compose.yml": _top([{"path": "sub/inc.yml", "project_directory": "sub"}]),
        "sub/inc.yml": _services(s={"image": "x"}),
    }, "sets project_directory"),
    "include env_file inside the project": ({
        "compose.yml": _top([{"path": "inc.yml", "env_file": "inc.env"}]),
        "inc.yml": _services(s={"image": "x"}), "inc.env": "A=1\n",
    }, "sets env_file"),
    "three levels of includes": ({
        "compose.yml": _top(["p/inc.yml"]),
        "p/inc.yml": {"include": ["q/inc2.yml"]},
        "p/q/inc2.yml": {"include": ["i3.yml"]},
        "p/q/i3.yml": _services(s={"image": "x"}),
    }, "deeper than 2"),
    "missing include file": ({"compose.yml": _top(["parts/gone.yml"])}, "is not a file"),
    "include of a directory": ({"compose.yml": _top(["parts"]), "parts/x": ""}, "is not a file"),
    "missing extends file": ({
        "compose.yml": _services(web={"extends": {"file": "gone.yml", "service": "a"}}),
    }, "is not a file"),
    "include entry without a path": ({"compose.yml": _top([{"path": []}])}, "names no path"),
    "path list env_file escape": ({
        "compose.yml": {**MULTI, "services": {}},
        "a/x.yml": _services(xa={"image": "x"}),
        "b/deep/y.yml": _services(leak={"image": "x", "env_file": "../../victim/secrets.env"}),
        "b/victim/secrets.env": "X=decoy\n",
    }, "outside the project"),
    "path list label_file escape": ({
        "compose.yml": {**MULTI, "services": {}},
        "a/x.yml": _services(xa={"image": "x"}),
        "b/deep/y.yml": _services(leak={"image": "x", "label_file": "../../victim/secrets.env"}),
        "b/victim/secrets.env": "X=decoy\n",
    }, "outside the project"),
    "path list extends escape": ({
        "compose.yml": {**MULTI, "services": {}},
        "a/x.yml": _services(xa={"image": "x"}),
        "b/deep/y.yml": _services(leak={"extends": {"file": "../../victim/ext.yml",
                                                    "service": "b"}}),
        "b/victim/ext.yml": _services(b={"image": "x"}),
    }, "outside the project"),
}


@pytest.mark.parametrize("files,match", REFUSED.values(), ids=REFUSED.keys())
def test_walk_refuses_shapes_outside_the_include_subset(
    tmp_path: Path, files: dict, match: str,
) -> None:
    project_dir = tmp_path / "projects" / "evil"
    problems, _ = compose_references.walk_references(_tree(project_dir, files), (project_dir,))
    assert problems, "accepted"
    assert any(re.search(match, p) for p in problems), problems


@pytest.mark.parametrize("files,match", REFUSED.values(), ids=REFUSED.keys())
def test_validation_refuses_them_and_names_the_fix(
    paths: BoxPaths, files: dict, match: str,
) -> None:
    compose = _tree(paths.project_dir("myapp"), files)
    with pytest.raises(ComposeSecurityError, match=r"prod-deploy myapp\.$"):
        validate_user_compose(compose, paths, project_name="myapp")


def test_refusing_an_entry_names_the_allowed_forms(tmp_path: Path) -> None:
    compose = _tree(tmp_path, {
        "compose.yml": _top([{"path": "inc.yml", "project_directory": "."}]),
        "inc.yml": _services(s={"image": "x"}),
    })
    problems, _ = compose_references.walk_references(compose, (tmp_path,))
    assert compose_references.ALLOWED_INCLUDES in problems[0]


# ---------------------------------------------------------------------------
# What the allowed subset reads, where Compose reads it
# ---------------------------------------------------------------------------

def test_path_list_files_resolve_from_the_first_path(tmp_path: Path) -> None:
    compose = _tree(tmp_path, {
        "compose.yml": {**MULTI, "services": {}},
        "a/x.yml": _services(xa={"image": "x"}),
        "b/deep/y.yml": _services(yb={"image": "x", "env_file": "y.env", "label_file": "l.txt"}),
    })
    problems, files = compose_references.walk_references(compose, (tmp_path,))
    assert problems == []
    assert {tmp_path / "a/x.yml", tmp_path / "b/deep/y.yml", tmp_path / "a/y.env",
            tmp_path / "a/l.txt", tmp_path / "a/.env"} <= set(files)
    assert tmp_path / "b/deep/y.env" not in files


def test_two_levels_of_includes_are_allowed_and_followed(tmp_path: Path) -> None:
    compose = _tree(tmp_path, {
        "compose.yml": {"include": [{"path": ["a/x.yml", "b/inc.yml"]}], "services": {}},
        "a/x.yml": _services(xa={"image": "x"}),
        "b/inc.yml": {"include": ["n/nest.yml"]},
        "a/n/nest.yml": _services(nest={"image": "x", "env_file": "n.env",
                                        "extends": {"file": "e/ext.yml", "service": "b"}}),
        "a/n/e/ext.yml": _services(b={"image": "x", "env_file": "e.env"}),
    })
    problems, files = compose_references.walk_references(compose, (tmp_path,))
    assert problems == []
    for rel in ("a/n/nest.yml", "a/n/n.env", "a/n/.env", "a/n/e/ext.yml", "a/n/e/e.env"):
        assert tmp_path / rel in files, rel


def test_same_file_included_with_two_bases_is_walked_for_each(tmp_path: Path) -> None:
    """../../x.env is inside from deep/a/, outside from shared/."""
    compose = _tree(tmp_path, {
        "compose.yml": _top([{"path": ["deep/a/x.yml", "shared/inc.yml"]}, "shared/inc.yml"]),
        "deep/a/x.yml": _services(xa={"image": "x"}),
        "shared/inc.yml": _services(s={"image": "x", "env_file": "../../x.env"}),
    })
    problems, _ = compose_references.walk_references(compose, (tmp_path,))
    assert len(problems) == 1 and "outside the project directory" in problems[0]


# ---------------------------------------------------------------------------
# The service-name census follows includes from the same base
# ---------------------------------------------------------------------------

def _resolved_as(monkeypatch, services: dict) -> None:
    model = {"name": "myapp", "services": services}
    monkeypatch.setattr(docker, "compose_config", lambda *a, **kw: json.dumps(model))


def _census_project(paths: BoxPaths) -> Path:
    return _tree(paths.project_dir("myapp"), {
        "compose.yml": {"include": [{"path": ["a/x.yml", "b/inc.yml"]}],
                        "services": {"web": {"image": "nginx"}}},
        "a/x.yml": {"services": {}},
        "b/inc.yml": {"include": ["n/nest.yml"]},
        "a/n/nest.yml": _services(nest={"image": "x"}),
        "b/n/nest.yml": _services(decoy={"image": "x"}),
    })


def test_service_census_reads_nested_includes_from_the_entry_base(
    paths: BoxPaths, monkeypatch,
) -> None:
    compose = _census_project(paths)
    _resolved_as(monkeypatch, {"web": {"image": "nginx"}, "nest": {"image": "x"}})
    compose_resolve.resolve_compose_config(compose, "myapp")


def test_service_census_still_fails_closed_through_nested_includes(
    paths: BoxPaths, monkeypatch,
) -> None:
    compose = _census_project(paths)
    _resolved_as(monkeypatch, {"web": {"image": "nginx"}})
    with pytest.raises(compose_resolve.ComposeResolveError, match="left out service.s. nest"):
        compose_resolve.resolve_compose_config(compose, "myapp")


# ---------------------------------------------------------------------------
# Belt and braces: the resolved model's env files
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


def test_model_env_file_is_protected_from_read_write_mounts(paths: BoxPaths, monkeypatch) -> None:
    """An env file only the model names is still a file boxmunge reads, so
    a read-write mount of its directory is refused."""
    project_dir = paths.project_dir("myapp")
    compose = _tree(project_dir, {"compose.yml": _services(web={"image": "x"})})
    _resolved_as(monkeypatch, {"web": {
        "image": "x", "env_file": [{"path": str(project_dir / "hidden" / "x.env")}],
        "volumes": [{"type": "bind", "source": str(project_dir / "hidden"), "target": "/h"}]}})
    with pytest.raises(ComposeSecurityError, match="read-write.*hidden/x.env"):
        validate_user_compose(compose, paths, project_name="myapp")


def test_model_env_files_are_listed_absolute(tmp_path: Path) -> None:
    model = {"services": {"web": {"env_file": [{"path": "/abs/a.env"}, "rel.env"]},
                          "db": {"image": "x"}}}
    assert compose_resolve.model_env_files(model, tmp_path) == [
        Path("/abs/a.env"), tmp_path / "rel.env"]


# ---------------------------------------------------------------------------
# Start checks: the record covers the model's env files; refusals say what to run
# ---------------------------------------------------------------------------

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
    _tree(shop, {"hidden/x.env": "A=1\n"})
    model = {"services": {"web": {"image": "nginx:1.27",
                                  "env_file": [{"path": str(shop / "hidden/x.env")}]}}}
    monkeypatch.setattr(compose_resolve, "resolve_deployed_config", lambda *a, **kw: model)
    _start(paths, record=True)
    record = json.loads(paths.project_bind_record("shop").read_text())
    assert "hidden/x.env" in record["control"]
    (shop / "hidden/x.env").write_text("A=2\n")
    with pytest.raises(ComposeRefused, match="hidden/x.env changed.*prod-deploy shop --redeploy to run it"):
        _start(paths)


def test_a_file_the_old_record_lacks_is_reported_as_newly_tracked(
    paths: BoxPaths, shop: Path,
) -> None:
    """A project recorded by an older boxmunge, which did not read the file."""
    _start(paths, record=True)
    _tree(shop, {"compose.yml": {"include": ["parts/db.yml"],
                                 "services": {"web": {"image": "nginx:1.27"}}},
                 "parts/db.yml": _services(db={"image": "postgres:16"})})
    record_path = paths.project_bind_record("shop")
    rec = json.loads(record_path.read_text())
    rec["control"]["compose.yml"] = bind_sources.control_hashes(
        shop, [shop / "compose.yml"])["compose.yml"]
    record_path.write_text(json.dumps(rec))
    with pytest.raises(ComposeRefused, match=r"parts/db.yml is newly tracked.*"
                       r"prod-deploy shop --redeploy to record it"):
        _start(paths)


def test_staging_newly_tracked_advice_is_to_stage_again(tmp_path: Path) -> None:
    (tmp_path / "x.env").write_text("A=1\n")
    with pytest.raises(BindSourceError, match="newly tracked.*stage shop again to record it"):
        bind_sources.check_control(tmp_path, [tmp_path / "x.env"], {},
                                   redo="stage shop again")


def test_deployed_project_with_a_refused_include_is_refused_with_the_fix(
    paths: BoxPaths, shop: Path,
) -> None:
    """A project deployed before this fix with a project_directory include
    is refused at its next start (upgrade, container update, recover), and
    the refusal names the way out."""
    _start(paths, record=True)
    _tree(shop, {"compose.yml": _top([{"path": "sub/inc.yml", "project_directory": "sub"}]),
                 "sub/inc.yml": _services(s={"image": "x"})})
    with pytest.raises(ComposeRefused, match=r"sets project_directory\. .*Then upload "
                       r"the fixed release and deploy it: prod-deploy shop\. Nothing was started"):
        _start(paths)
