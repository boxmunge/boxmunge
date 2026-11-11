# SPDX-License-Identifier: Apache-2.0
"""The one walk of a compose model's host paths, and the path helpers
around it (compose_mounts): every module that asks which paths a model
mounts, read-write or not, and where they lie, shares these answers."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from boxmunge import bind_sources
from boxmunge.bind_sources import BindSourceError
from boxmunge.compose_mounts import (
    BindEntry, bind_entries, file_entries, path_within, project_rel, read_only,
    service_bind_entries,
)


def _one(entry, base: Path = Path("/srv/app")) -> list[BindEntry]:
    return list(service_bind_entries("web", {"volumes": [entry]}, base))


# --- read_only -------------------------------------------------------------

@pytest.mark.parametrize("entry, expected", [
    ("./data:/data", False),
    ("./data:/data:ro", True),
    ("./data:/data:rw", False),
    ("./data:/data:z,ro", True),
    ("./data:/data:ro,z", True),
    ("./data:/data:rox", False),            # an option merely starting with "ro"
    ("/data", False),                       # anonymous volume
    ({"type": "bind", "source": "./d", "target": "/d", "read_only": True}, True),
    ({"type": "bind", "source": "./d", "target": "/d", "read_only": False}, False),
    ({"type": "bind", "source": "./d", "target": "/d"}, False),            # key missing
    ({"type": "bind", "source": "./d", "target": "/d", "read_only": "true"}, False),
    ({"type": "bind", "source": "./d", "target": "/d", "read_only": 1}, False),
])
def test_read_only_reads_both_syntaxes_and_defaults_to_read_write(entry, expected) -> None:
    assert read_only(entry) is expected


# --- service_bind_entries ----------------------------------------------------

def test_a_short_bind_is_joined_to_the_base_and_normalised() -> None:
    assert _one("./data/../data/db:/var/db") == [
        BindEntry("services", "web", "./data/../data/db", "/srv/app/data/db", True, "/var/db")]


def test_a_long_bind_reads_source_target_and_read_only() -> None:
    entry = {"type": "bind", "source": "/srv/app/conf", "target": "/etc/app", "read_only": True}
    assert _one(entry) == [
        BindEntry("services", "web", "/srv/app/conf", "/srv/app/conf", False, "/etc/app")]


@pytest.mark.parametrize("entry", [
    "dbdata:/var/lib/db",                                   # named volume
    "/var/lib/db",                                          # anonymous volume
    "$DATA:/data",                                          # a name, to Compose
    "${DATA}/x:/data",
    {"type": "volume", "source": "dbdata", "target": "/d"},
    {"type": "tmpfs", "target": "/tmp"},
    {"type": "image", "source": "busybox", "target": "/i"},
    {"type": "bind", "target": "/d"},                       # no source
    {"type": "bind", "source": None, "target": "/d"},
    {"source": "./d", "target": "/d"},                      # type missing: a volume
    42,
])
def test_what_is_not_a_host_path_is_left_out(entry) -> None:
    assert _one(entry) == []


def test_a_long_bind_with_a_variable_is_passed_through_as_written() -> None:
    """Validation refuses it (check_volumes); the walk itself judges nothing."""
    [bind] = _one({"type": "bind", "source": "${DATA}", "target": "/d"})
    assert (bind.source, bind.path) == ("${DATA}", "/srv/app/${DATA}")


def test_a_home_relative_source_is_expanded(monkeypatch) -> None:
    monkeypatch.setenv("HOME", "/home/deploy")
    [bind] = _one("~/data:/data")
    assert (bind.source, bind.path) == ("~/data", "/home/deploy/data")


def test_the_path_is_not_resolved_through_symlinks(tmp_path: Path) -> None:
    (tmp_path / "real").mkdir()
    (tmp_path / "link").symlink_to(tmp_path / "real")
    [bind] = _one("./link/x:/x", tmp_path)
    assert bind.path == str(tmp_path / "link/x")


def test_repeated_leading_slashes_are_collapsed() -> None:
    [bind] = _one("//srv//app/data:/data")
    assert bind.path == "/srv/app/data"


@pytest.mark.parametrize("svc", [None, "web", [], {"volumes": None}, {"volumes": {}},
                                 {"volumes": "./data:/data"}, {}])
def test_a_service_without_a_volumes_list_mounts_nothing(svc) -> None:
    assert list(service_bind_entries("web", svc, Path("/srv/app"))) == []


# --- file_entries and bind_entries -------------------------------------------

MODEL = {
    "services": {
        "web": {"volumes": ["./data:/data", "cache:/cache", "./conf:/etc/app:ro"]},
        "db": {"volumes": [{"type": "bind", "source": "/srv/app/db", "target": "/var/db"}]},
        "broken": "not a mapping",
    },
    "secrets": {"key": {"file": "./secrets/key"}, "env": {"environment": "KEY"}},
    "configs": {"site": {"file": "/srv/app/site.conf"}, "inline": {"content": "x"}, "odd": "x"},
}


def test_secret_and_config_files_are_read_only_mounts() -> None:
    assert list(file_entries(MODEL, Path("/srv/app"))) == [
        BindEntry("secrets", "key", "./secrets/key", "/srv/app/secrets/key", False, None),
        BindEntry("configs", "site", "/srv/app/site.conf", "/srv/app/site.conf", False, None),
    ]


def test_bind_entries_walks_services_in_order_then_secrets_then_configs() -> None:
    found = [(b.section, b.name, b.path, b.read_write)
             for b in bind_entries(MODEL, Path("/srv/app"))]
    assert found == [
        ("services", "web", "/srv/app/data", True),
        ("services", "web", "/srv/app/conf", False),
        ("services", "db", "/srv/app/db", True),
        ("secrets", "key", "/srv/app/secrets/key", False),
        ("configs", "site", "/srv/app/site.conf", False),
    ]


@pytest.mark.parametrize("model", [{}, {"services": None}, {"services": []},
                                   {"secrets": [], "configs": "x"}])
def test_a_model_without_those_sections_mounts_nothing(model) -> None:
    assert list(bind_entries(model, Path("/srv/app"))) == []


# --- path_within -----------------------------------------------------------

@pytest.mark.parametrize("path, root, expected", [
    ("/srv/app/data", "/srv/app/data", True),      # equal counts as inside
    ("/srv/app/data/db", "/srv/app/data", True),
    ("/srv/app/data", "/srv/app/data/db", False),  # not symmetric
    ("/srv/app/database", "/srv/app/data", False),  # a name that merely starts alike
    ("/srv/app", "/", True),                       # / holds every absolute path
    ("/", "/", True),
    ("/", "/srv", False),
    ("data/db", "data", True),                     # relative forms, same directory
    ("data", "data", True),
    ("database", "data", False),
    ("data", ".", False),                          # "." is the caller's to interpret
])
def test_path_within(path: str, root: str, expected: bool) -> None:
    assert path_within(path, root) is expected


def test_path_within_compares_text_and_resolves_nothing(tmp_path: Path) -> None:
    (tmp_path / "real").mkdir()
    (tmp_path / "link").symlink_to(tmp_path / "real")
    assert not path_within(str(tmp_path / "link/x"), str(tmp_path / "real"))


# --- project_rel -------------------------------------------------------------

def test_project_rel_of_relative_and_absolute_sources(tmp_path: Path) -> None:
    project = tmp_path / "app"
    project.mkdir()
    assert project_rel("./data/db", project) == "data/db"
    assert project_rel("data/../conf", project) == "conf"
    assert project_rel(str(project / "data"), project) == "data"
    assert project_rel(".", project) == "."
    assert project_rel(str(project), project) == "."
    assert project_rel("../other", project) is None
    assert project_rel(str(tmp_path / "application"), project) is None
    assert project_rel("~/data", project) is None


def test_project_rel_sees_a_project_dir_reached_through_a_symlink(tmp_path: Path) -> None:
    real = tmp_path / "real"
    (real / "data").mkdir(parents=True)
    (tmp_path / "opt").symlink_to(real)
    assert project_rel(str(real / "data"), tmp_path / "opt") == "data"
    assert project_rel(str(tmp_path / "opt/data"), real) == "data"
    assert project_rel(str(real / "data"), tmp_path / "opt", literal=True) == "data"


def test_literal_does_not_follow_the_sources_own_links(tmp_path: Path) -> None:
    project, outside = tmp_path / "app", tmp_path / "outside"
    (project / "data").mkdir(parents=True)
    outside.mkdir()
    (outside / "in").symlink_to(project / "data")
    (project / "out").symlink_to(outside)
    # A path outside that links in: found only when its links are followed.
    assert project_rel(str(outside / "in"), project) == "data"
    assert project_rel(str(outside / "in"), project, literal=True) is None
    # A path inside that links out stays where it is spelled, either way.
    assert project_rel(str(project / "out/x"), project) == "out/x"
    assert project_rel(str(project / "out/x"), project, literal=True) == "out/x"


# --- bind_sources: the same answers, refusing a path outside ------------------

def test_bind_sources_project_rel_refuses_a_path_outside(tmp_path: Path) -> None:
    project = tmp_path / "app"
    (project / "data").mkdir(parents=True)
    (tmp_path / "outside").mkdir()
    (tmp_path / "outside/in").symlink_to(project / "data")
    assert bind_sources.project_rel(str(project / "data/../data/db"), project) == "data/db"
    assert bind_sources.project_rel(str(project), project) == "."
    for outside in (str(tmp_path / "application"), str(tmp_path / "outside/in"), "/"):
        with pytest.raises(BindSourceError, match="outside the project directory"):
            bind_sources.project_rel(outside, project)


@pytest.mark.parametrize("source", ["data", "./data", "~/data"])
def test_bind_sources_project_rel_refuses_a_relative_source(
        tmp_path: Path, monkeypatch, source: str) -> None:
    """Its callers hold absolute paths; a relative one is not read from the
    working directory, even when that is the project dir."""
    (tmp_path / "data").mkdir()
    monkeypatch.chdir(tmp_path)
    with pytest.raises(BindSourceError, match="outside the project directory"):
        bind_sources.project_rel(source, tmp_path)


def test_model_sources_are_the_models_bind_entries(tmp_path: Path) -> None:
    project = tmp_path / "app"
    model = {
        "services": {"web": {"volumes": [
            "./data:/data", "cache:/cache", f"{project}/conf:/etc/app:ro",
            {"type": "bind", "source": str(project / "db"), "target": "/var/db"}]}},
        "secrets": {"key": {"file": "./secrets/key"}},
        "configs": {"site": {"file": str(project / "site.conf")}},
    }
    assert bind_sources.model_sources(model, project) == {
        "data", "conf", "db", "secrets/key", "site.conf"}
    model["services"]["web"]["volumes"].append(f"{tmp_path}/elsewhere:/x")
    with pytest.raises(BindSourceError):
        bind_sources.model_sources(model, project)


def test_a_relative_base_still_places_paths(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "app").mkdir()
    monkeypatch.chdir(tmp_path)
    [bind] = _one("./data:/data", Path("app"))
    assert bind.path == "app/data"
    assert project_rel(os.path.abspath(bind.path), Path("app")) == "data"
    assert bind_sources.project_rel(bind.path, Path("app")) == "data"
