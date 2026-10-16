"""F-02: validation runs on the model Compose will run, not the literal file.

The resolver's Docker call is fed canned `docker compose config` output
here (the shape Docker Compose v2 emits); tests/integration/
test_compose_resolve.py runs the real command.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from boxmunge import docker
from boxmunge.compose import (
    ComposeError,
    load_user_compose,
)
from boxmunge.compose_validate import ComposeSecurityError, validate_user_compose
from boxmunge.paths import BoxPaths


def _project(paths: BoxPaths, files: dict[str, object]) -> Path:
    project_dir = paths.project_dir("myapp")
    project_dir.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        path = project_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content if isinstance(content, str) else yaml.safe_dump(content))
    return project_dir / "compose.yml"


def _resolved_as(monkeypatch, resolved: dict) -> None:
    monkeypatch.setattr(
        docker, "compose_config",
        lambda project_dir, compose_files=None, *, project_name: json.dumps(resolved),
    )


def _resolved_service(**svc) -> dict:
    return {
        "name": "myapp",
        "networks": {"default": {"name": "myapp_default", "ipam": {}}},
        "services": {"web": {"image": "nginx", "networks": {"default": None}, **svc}},
    }


def _validate(compose: Path, paths: BoxPaths) -> None:
    validate_user_compose(compose, paths, project_name="myapp")


# ---------------------------------------------------------------------------
# Values only visible after interpolation / extends
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("literal,resolved", [
    ({"cap_add": ["${C}"]}, {"cap_add": ["SYS_ADMIN"]}),
    ({"security_opt": ["apparmor=${U}"]}, {"security_opt": ["apparmor=unconfined"]}),
    ({"network_mode": "${N:-bridge}"}, {"network_mode": "host"}),
    ({"privileged": "${P:-false}"}, {"privileged": True}),
    ({"extends": {"file": "base.yml", "service": "evil"}}, {"pid": "host"}),
], ids=["cap from .env", "apparmor from .env", "network default", "privileged", "extends"])
def test_hostile_value_visible_only_after_resolution_rejected(
    paths: BoxPaths, monkeypatch, literal: dict, resolved: dict,
) -> None:
    compose = _project(paths, {
        "compose.yml": {"services": {"web": {"image": "nginx", **literal}}},
        "base.yml": {"services": {"evil": {"image": "x"}}},
    })
    _resolved_as(monkeypatch, _resolved_service(**resolved))
    with pytest.raises(ComposeSecurityError, match="service web"):
        _validate(compose, paths)


def test_resolved_bind_mount_outside_project_rejected(paths: BoxPaths, monkeypatch) -> None:
    compose = _project(paths, {"compose.yml": {"services": {"web": {"image": "nginx"}}}})
    _resolved_as(monkeypatch, _resolved_service(volumes=[
        {"type": "bind", "source": "/", "target": "/host", "bind": {}},
    ]))
    with pytest.raises(ComposeSecurityError, match="protected host path"):
        _validate(compose, paths)


def test_resolved_benign_project_accepted(paths: BoxPaths, monkeypatch) -> None:
    compose = _project(paths, {"compose.yml": {"services": {"web": {"image": "nginx"}}}})
    data = str(paths.project_dir("myapp") / "data")
    _resolved_as(monkeypatch, _resolved_service(
        volumes=[{"type": "bind", "source": data, "target": "/data", "bind": {}}],
        environment={"A": "1"},
    ))
    _validate(compose, paths)


def test_unresolvable_compose_refused(paths: BoxPaths, monkeypatch) -> None:
    compose = _project(paths, {"compose.yml": {"services": {"web": {"image": "nginx"}}}})

    def _fail(*a, **kw):
        raise docker.DockerError("service web refers to undefined network x")

    monkeypatch.setattr(docker, "compose_config", _fail)
    with pytest.raises(ComposeSecurityError, match="could not resolve"):
        _validate(compose, paths)


# ---------------------------------------------------------------------------
# include / extends / env_file references must stay inside the project
# ---------------------------------------------------------------------------

REFERENCES_REJECTED = {
    "include outside": {"include": ["../other/inc.yml"], "services": {}},
    "include long syntax outside": {"include": [{"path": "/srv/inc.yml"}], "services": {}},
    "include env_file outside": {
        "include": [{"path": "inc.yml", "env_file": "../projb/secrets.env"}], "services": {},
    },
    "include project_directory outside": {
        "include": [{"path": "inc.yml", "project_directory": "../.."}], "services": {},
    },
    "remote include": {"include": ["oci://registry.example.com/evil:latest"], "services": {}},
    "extends file outside": {
        "services": {"web": {"extends": {"file": "../projb/compose.yml", "service": "db"}}},
    },
    "env_file in another project": {
        "services": {"web": {"image": "x", "env_file": ["../projb/secrets.env"]}},
    },
    "env_file in boxmunge config": {
        "services": {"web": {"image": "x", "env_file": "../../config/secrets.env"}},
    },
    "env_file long syntax outside": {
        "services": {"web": {"image": "x", "env_file": [{"path": "/etc/environment"}]}},
    },
    "env_file interpolated": {
        "services": {"web": {"image": "x", "env_file": ["${ENVF}"]}},
    },
}


@pytest.mark.parametrize("doc", REFERENCES_REJECTED.values(), ids=REFERENCES_REJECTED.keys())
def test_reference_leaving_project_rejected(paths: BoxPaths, doc: dict) -> None:
    compose = _project(paths, {"compose.yml": doc, "inc.yml": {"services": {}}})
    with pytest.raises(ComposeSecurityError):
        _validate(compose, paths)


def test_nested_include_leaving_project_rejected(paths: BoxPaths) -> None:
    compose = _project(paths, {
        "compose.yml": {"include": ["parts/inc.yml"], "services": {}},
        "parts/inc.yml": {"include": ["../../projb/compose.yml"], "services": {}},
    })
    with pytest.raises(ComposeSecurityError, match="parts|inc.yml"):
        _validate(compose, paths)


def test_references_inside_project_accepted(paths: BoxPaths) -> None:
    compose = _project(paths, {
        "compose.yml": {
            "include": ["parts/db.yml"],
            "services": {"web": {
                "extends": {"file": "base.yml", "service": "app"},
                "env_file": ["project.env"],
            }},
        },
        "parts/db.yml": {"services": {"db": {"image": "postgres", "env_file": "../db.env"}}},
        "base.yml": {"services": {"app": {"image": "nginx"}}},
    })
    _validate(compose, paths)


# ---------------------------------------------------------------------------
# The overlay sees every resolved service; staging refuses what it cannot split
# ---------------------------------------------------------------------------

def test_overlay_reads_services_from_resolved_model(paths: BoxPaths, monkeypatch) -> None:
    compose = _project(paths, {"compose.yml": {"include": ["parts/db.yml"], "services": {}}})
    resolved = _resolved_service()
    resolved["services"]["db"] = {"image": "postgres"}
    _resolved_as(monkeypatch, resolved)
    assert set(load_user_compose(compose, "myapp")["services"]) == {"web", "db"}


def test_overlay_refuses_unresolvable_compose(paths: BoxPaths) -> None:
    with pytest.raises(ComposeError, match="cannot resolve"):
        load_user_compose(paths.project_dir("myapp") / "compose.yml", "myapp")


