"""container_name stays inside the project's `<project>-` prefix.

The host's CrowdSec and every Caddy validate and reload find boxmunge-caddy
by name, and Docker hands a free name to whoever asks first: a project that
could name a container boxmunge-caddy would be fed Caddy's traffic and
reloads whenever the real one is absent. Real `docker compose config` runs.
"""
from __future__ import annotations

from typing import Any

import pytest
import yaml

from boxmunge.compose_validate import ComposeSecurityError, validate_user_compose
from boxmunge.paths import BoxPaths
from boxmunge.staging_compose import generate_staging_compose_base


def _validate(paths: BoxPaths, svc: dict[str, Any], *, off: bool = False) -> None:
    project_dir = paths.project_dir("myapp")
    project_dir.mkdir(parents=True, exist_ok=True)
    compose = project_dir / "compose.yml"
    compose.write_text(yaml.safe_dump({"services": {"web": {"image": "alpine", **svc}}}))
    validate_user_compose(compose, paths, project_name="myapp",
                          off_services={"web"} if off else None)


@pytest.mark.parametrize("name", ["boxmunge-caddy", "boxmunge-system", "other-web-1",
                                  "myapp", "myappweb", "MYAPP-web"])
@pytest.mark.parametrize("off", [False, True])
def test_container_name_outside_the_project_prefix_is_refused(paths, name, off) -> None:
    with pytest.raises(ComposeSecurityError) as e:
        _validate(paths, {"container_name": name}, off=off)
    message = str(e.value)
    assert f"container_name {name!r} does not start with 'myapp-'" in message
    assert "Compose names the container myapp-web-1" in message


@pytest.mark.parametrize("name", ["myapp-web", "myapp-custom-web-1"])
def test_container_name_inside_the_project_prefix_is_accepted(paths, name) -> None:
    _validate(paths, {"container_name": name})


def test_no_container_name_is_accepted(paths) -> None:
    _validate(paths, {})


def test_staging_drops_container_name(paths) -> None:
    """A staging copy runs beside production, so it takes Compose's own names."""
    project_dir = paths.project_dir("myapp")
    project_dir.mkdir(parents=True, exist_ok=True)
    compose = yaml.safe_dump({"services": {"web": {"image": "alpine",
                                                   "container_name": "myapp-web"}}})
    (project_dir / "compose.yml").write_text(compose)
    staged = yaml.safe_load(generate_staging_compose_base(project_dir / "compose.yml", set()))
    assert "container_name" not in staged["services"]["web"]
