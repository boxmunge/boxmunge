"""container_name is refused: Compose names every container inside the project.

The host's CrowdSec follows boxmunge-caddy by name, and Docker hands a free
name to whoever asks first: a project that could name a container would be
fed Caddy's traffic whenever the real one is absent, or take another
project's names. No prefix rule is safe (project names contain hyphens, and
`boxmunge` is a valid one). Real `docker compose config` runs.
"""
from __future__ import annotations

from typing import Any

import pytest
import yaml

from boxmunge.compose_validate import ComposeSecurityError, validate_user_compose
from boxmunge.paths import BoxPaths


def _validate(paths: BoxPaths, svc: dict[str, Any], *, project: str = "myapp",
              off: bool = False) -> None:
    project_dir = paths.project_dir(project)
    project_dir.mkdir(parents=True, exist_ok=True)
    compose = project_dir / "compose.yml"
    compose.write_text(yaml.safe_dump({"services": {"web": {"image": "alpine", **svc}}}))
    validate_user_compose(compose, paths, project_name=project,
                          off_services={"web"} if off else None)


@pytest.mark.parametrize(("project", "name"), [
    ("myapp", "boxmunge-caddy"), ("myapp", "other-web-1"), ("myapp", "myapp-web"),
    ("myapp", "myapp-x-web-1"),  # project myapp-x's default name
    ("boxmunge", "boxmunge-caddy"),
])
@pytest.mark.parametrize("off", [False, True])
def test_any_container_name_is_refused(paths, project, name, off) -> None:
    with pytest.raises(ComposeSecurityError) as e:
        _validate(paths, {"container_name": name}, project=project, off=off)
    message = str(e.value)
    assert "service web: container_name is not allowed" in message
    assert f"Compose names the container itself ({project}-web-1)" in message


def test_no_container_name_is_accepted(paths) -> None:
    _validate(paths, {})
