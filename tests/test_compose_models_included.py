"""Top-level `models:` is refused in every compose file the project reads.

`docker compose config` drops unused top-level models, so the rule is
checked on the literal files, and it was checked only on compose.yml: the
same block in an included file passed, and `up` would hand it to Docker
Model Runner, outside the project's containers.
"""
from __future__ import annotations

import pytest
import yaml

from boxmunge.compose_validate import ComposeSecurityError, validate_user_compose
from boxmunge.paths import BoxPaths

_MODELS = {"llm": {"model": "ai/smollm2"}}


def _validate(paths: BoxPaths, files: dict[str, dict]) -> None:
    project_dir = paths.project_dir("myapp")
    for name, doc in files.items():
        path = project_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.safe_dump(doc))
    validate_user_compose(project_dir / "compose.yml", paths, project_name="myapp")


def test_models_in_compose_yml_refused(paths: BoxPaths) -> None:
    with pytest.raises(ComposeSecurityError, match="Docker Model Runner"):
        _validate(paths, {"compose.yml": {"services": {"web": {"image": "nginx"}},
                                          "models": _MODELS}})


def test_models_in_an_included_file_refused(paths: BoxPaths) -> None:
    with pytest.raises(ComposeSecurityError, match="db.yml: declares top-level models:.*Docker Model Runner"):
        _validate(paths, {
            "compose.yml": {"include": ["parts/db.yml"],
                            "services": {"web": {"image": "nginx"}}},
            "parts/db.yml": {"services": {"db": {"image": "postgres:16"}},
                             "models": _MODELS},
        })


def test_an_include_without_models_passes(paths: BoxPaths) -> None:
    _validate(paths, {
        "compose.yml": {"include": ["parts/db.yml"], "services": {"web": {"image": "nginx"}}},
        "parts/db.yml": {"services": {"db": {"image": "postgres:16"}}},
    })
