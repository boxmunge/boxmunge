"""F-08: every compose invocation names its project explicitly.

Without `-p`, Compose takes the project name from a top-level `name:` in
the user's compose file (or the directory name), so a bundle could point
`up --remove-orphans` or `down` at another project's containers and
volumes.
"""
from __future__ import annotations

import functools

import ast
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from boxmunge import docker
from boxmunge.compose_validate import ComposeSecurityError, validate_user_compose
from boxmunge.paths import BoxPaths

COMPOSE_FUNCS = {
    "compose_up": docker.compose_up,
    "compose_down": docker.compose_down,
    "compose_stop": docker.compose_stop,
    "compose_logs": docker.compose_logs,
    "compose_logs_capture": docker.compose_logs_capture,
    "compose_ps": docker.compose_ps,
    "compose_pull": functools.partial(docker.compose_pull, services=["web"]),
}


@pytest.mark.parametrize("func", COMPOSE_FUNCS.values(), ids=COMPOSE_FUNCS.keys())
@pytest.mark.parametrize("name", ["myapp", "myapp-staging"])
def test_every_compose_call_passes_project_name(func, name: str, tmp_path: Path) -> None:
    with patch("boxmunge.docker._run") as run:
        func(tmp_path, project_name=name)
    cmd = run.call_args[0][0]
    assert cmd[:4] == ["docker", "compose", "-p", name]


@pytest.mark.parametrize("func", COMPOSE_FUNCS.values(), ids=COMPOSE_FUNCS.keys())
def test_project_name_is_required(func, tmp_path: Path) -> None:
    with patch("boxmunge.docker._run") as run, pytest.raises(TypeError):
        func(tmp_path)
    run.assert_not_called()


@pytest.mark.parametrize("bad", ["", "../x", "Other", "a b", "shop-staging-staging", "caddy-staging"])
def test_invalid_compose_project_name_runs_nothing(bad: str, tmp_path: Path) -> None:
    with patch("boxmunge.docker._run") as run, pytest.raises(ValueError):
        docker.compose_up(tmp_path, project_name=bad)
    run.assert_not_called()


def test_platform_caddy_stack_name_accepted(tmp_path: Path) -> None:
    # container-update recreates the platform Caddy stack as compose
    # project "caddy"; user projects cannot take that name.
    with patch("boxmunge.docker._run") as run:
        docker.compose_pull(tmp_path, project_name="caddy", services=["caddy"])
    assert run.call_args[0][0][:4] == ["docker", "compose", "-p", "caddy"]


def test_staging_compose_project_name() -> None:
    assert docker.staging_compose_project("shop") == "shop-staging"
    with pytest.raises(ValueError):
        docker.staging_compose_project("shop-staging")


def test_top_level_name_rejected(paths: BoxPaths) -> None:
    project_dir = paths.project_dir("myapp")
    project_dir.mkdir(parents=True)
    compose = project_dir / "compose.yml"
    compose.write_text(yaml.safe_dump({"name": "projb", "services": {"web": {"image": "x"}}}))
    with pytest.raises(ComposeSecurityError, match="Remove the top-level name"):
        validate_user_compose(compose, paths, project_name="myapp")


def test_top_level_name_rejected_even_when_profile_off(paths: BoxPaths) -> None:
    project_dir = paths.project_dir("myapp")
    project_dir.mkdir(parents=True)
    compose = project_dir / "compose.yml"
    compose.write_text(yaml.safe_dump({"name": "myapp", "services": {"web": {"image": "x"}}}))
    with pytest.raises(ComposeSecurityError, match="top-level name"):
        validate_user_compose(compose, paths, project_name="myapp", off_services={"web"})


# ---------------------------------------------------------------------------
# No compose invocation bypasses compose_command
# ---------------------------------------------------------------------------

SRC = Path(__file__).resolve().parents[1] / "src" / "boxmunge"

# Files whose compose invocations drive the platform's own Caddy stack (run
# from /opt/boxmunge/caddy), never a project's.
_PLATFORM_CADDY_FILES = {
    "commands/caddy_status.py", "commands/doctor.py", "tui/data.py", "docker.py",
}


def _literal_compose_calls(path: Path) -> list[tuple[int, list]]:
    """Return (line, constant items) for list literals starting
    ["docker", "compose", ...]."""
    tree = ast.parse(path.read_text())
    hits = []
    for node in ast.walk(tree):
        if isinstance(node, ast.List) and len(node.elts) >= 2:
            consts = [e.value for e in node.elts if isinstance(e, ast.Constant)]
            if consts[:2] == ["docker", "compose"]:
                hits.append((node.lineno, consts))
    return hits


def test_project_compose_commands_all_name_the_project() -> None:
    offenders = []
    for path in sorted(SRC.rglob("*.py")):
        rel = str(path.relative_to(SRC))
        if rel in _PLATFORM_CADDY_FILES:
            continue
        for lineno, consts in _literal_compose_calls(path):
            # `docker compose version` reads no project.
            if "-p" not in consts and consts[2:3] != ["version"]:
                offenders.append(f"{rel}:{lineno}")
    assert offenders == [], (
        "compose invocations without -p; build them with docker.compose_command: "
        + ", ".join(offenders)
    )


# Helpers that act on one project's containers; every call must name it.
_PROJECT_SCOPED = {
    "compose_up", "compose_down", "compose_stop", "compose_logs",
    "compose_logs_capture", "compose_ps", "compose_pull", "compose_config",
    "project_restart_policies",
}


def test_project_scoped_helpers_always_get_project_name() -> None:
    offenders = []
    for path in sorted(SRC.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
            if name in _PROJECT_SCOPED and not any(
                k.arg == "project_name" for k in node.keywords
            ):
                offenders.append(f"{path.relative_to(SRC)}:{node.lineno} {name}")
    assert offenders == [], "calls without project_name=: " + ", ".join(offenders)


def test_compose_project_label_only_built_in_docker_module() -> None:
    # Raw docker calls that select a project's containers by label must use
    # docker.compose_project_filter, which validates the name.
    offenders = [
        str(path.relative_to(SRC)) for path in sorted(SRC.rglob("*.py"))
        if path.name != "docker.py" and "com.docker.compose.project" in path.read_text()
    ]
    assert offenders == [], offenders


def test_compose_project_filter_validates_name() -> None:
    assert docker.compose_project_filter("myapp-staging") == [
        "--filter", "label=com.docker.compose.project=myapp-staging",
    ]
    with pytest.raises(ValueError):
        docker.compose_project_filter("../other")


def test_restart_policies_require_valid_project_name() -> None:
    with patch("boxmunge.docker._run") as run, pytest.raises(ValueError):
        docker.project_restart_policies(project_name="Bad Name")
    run.assert_not_called()
