"""Integration: Compose resolves the same model whoever runs boxmunge.

Compose interpolates `${VAR}` from the process environment as well as the
project's `.env`. Deploys run in the deploy user's SSH session; timers,
upgrades and health restarts run as root under systemd, which sets
INVOCATION_ID, JOURNAL_STREAM and a different HOME. If each compose call
inherited its caller's environment, a compose file could resolve to one
model when validated and another when run, e.g.
`pid: "${INVOCATION_ID:+host}"` is empty in a deploy and `host` under a
timer. These tests resolve through the validation path (captured
`docker compose config`, as the validator and overlay generator use) and
through the execution path (the streaming runner used by up, pull, build
and down) under deliberately different parent environments, and require
identical models.
"""
from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest
import yaml

from boxmunge import docker_run
from boxmunge.compose_resolve import resolve_compose_config
from boxmunge.compose_validate import validate_user_compose
from boxmunge.docker import compose_command
from boxmunge.paths import BoxPaths

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which("docker") is None, reason="docker CLI not on PATH"),
]

_PROJECT = "envprobe"
_HOME = os.path.expanduser("~")

# What a deploy over SSH looks like.
DEPLOY_SESSION = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "HOME": _HOME,
    "LANG": "en_GB.UTF-8",
    "USER": "deploy",
    "SSH_CONNECTION": "192.0.2.10 50022 192.0.2.20 922",
}
# What a root systemd timer looks like, plus variables an attacker could
# hope to find set in some caller's environment.
SYSTEMD_TIMER = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "HOME": _HOME,
    "LANG": "C",
    "INVOCATION_ID": "6f1c0a9e2b0d4c7f8a1e3d5b7c9f0a12",
    "JOURNAL_STREAM": "8:41234",
    "IMAGE_TAG": "attacker",
    "COMPOSE_PROFILES": "debug",
}


def _with_parent_env(monkeypatch: pytest.MonkeyPatch, env: dict[str, str]) -> None:
    for key in list(os.environ):
        monkeypatch.delenv(key)
    for key, value in env.items():
        monkeypatch.setenv(key, value)


def _project(tmp_path: Path, compose: dict, dotenv: str = "") -> tuple[BoxPaths, Path]:
    paths = BoxPaths(root=tmp_path / "bm")
    project_dir = paths.project_dir(_PROJECT)
    project_dir.mkdir(parents=True)
    (project_dir / "compose.yml").write_text(yaml.safe_dump(compose))
    if dotenv:
        (project_dir / ".env").write_text(dotenv)
    return paths, project_dir / "compose.yml"


def _execution_model(compose: Path, capfd: pytest.CaptureFixture[str]) -> dict:
    """Resolve through the streaming runner that up/pull/build/down use."""
    capfd.readouterr()
    docker_run.run(
        compose_command(_PROJECT, [compose.name])
        + ["config", "--format", "json", "--no-env-resolution"],
        cwd=compose.parent,
    )
    return json.loads(capfd.readouterr().out)


_CONDITIONAL_PID = {"services": {"web": {
    "image": "nginx:1.25", "pid": "${INVOCATION_ID:+host}",
}}}


def test_validated_model_is_the_model_a_timer_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str],
) -> None:
    paths, compose = _project(tmp_path, _CONDITIONAL_PID)
    _with_parent_env(monkeypatch, DEPLOY_SESSION)
    validate_user_compose(compose, paths, project_name=_PROJECT)
    validated = resolve_compose_config(compose, _PROJECT)

    _with_parent_env(monkeypatch, SYSTEMD_TIMER)
    executed = _execution_model(compose, capfd)

    assert "pid" not in executed["services"]["web"]
    assert executed == validated


def test_every_caller_environment_resolves_identically(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str],
) -> None:
    _, compose = _project(tmp_path, {"services": {
        "web": {"image": "nginx:${IMAGE_TAG}", "environment": {
            "SEEN_HOME": "${HOME:-unset}", "SEEN_USER": "${USER:-unset}",
            "SEEN_JOURNAL": "${JOURNAL_STREAM:-unset}",
        }},
        "dbg": {"image": "busybox", "privileged": True, "profiles": ["debug"]},
    }}, dotenv="IMAGE_TAG=1.25\n")

    validated, executed = [], []
    for env in (DEPLOY_SESSION, SYSTEMD_TIMER):
        _with_parent_env(monkeypatch, env)
        validated.append(resolve_compose_config(compose, _PROJECT))
        executed.append(_execution_model(compose, capfd))

    assert all(m == validated[0] for m in validated)
    assert all(m == executed[0] for m in executed)
    # Validation resolves every profile (a profiled service still starts
    # when named); execution starts only the active ones. Otherwise the
    # models agree, whoever the caller.
    assert "dbg" in validated[0]["services"]
    assert "dbg" not in executed[0]["services"]
    assert validated[0]["services"]["web"] == executed[0]["services"]["web"]
    web = executed[0]["services"]["web"]
    # The project's own .env still interpolates; nothing from a caller does.
    assert web["image"] == "nginx:1.25"
    assert web["environment"] == {
        "SEEN_HOME": "unset", "SEEN_USER": "unset", "SEEN_JOURNAL": "unset",
    }
