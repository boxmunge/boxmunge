"""Root's deploy runs the pre_deploy hook as the real deploy user.

Runs tests/integration/uid_hook/run_hook.py as real root in a throwaway
Debian 13 container with a real deploy account, the way an operator's
`sudo boxmunge-server prod-deploy` would run the hook.
"""
import json
import subprocess
import uuid
from pathlib import Path

import pytest
import yaml

import boxmunge
from tests.integration.conftest import skip_no_docker

pytestmark = [pytest.mark.integration, skip_no_docker]

IMAGE = "python:3.13-slim-trixie"
SRC = Path(boxmunge.__file__).parents[1]
SCRIPT = Path(__file__).parent / "uid_hook" / "run_hook.py"


@pytest.fixture(scope="module")
def seen() -> dict:
    result = subprocess.run(
        ["docker", "run", "--rm", "--network", "none",
         "--name", f"bmtest-hook-as-deploy-{uuid.uuid4().hex[:10]}",
         "-v", f"{SRC}:/src:ro", "-v", f"{SCRIPT}:/run_hook.py:ro",
         "-v", f"{Path(yaml.__file__).parent}:/deps/yaml:ro",
         "-e", "PYTHONPATH=/src:/deps", IMAGE, "python", "/run_hook.py"],
        capture_output=True, text=True, timeout=300,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads(result.stdout.strip().splitlines()[-1])
    assert report["rc"] == 0, result.stdout + result.stderr
    lines = report["report"].splitlines()
    report["facts"] = dict(line.split("=", 1) for line in lines if not line.startswith("env:"))
    report["env"] = dict(line[4:].split("=", 1) for line in lines if line.startswith("env:"))
    return report


def test_the_hook_runs_with_deploys_uid_gid_and_groups(seen: dict) -> None:
    uid, gid = seen["deploy_uid"], seen["deploy_gid"]
    assert seen["facts"]["uid"] == f"{uid} gid={gid} groups={gid}", seen
    assert seen["facts"]["cwd"] == seen["project"], seen


def test_the_hook_cannot_reach_roots_files_or_descriptors(seen: dict) -> None:
    assert seen["facts"]["secret"] == "denied", seen
    assert seen["facts"]["fd7"] == "closed", seen
    assert seen["facts"]["tty"] == "no", seen
    assert seen["facts"]["own_session"] == "True", seen  # no terminal of root's to inject into


def test_the_hook_gets_deploys_shell_environment(seen: dict) -> None:
    env = seen["env"]
    assert env["HOME"] == "/home/deploy" and env["USER"] == "deploy", env
    assert env["PATH"] == "/usr/local/bin:/usr/bin:/bin", env
    for name in ("SUDO_USER", "BASH_ENV", "PYTHONPATH"):
        assert name not in env, env


def test_ctrl_c_on_a_deploy_kills_what_its_hook_started(seen: dict) -> None:
    assert seen["survivors"] == [], seen
