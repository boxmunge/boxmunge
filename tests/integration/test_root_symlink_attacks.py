"""Root never follows a link the deploy user planted in a deploy-writable dir.

Runs tests/integration/uid_attacks/attack.py as real root in a throwaway
container with a real deploy uid as the attacker. Each scenario points a
boxmunge path (or a temp file, swapped right after mkstemp) at a root-only
file, then lets root do its normal write. The root-only file must come out
unchanged, and the refusal must be loud.
"""
import json
import subprocess
from pathlib import Path

import pytest
import yaml

import boxmunge

pytestmark = pytest.mark.integration

IMAGE = "python:3.12-slim"
SRC = Path(boxmunge.__file__).parents[1]
ATTACK = Path(__file__).parent / "uid_attacks" / "attack.py"
UNTOUCHED = {"uid": 0, "gid": 0, "mode": "0o600", "content": "ROOT-ONLY\n"}


def _attack(scenario: str) -> dict:
    result = subprocess.run(
        ["docker", "run", "--rm",
         "-v", f"{SRC}:/src:ro", "-v", f"{ATTACK}:/attack.py:ro",
         "-v", f"{Path(yaml.__file__).parent}:/deps/yaml:ro",
         "-e", "PYTHONPATH=/src:/deps", IMAGE, "python", "/attack.py", scenario],
        capture_output=True, text=True, timeout=300,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout.strip().splitlines()[-1])


@pytest.mark.parametrize("scenario", ["log-active-link", "log-archive-link"])
def test_logging_as_root_does_not_write_through_a_planted_link(scenario: str) -> None:
    report = _attack(scenario)
    assert report["secret"] == UNTOUCHED, report
    assert "not a plain regular file" in report["stderr"] or "Too many levels" in report["stderr"], report


@pytest.mark.parametrize("scenario", [
    "lock-link", "atomic-write-swap", "dump-temp-swap", "stash-link",
])
def test_root_writers_refuse_a_planted_link(scenario: str) -> None:
    report = _attack(scenario)
    assert report["secret"] == UNTOUCHED, report
    assert report["outcome"].startswith("raised"), report
