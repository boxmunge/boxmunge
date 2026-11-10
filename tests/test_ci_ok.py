# SPDX-License-Identifier: Apache-2.0
"""CI's `ci-ok` job, the one check main's ruleset requires: it needs every
other job, always runs, and passes only if they all succeeded (dco may skip
on a push, where the workflow skips it)."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "ci-ok.py"
CI = yaml.safe_load((REPO / ".github" / "workflows" / "ci.yml").read_text())


def _run(results: dict[str, str], event: str = "pull_request") -> subprocess.CompletedProcess:
    needs = {job: {"result": r, "outputs": {}} for job, r in results.items()}
    env = {**os.environ, "NEEDS": json.dumps(needs), "EVENT": event}
    return subprocess.run([sys.executable, "-I", str(SCRIPT)], env=env,
                          capture_output=True, text=True, check=False)


ALL = ["arm64", "cli", "dco", "integration", "lint", "locks", "unit", "userns-dind",
       "version-check"]


def test_all_succeeded_passes() -> None:
    assert _run(dict.fromkeys(ALL, "success")).returncode == 0


@pytest.mark.parametrize("result", ["failure", "cancelled", "skipped"])
@pytest.mark.parametrize("job", ["unit", "userns-dind", "arm64"])
def test_any_other_result_fails(job: str, result: str) -> None:
    proc = _run({**dict.fromkeys(ALL, "success"), job: result})
    assert proc.returncode == 1
    assert f"{job}: {result}" in proc.stderr


def test_dco_may_skip_on_a_push_only() -> None:
    results = {**dict.fromkeys(ALL, "success"), "dco": "skipped"}
    assert _run(results, event="push").returncode == 0
    assert _run(results, event="pull_request").returncode == 1


def test_an_empty_needs_fails() -> None:
    assert _run({}).returncode == 1


def test_ci_ok_needs_every_other_job_and_always_runs() -> None:
    job = CI["jobs"]["ci-ok"]
    assert job["if"] == "always()"
    assert set(job["needs"]) == set(CI["jobs"]) - {"ci-ok"} == set(ALL)
    step = job["steps"][-1]
    assert "scripts/ci-ok.py" in step["run"]
    assert step["env"] == {"NEEDS": "${{ toJSON(needs) }}", "EVENT": "${{ github.event_name }}"}


def test_dco_is_the_only_job_that_skips_by_design() -> None:
    conditional = {name for name, job in CI["jobs"].items() if "if" in job} - {"ci-ok"}
    assert conditional == {"dco"}
    assert CI["jobs"]["dco"]["if"] == "github.event_name == 'pull_request'"
