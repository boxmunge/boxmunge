# SPDX-License-Identifier: Apache-2.0
"""scripts/ci-touches.sh: whether a change touches given paths, which decides
whether CI's arm64 job does its work or reports a skip. The job always runs
(a required check must report); only its steps are conditional."""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "ci-touches.sh"
ZERO = "0" * 40


def _git(repo: Path, *args: str) -> str:
    env = {"GIT_AUTHOR_NAME": "Dev", "GIT_AUTHOR_EMAIL": "dev@example.com",
           "GIT_COMMITTER_NAME": "Dev", "GIT_COMMITTER_EMAIL": "dev@example.com",
           "HOME": str(repo), "PATH": "/usr/bin:/bin:/usr/local/bin", "GIT_CONFIG_NOSYSTEM": "1"}
    return subprocess.run(["git", *args], cwd=repo, env=env, check=True,
                          capture_output=True, text=True).stdout.strip()


def _commit(repo: Path, *files: str) -> str:
    for name in files:
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_text(f"{name} {_git(repo, 'rev-list', '--all', '--count')}\n")
        _git(repo, "add", name)
    _git(repo, "commit", "-q", "-m", f"touch {' '.join(files)}")
    return _git(repo, "rev-parse", "HEAD")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "-q", "-b", "main")
    _commit(tmp_path, "README.md")
    return tmp_path


PATHS = ["system/", "install.sh", "bootstrap/", "scripts/", ".github/workflows/"]


def _touches(repo: Path, base: str) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", str(SCRIPT), base, *PATHS], cwd=repo,
                          capture_output=True, text=True, check=False)


@pytest.mark.parametrize("changed", ["system/Dockerfile", "install.sh", "bootstrap/cosign.sh",
                                     "scripts/boxmunge-upgrade", ".github/workflows/ci.yml"])
def test_a_change_under_a_path_is_relevant(repo: Path, changed: str) -> None:
    base = _git(repo, "rev-parse", "HEAD")
    _commit(repo, changed)
    proc = _touches(repo, base)
    assert proc.returncode == 0, proc.stderr
    assert changed in proc.stdout


@pytest.mark.parametrize("changed", ["src/boxmunge/cli.py", "docs/x.md", "installer.md",
                                     "systemd/x.timer", ".github/dependabot.yml"])
def test_other_changes_are_not(repo: Path, changed: str) -> None:
    base = _git(repo, "rev-parse", "HEAD")
    _commit(repo, changed)
    proc = _touches(repo, base)
    assert proc.returncode == 1, proc.stderr
    assert "none of" in proc.stdout


def test_a_pull_request_is_compared_from_its_merge_base(repo: Path) -> None:
    """main moving on (here: touching system/) must not count as the PR's change."""
    fork = _git(repo, "rev-parse", "HEAD")
    _git(repo, "checkout", "-q", "-b", "feature")
    _commit(repo, "src/x.py")
    _git(repo, "checkout", "-q", "main")
    base = _commit(repo, "system/Dockerfile")
    _git(repo, "checkout", "-q", "feature")
    assert _touches(repo, base).returncode == 1
    assert _git(repo, "merge-base", base, "HEAD") == fork


@pytest.mark.parametrize("base", [ZERO, "", "1234567890abcdef1234567890abcdef12345678"])
def test_an_unknown_base_does_the_work(repo: Path, base: str) -> None:
    """A new branch (before = zeros) or a base not in the clone: run the job."""
    proc = _touches(repo, base)
    assert proc.returncode == 0
    assert "cannot compare" in proc.stdout


def test_usage(repo: Path) -> None:
    proc = subprocess.run(["bash", str(SCRIPT), "HEAD"], cwd=repo, capture_output=True, text=True)
    assert proc.returncode == 2


def test_the_arm64_job_always_runs_and_gates_its_steps() -> None:
    """No workflow-level paths filter and no job-level `if`: a required check
    that never reports blocks every merge."""
    ci = yaml.safe_load((REPO / ".github" / "workflows" / "ci.yml").read_text())
    triggers = ci[True]  # PyYAML reads the `on` key as True
    assert all("paths" not in (triggers.get(t) or {}) for t in triggers)
    job = ci["jobs"]["arm64"]
    assert "if" not in job and "name" not in job  # the check is named "arm64"
    checkout, scope, *work = job["steps"]
    assert checkout["with"]["fetch-depth"] == 0
    assert scope["id"] == "scope"
    assert "scripts/ci-touches.sh" in scope["run"]
    for path in PATHS:
        assert path in scope["run"]
    assert work and all(s["if"] == "steps.scope.outputs.relevant == 'true'" for s in work)
