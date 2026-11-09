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


PATHS = ["system/", "install.sh", "bootstrap/", "scripts/", ".github/workflows/",
         "tests/fixtures/age-v1.2.1/"]


def _touches(repo: Path, base: str) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", str(SCRIPT), base, *PATHS], cwd=repo,
                          capture_output=True, text=True, check=False)


@pytest.mark.parametrize("changed", ["system/Dockerfile", "install.sh", "bootstrap/cosign.sh",
                                     "scripts/boxmunge-upgrade", ".github/workflows/ci.yml",
                                     "tests/fixtures/age-v1.2.1/identity.txt"])
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


def test_a_failing_git_diff_is_an_error_not_a_skip(repo: Path, tmp_path_factory) -> None:
    """Exit 1 means "skip the checks"; a broken comparison must not look like it."""
    base = _git(repo, "rev-parse", "HEAD")
    _commit(repo, "system/Dockerfile")
    shim = tmp_path_factory.mktemp("bin")
    real = subprocess.run(["sh", "-c", "command -v git"], capture_output=True, text=True).stdout.strip()
    (shim / "git").write_text(f'#!/bin/sh\n[ "$1" = diff ] && exit 128\nexec {real} "$@"\n')
    (shim / "git").chmod(0o755)
    proc = subprocess.run(["bash", str(SCRIPT), base, *PATHS], cwd=repo, capture_output=True,
                          text=True, env={"PATH": f"{shim}:/usr/bin:/bin"})
    assert proc.returncode not in (0, 1), proc.stdout


def _scope(touches_rc: int, tmp: Path, job: str = "arm64") -> subprocess.CompletedProcess:
    """Run a job's scope step (scripts/ci-scope.sh) with ci-touches.sh exiting touches_rc."""
    (tmp / "scripts").mkdir()
    (tmp / "scripts" / "ci-touches.sh").write_text(f"exit {touches_rc}\n")
    (tmp / "scripts" / "ci-scope.sh").write_text((REPO / "scripts" / "ci-scope.sh").read_text())
    out = tmp / "github_output"
    step = yaml.safe_load((REPO / ".github" / "workflows" / "ci.yml").read_text())["jobs"][job]["steps"][1]
    proc = subprocess.run(["bash", "-e", "-c", step["run"]], cwd=tmp, capture_output=True, text=True,
                          env={"PATH": "/usr/bin:/bin", "BASE": "x", "GITHUB_OUTPUT": str(out)})
    proc.stdout += out.read_text() if out.exists() else ""
    return proc


GATED = ["arm64", "integration", "userns-dind"]


@pytest.mark.parametrize("job", GATED)
@pytest.mark.parametrize(("rc", "relevant"), [(0, "true"), (1, "false")])
def test_the_scope_step_runs_or_skips(tmp_path: Path, rc: int, relevant: str, job: str) -> None:
    proc = _scope(rc, tmp_path, job)
    assert proc.returncode == 0, proc.stderr
    assert f"relevant={relevant}\n" in proc.stdout


@pytest.mark.parametrize("job", GATED)
@pytest.mark.parametrize("rc", [2, 128])
def test_the_scope_step_fails_on_any_other_exit(tmp_path: Path, rc: int, job: str) -> None:
    proc = _scope(rc, tmp_path, job)
    assert proc.returncode != 0
    assert "relevant=" not in proc.stdout


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
    assert scope["run"].startswith("bash scripts/ci-scope.sh \"$BASE\" ")
    for path in PATHS:
        assert path in scope["run"]
    assert work and all(s["if"] == "steps.scope.outputs.relevant == 'true'" for s in work)


# What the Docker jobs may skip on: files none of their tests reads.
DOCKER_SKIPPABLE = ["cli/", "services/version-check/", "docs/DEVELOPMENT.md",
                    "docs/PLUGIN_API.md", "README.md", "CONTRIBUTING.md",
                    "CODE_OF_CONDUCT.md", "SECURITY.md", "INSTALL.md"]


def _outside(repo: Path, base: str) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", str(SCRIPT), "--outside", base, *DOCKER_SKIPPABLE], cwd=repo,
                          capture_output=True, text=True, check=False)


@pytest.mark.parametrize("changed", [["cli/src/x.py"], ["services/version-check/app.py"],
                                     ["README.md", "docs/DEVELOPMENT.md", "cli/README.md"]])
def test_outside_skips_a_change_made_only_of_listed_paths(repo: Path, changed: list[str]) -> None:
    base = _git(repo, "rev-parse", "HEAD")
    _commit(repo, *changed)
    proc = _outside(repo, base)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "nothing outside" in proc.stdout


@pytest.mark.parametrize("changed", [["src/boxmunge/x.py"], ["cli/x.py", "tests/test_x.py"],
                                     ["docs/on-server/OPERATIONS.md"], ["newdir/x"],
                                     ["services/other/x.py"], ["cli"]])
def test_outside_runs_for_any_other_file(repo: Path, changed: list[str]) -> None:
    base = _git(repo, "rev-parse", "HEAD")
    _commit(repo, *changed)
    proc = _outside(repo, base)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert any(c in proc.stdout for c in changed if not c.startswith("cli/"))


def test_outside_with_an_unknown_base_does_the_work(repo: Path) -> None:
    assert _outside(repo, ZERO).returncode == 0


@pytest.mark.parametrize("job", ["integration", "userns-dind"])
def test_the_docker_jobs_always_run_and_gate_their_steps(job: str) -> None:
    ci = yaml.safe_load((REPO / ".github" / "workflows" / "ci.yml").read_text())
    spec = ci["jobs"][job]
    assert "if" not in spec
    checkout, scope, *work = spec["steps"]
    assert checkout["with"]["fetch-depth"] == 0
    assert scope["id"] == "scope"
    assert scope["run"].split() == ["bash", "scripts/ci-scope.sh", "--outside", '"$BASE"',
                                    *DOCKER_SKIPPABLE]
    assert work and all(s["if"] == "steps.scope.outputs.relevant == 'true'" for s in work)
