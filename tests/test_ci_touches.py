# SPDX-License-Identifier: Apache-2.0
"""scripts/ci-touches.sh: whether a change touches given paths, which decides
whether CI's arm64 job does its work or reports a skip. The job always runs
(a required check must report); only its steps are conditional."""
from __future__ import annotations

import re
import subprocess
import sys
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


def _scope(touches_rc: int, tmp: Path, job: str = "arm64",
           event: str = "pull_request") -> subprocess.CompletedProcess:
    """Run a job's scope step (scripts/ci-scope.sh) with ci-touches.sh exiting touches_rc."""
    (tmp / "scripts").mkdir()
    (tmp / "scripts" / "ci-touches.sh").write_text(f"exit {touches_rc}\n")
    (tmp / "scripts" / "ci-scope.sh").write_text((REPO / "scripts" / "ci-scope.sh").read_text())
    out = tmp / "github_output"
    step = yaml.safe_load((REPO / ".github" / "workflows" / "ci.yml").read_text())["jobs"][job]["steps"][1]
    proc = subprocess.run(["bash", "-e", "-c", step["run"]], cwd=tmp, capture_output=True, text=True,
                          env={"PATH": "/usr/bin:/bin", "BASE": "x", "EVENT": event,
                               "GITHUB_OUTPUT": str(out)})
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
    assert scope["env"] == {"EVENT": "${{ github.event_name }}",
                            "BASE": "${{ github.event.pull_request.base.sha }}"}
    words = scope["run"].replace("\\\n", " ").split()
    call = words[words.index("scripts/ci-scope.sh") - 1:]
    assert call == ["bash", "scripts/ci-scope.sh", "--outside", '"$BASE"', *DOCKER_SKIPPABLE]
    assert work and all(s["if"] == "steps.scope.outputs.relevant == 'true'" for s in work)


@pytest.mark.parametrize("job", ["integration", "userns-dind"])
@pytest.mark.parametrize("touches_rc", [0, 1, 2])
def test_a_push_to_main_runs_the_docker_tiers_in_full(tmp_path: Path, job: str,
                                                      touches_rc: int) -> None:
    """Every main commit is tested: only a pull request may skip them."""
    proc = _scope(touches_rc, tmp_path, job, event="push")
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.endswith("relevant=true\n")


# Where a file the Docker tiers read names a skippable path, and why that is
# no dependency of theirs. Anything else naming one fails the test below:
# either the reference is not a dependency (add it here, with the reason) or
# the path must come off DOCKER_SKIPPABLE, so the Docker jobs run for it.
NOT_DEPENDENCIES = {
    ("Makefile", "cli/"): "the lint and lock targets; the bundle never reads cli/",
    ("Makefile", "docs/DEVELOPMENT.md"): "a comment on the lock targets",
    ("Makefile", "services/version-check/"): "the lock target only",
    ("scripts/check-dco.sh", "CONTRIBUTING.md"): "named in its error message",
    ("scripts/release-lint.py", "services/version-check/"):
        "release tooling: the release workflow and its unit test run it, no Docker test does",
    ("scripts/release-lint.py", "docs/DEVELOPMENT.md"): "named in its error message",
    ("src/boxmunge/api/result.py", "docs/PLUGIN_API.md"): "a docstring reference",
    ("src/boxmunge/api/server.py", "docs/PLUGIN_API.md"): "named in an error message",
    ("src/boxmunge/commands/help.py", "SECURITY.md"): "the on-server doc of that name",
    ("src/boxmunge/compose_images.py", "SECURITY.md"): "a comment",
    ("src/boxmunge/release_selection.py", "services/version-check/"): "a docstring reference",
}


def _docker_test_files() -> set[str]:
    """The test files holding a test either Docker tier selects."""
    out = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/", "--ignore=tests/vm", "-m", "integration",
         "--collect-only", "-q", "-p", "no:cacheprovider"],
        cwd=REPO, capture_output=True, text=True, check=True).stdout
    return {line.split("::", 1)[0] for line in out.splitlines() if "::" in line}


def _read_by_docker_tiers(name: str, docker_tests: set[str]) -> bool:
    """Whether the integration or userns-dind jobs can read this tracked
    file: anything outside the skippable paths and .github/, except
    Markdown prose and the test files of the unit tier."""
    if name.startswith(".github/") or name.endswith(".md") or any(
            name.startswith(p) if p.endswith("/") else name == p for p in DOCKER_SKIPPABLE):
        return False
    if name.startswith("tests/") and name.rsplit("/", 1)[-1].startswith("test_"):
        return name in docker_tests
    return True


def _skippable_references(text: str) -> set[str]:
    # `REPO / "services" / "version-check"` names services/version-check/ too.
    joined = re.sub(r"""(["'])\s*/\s*(["'])""", "/", text)
    found = set(re.findall(r"(?<![\w./-])(" + "|".join(map(re.escape, DOCKER_SKIPPABLE)) + ")",
                           joined))
    if re.search(r"""/\s*["']cli["']""", text):
        found.add("cli/")
    return found


def test_nothing_the_docker_tiers_read_depends_on_a_skippable_path() -> None:
    """The Docker jobs skip a pull request that changes only skippable paths,
    so no test of theirs, nor the code it drives, may read one."""
    tracked = subprocess.run(["git", "ls-files"], cwd=REPO, capture_output=True, text=True,
                             check=True).stdout.splitlines()
    docker_tests = _docker_test_files()
    assert "tests/integration/test_probe.py" in docker_tests
    found = set()
    for name in (n for n in tracked if _read_by_docker_tiers(n, docker_tests)):
        try:
            text = (REPO / name).read_text()
        except (UnicodeDecodeError, IsADirectoryError, FileNotFoundError):
            continue
        found |= {(name, path) for path in _skippable_references(text)}
    assert found - set(NOT_DEPENDENCIES) == set(), \
        "Docker-tier files name skippable paths (see NOT_DEPENDENCIES)"
    assert set(NOT_DEPENDENCIES) - found == set(), "stale NOT_DEPENDENCIES entries"


@pytest.mark.parametrize("text, path", [
    ('open(REPO / "services" / "version-check" / "x.json")', "services/version-check/"),
    ("subprocess.run(['make', '-C', 'cli/'])", "cli/"),
    ('ROOT / "cli" / "src"', "cli/"),
    ('read("README.md")', "README.md"),
])
def test_the_guard_sees_a_reference_however_it_is_written(text: str, path: str) -> None:
    assert path in _skippable_references(text)


@pytest.mark.parametrize("text", ["boxmunge_cli/x.py", "docs/on-server/README.md",
                                  "/opt/box/README.md", 'root / "docs"'])
def test_the_guard_ignores_other_paths(text: str) -> None:
    assert _skippable_references(text) == set()
