# SPDX-License-Identifier: Apache-2.0
"""Tests for scripts/check-dco.sh, the CI gate requiring DCO sign-offs."""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "check-dco.sh"


def _git(repo: Path, *args: str, email: str = "dev@example.com") -> str:
    env = {
        "GIT_AUTHOR_NAME": "Dev", "GIT_AUTHOR_EMAIL": email,
        "GIT_COMMITTER_NAME": "Dev", "GIT_COMMITTER_EMAIL": email,
        "HOME": str(repo), "PATH": "/usr/bin:/bin:/usr/local/bin",
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    return subprocess.run(
        ["git", *args], cwd=repo, env=env, check=True,
        capture_output=True, text=True,
    ).stdout.strip()


def _commit(repo: Path, name: str, *, signoff: bool, email: str = "dev@example.com") -> str:
    (repo / name).write_text(name)
    _git(repo, "add", name, email=email)
    args = ["commit", "-q", "-m", f"add {name}"]
    if signoff:
        args.insert(1, "-s")
    _git(repo, *args, email=email)
    return _git(repo, "rev-parse", "HEAD", email=email)


def _run(repo: Path, base: str, head: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(SCRIPT), base, head], cwd=repo,
        capture_output=True, text=True, check=False,
    )


@pytest.fixture
def repo(tmp_path: Path) -> tuple[Path, str]:
    _git(tmp_path, "init", "-q", "-b", "main")
    base = _commit(tmp_path, "base", signoff=False)
    return tmp_path, base


def test_all_signed_off_passes(repo) -> None:
    path, base = repo
    _commit(path, "a", signoff=True)
    head = _commit(path, "b", signoff=True)
    result = _run(path, base, head)
    assert result.returncode == 0, result.stderr
    assert "All 2 commit(s) signed off." in result.stdout


def test_one_unsigned_commit_fails_and_names_it(repo) -> None:
    path, base = repo
    _commit(path, "a", signoff=True)
    bad = _commit(path, "b", signoff=False)
    result = _run(path, base, bad)
    assert result.returncode == 1
    assert bad[:12] in result.stderr
    assert "git rebase --signoff" in result.stderr


def test_signoff_must_match_author_email(repo) -> None:
    path, base = repo
    (path / "c").write_text("c")
    _git(path, "add", "c")
    _git(path, "commit", "-q", "-m", "add c\n\nSigned-off-by: Someone Else <other@example.com>")
    head = _git(path, "rev-parse", "HEAD")
    result = _run(path, base, head)
    assert result.returncode == 1


def test_bot_authors_are_exempt(repo) -> None:
    path, base = repo
    head = _commit(
        path, "bump", signoff=False,
        email="49699333+dependabot[bot]@users.noreply.github.com",
    )
    result = _run(path, base, head)
    assert result.returncode == 0, result.stderr
    assert "skip" in result.stdout


def test_empty_range_fails_noisily(repo) -> None:
    path, base = repo
    result = _run(path, base, base)
    assert result.returncode == 1
    assert "no commits found" in result.stderr


def test_bad_usage_exits_2(repo) -> None:
    path, _ = repo
    result = subprocess.run(
        ["bash", str(SCRIPT)], cwd=path, capture_output=True, text=True, check=False,
    )
    assert result.returncode == 2
