# SPDX-License-Identifier: Apache-2.0
"""Tests for scripts/release-lint.py, the release workflow's class gate."""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

from boxmunge.upgrade_discovery import _github_release_class

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "release-lint.py"
GH = "https://github.com/boxmunge/boxmunge/releases/tag/v"


def _load_module():
    spec = importlib.util.spec_from_file_location("release_lint", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve their module by name
    spec.loader.exec_module(module)
    return module


lint = _load_module()


def _write_tree(tmp_path: Path, version: str, releases: list[tuple[str, str]]) -> dict:
    releases_json = tmp_path / "releases.json"
    releases_json.write_text(json.dumps({"releases": [
        {"version": v, "class": c, "url": f"{GH}{v}"} for v, c in releases
    ]}))
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(f'[project]\nname = "boxmunge-server"\nversion = "{version}"\n')
    return {"releases": releases_json, "pyproject": pyproject}


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(SCRIPT), *args],
                          capture_output=True, text=True, check=False)


class TestCheck:
    @pytest.mark.parametrize("cls,marker", [
        ("security", "[security]"), ("breakfix", "[breakfix]"), ("feature", None),
    ])
    def test_listed_version_yields_class_title_and_notes(self, tmp_path, cls, marker):
        files = _write_tree(tmp_path, "0.11.1", [("0.11.1", cls), ("0.11.0", "feature")])
        plan = lint.plan_release("v0.11.1", files["releases"], files["pyproject"])
        assert plan.release_class == cls
        if marker:
            assert plan.title == f"v0.11.1 {marker}"
            assert plan.notes.startswith(marker)
        else:
            assert plan.title == "v0.11.1"
            assert "[security]" not in plan.notes and "[breakfix]" not in plan.notes

    def test_generated_notes_classify_as_listed(self, tmp_path):
        """The marker we generate is read back by boxes as the listed class."""
        for cls in ("security", "breakfix", "feature"):
            files = _write_tree(tmp_path, "0.11.1", [("0.11.1", cls)])
            plan = lint.plan_release("v0.11.1", files["releases"], files["pyproject"])
            release = {"name": plan.title, "body": plan.notes}
            assert _github_release_class(release) == cls
            assert lint.classify_release(plan.title, plan.notes) == cls

    def test_unlisted_version_fails(self, tmp_path):
        files = _write_tree(tmp_path, "0.11.2", [("0.11.1", "feature")])
        with pytest.raises(lint.ReleaseLintError, match="0.11.2"):
            lint.plan_release("v0.11.2", files["releases"], files["pyproject"])

    def test_invalid_class_fails(self, tmp_path):
        files = _write_tree(tmp_path, "0.11.1", [("0.11.1", "urgent")])
        with pytest.raises(lint.ReleaseLintError, match="urgent"):
            lint.plan_release("v0.11.1", files["releases"], files["pyproject"])

    def test_tag_must_match_pyproject_version(self, tmp_path):
        files = _write_tree(tmp_path, "0.11.0", [("0.11.1", "feature")])
        with pytest.raises(lint.ReleaseLintError, match="pyproject"):
            lint.plan_release("v0.11.1", files["releases"], files["pyproject"])

    @pytest.mark.parametrize("tag", ["0.11.1", "v0.11", "cli-v0.11.1", "v0.11.1-rc.1"])
    def test_malformed_tag_fails(self, tmp_path, tag):
        files = _write_tree(tmp_path, "0.11.1", [("0.11.1", "feature")])
        with pytest.raises(lint.ReleaseLintError, match="tag"):
            lint.plan_release(tag, files["releases"], files["pyproject"])

    def test_repository_releases_json_lists_pyproject_version(self):
        """The checked-in tree must be releasable: whatever version
        pyproject.toml declares is recorded in releases.json."""
        import tomllib
        version = tomllib.loads((REPO / "pyproject.toml").read_text())["project"]["version"]
        plan = lint.plan_release(f"v{version}", lint.RELEASES_JSON, lint.PYPROJECT)
        assert plan.release_class in ("feature", "breakfix", "security")


class TestVerify:
    @pytest.mark.parametrize("name,body,expected", [
        ("v0.11.1 [security]", "[security] fix\n\n## What's Changed", "security"),
        ("v0.11.1 [breakfix]", "[breakfix] fix", "breakfix"),
        ("v0.11.1", "Feature release.", "feature"),
    ])
    def test_matching_release_passes(self, name, body, expected):
        lint.verify_release(name, body, expected)

    def test_generated_notes_smuggling_a_marker_fail(self):
        """A feature release whose auto-generated notes quote a PR titled
        '[security] ...' would be auto-applied by GitHub-fallback boxes."""
        body = "Feature release.\n\n## What's Changed\n* [security] tighten X by @dev"
        with pytest.raises(lint.ReleaseLintError, match="security"):
            lint.verify_release("v0.11.1", body, "feature")

    def test_breakfix_release_with_security_marker_fails(self):
        with pytest.raises(lint.ReleaseLintError):
            lint.verify_release("v0.11.1 [breakfix]", "[breakfix]\n* [security] x", "breakfix")

    def test_missing_marker_fails(self):
        with pytest.raises(lint.ReleaseLintError, match="breakfix"):
            lint.verify_release("v0.11.1", "notes", "breakfix")

    @pytest.mark.parametrize("name,body", [
        ("x [Security]", ""), ("x", "[BREAKFIX]"), ("x", "plain"), ("", "[breakfix] [security]"),
    ])
    def test_marker_rule_matches_box_side_rule(self, name, body):
        assert lint.classify_release(name, body) == _github_release_class(
            {"name": name, "body": body})


class TestCli:
    def test_check_writes_outputs_and_notes(self, tmp_path):
        files = _write_tree(tmp_path, "0.11.1", [("0.11.1", "breakfix")])
        out, notes = tmp_path / "gh_output", tmp_path / "notes.md"
        proc = _run("check", "--tag", "v0.11.1", "--releases", str(files["releases"]),
                    "--pyproject", str(files["pyproject"]),
                    "--github-output", str(out), "--notes-out", str(notes))
        assert proc.returncode == 0, proc.stderr
        assert "class=breakfix" in out.read_text()
        assert "title=v0.11.1 [breakfix]" in out.read_text()
        assert notes.read_text().startswith("[breakfix]")

    def test_check_failure_is_loud(self, tmp_path):
        files = _write_tree(tmp_path, "0.11.2", [("0.11.1", "feature")])
        proc = _run("check", "--tag", "v0.11.2", "--releases", str(files["releases"]),
                    "--pyproject", str(files["pyproject"]),
                    "--github-output", str(tmp_path / "o"), "--notes-out", str(tmp_path / "n"))
        assert proc.returncode == 1
        assert proc.stderr.startswith("ERROR:")

    def test_verify_reads_gh_release_view_json(self, tmp_path):
        view = tmp_path / "release.json"
        view.write_text(json.dumps({"name": "v0.11.1", "body": "* [breakfix] x",
                                    "tagName": "v0.11.1", "isDraft": True}))
        proc = _run("verify", "--release-json", str(view), "--class", "feature")
        assert proc.returncode == 1
        assert "breakfix" in proc.stderr

    def test_verify_passes(self, tmp_path):
        view = tmp_path / "release.json"
        view.write_text(json.dumps({"name": "v0.11.1 [security]", "body": "[security]",
                                    "tagName": "v0.11.1", "isDraft": True}))
        proc = _run("verify", "--release-json", str(view), "--class", "security")
        assert proc.returncode == 0, proc.stderr


class TestWorkflowWiring:
    """release.yml must gate on the lint before building and publish only a
    verified release."""

    @staticmethod
    def _steps() -> list[dict]:
        import yaml
        workflow = yaml.safe_load((REPO / ".github" / "workflows" / "release.yml").read_text())
        return [step for job in workflow["jobs"].values() for step in job["steps"]]

    def _index(self, steps: list[dict], needle: str) -> int:
        hits = [i for i, s in enumerate(steps) if needle in (s.get("run") or "")]
        assert hits, f"no release.yml step runs {needle!r}"
        return hits[0]

    def test_lint_runs_before_build(self):
        steps = self._steps()
        assert self._index(steps, "release-lint.py check") < self._index(steps, "make installer")

    def test_release_is_drafted_verified_then_published(self):
        steps = self._steps()
        create = next(i for i, s in enumerate(steps)
                      if "action-gh-release" in (s.get("uses") or ""))
        assert steps[create]["with"]["draft"] is True
        assert "release-preamble.md" in steps[create]["with"]["body_path"]
        verify = self._index(steps, "release-lint.py verify")
        publish = self._index(steps, "--draft=false")
        assert create < verify < publish


class TestWorkflowPrivileges:
    """F-11 / D-34: build without write or OIDC tokens; any signing failure
    fails the workflow instead of publishing an unsigned release."""

    @staticmethod
    def _workflow() -> dict:
        import yaml
        return yaml.safe_load((REPO / ".github" / "workflows" / "release.yml").read_text())

    def test_top_level_permissions_are_read_only(self):
        assert self._workflow()["permissions"] == {"contents": "read"}

    def test_job_that_runs_third_party_code_is_read_only(self):
        jobs = self._workflow()["jobs"]
        for name, job in jobs.items():
            runs = " ".join(s.get("run") or "" for s in job["steps"])
            if "pip install" in runs or "pytest" in runs:
                assert job["permissions"] == {"contents": "read"}, name

    def test_only_the_publish_job_holds_write_and_oidc(self):
        jobs = self._workflow()["jobs"]
        privileged = [n for n, j in jobs.items()
                      if j.get("permissions", {}).get("id-token") == "write"
                      or j.get("permissions", {}).get("contents") == "write"]
        assert privileged == ["publish"]
        assert jobs["publish"]["needs"] == "build"

    def test_no_step_may_fail_softly(self):
        for job in self._workflow()["jobs"].values():
            for step in job["steps"]:
                assert "continue-on-error" not in step, step.get("name")
                assert "if" not in step, step.get("name")

    def test_signing_precedes_release_and_all_files_required(self):
        steps = self._workflow()["jobs"]["publish"]["steps"]
        sign = next(i for i, s in enumerate(steps) if "cosign sign-blob" in (s.get("run") or ""))
        create = next(i for i, s in enumerate(steps)
                      if "action-gh-release" in (s.get("uses") or ""))
        assert sign < create
        assert steps[create]["with"]["fail_on_unmatched_files"] is True
