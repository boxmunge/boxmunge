# SPDX-License-Identifier: Apache-2.0
"""release.yml publishes upgrade-notes.json under the signed SHA256SUMS,
built in the publish job from the repository's own files."""
from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
BUILD_NOTES = "scripts/release-lint.py upgrade-notes"


def _jobs() -> dict:
    return yaml.safe_load((REPO / ".github" / "workflows" / "release.yml").read_text())["jobs"]


def _index(steps: list[dict], needle: str) -> int:
    hits = [i for i, s in enumerate(steps) if needle in (s.get("run") or "")]
    assert len(hits) == 1, f"expected one step running {needle!r}, found {len(hits)}"
    return hits[0]


def test_publish_job_builds_and_signs_upgrade_notes():
    jobs = _jobs()
    steps = jobs["publish"]["steps"]
    build = _index(steps, BUILD_NOTES)
    sign = _index(steps, "cosign sign-blob")
    assert build < sign, "the notes must exist before SHA256SUMS is computed and signed"
    run = " ".join(steps[build]["run"].split())
    assert '--tag "$GITHUB_REF_NAME"' in run and "--out dist/upgrade-notes.json" in run
    sums = re.search(r"sha256sum ([^>\n]+)> SHA256SUMS", steps[sign]["run"])
    assert sums and sums.group(1).split() == [
        "boxmunge-install.sh", "boxmunge-*.tar.gz", "upgrade-notes.json"]
    create = next(s for s in steps if "action-gh-release" in (s.get("uses") or ""))
    assert "dist/upgrade-notes.json" in create["with"]["files"].split()
    assert all(BUILD_NOTES not in (s.get("run") or "") for s in jobs["build"]["steps"]), \
        "build in publish only: a dependency the build job runs must not shape signed notes"


def test_build_job_lints_the_notes_before_building():
    """`release-lint.py check` compiles the notes with the repository's
    defaults, so a tag without valid notes fails before anything is built."""
    steps = _jobs()["build"]["steps"]
    check = steps[_index(steps, "release-lint.py check")]["run"]
    assert "--notes-dir" not in check and "--floor-module" not in check
    assert _index(steps, "release-lint.py check") < _index(steps, "make installer")
