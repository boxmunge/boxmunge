# SPDX-License-Identifier: Apache-2.0
"""The release notes release.yml publishes: the preamble generated from
releases.json, then GitHub's generated changelog with every class marker a
PR title quotes neutralised, so a contributor's title can neither trip the
verify step nor reclassify a release for boxes on the GitHub fallback."""
from __future__ import annotations

import json
import subprocess
import sys

import pytest
import yaml

from tests.release_lint_helpers import REPO, SCRIPT, lint, write_tree

CHANGELOG = (
    "## What's Changed\n"
    "* [held] marker for the GitHub fallback by @dev in https://github.com/o/r/pull/158\n"
    "* [Security] tighten X by @dev in https://github.com/o/r/pull/159\n"
    "* [BREAKFIX] fix Y by @dev in https://github.com/o/r/pull/160\n"
    "* [breaKing] drop a flag (Kelvin sign) by @dev in https://github.com/o/r/pull/161\n"
    "* [docs] keep [this](https://example.invalid) as it is by @dev\n\n"
    "**Full Changelog**: https://github.com/o/r/compare/v0.11.4...v0.11.5\n"
)


class TestNeutraliseMarkers:
    @pytest.mark.parametrize("quoted,shown", [
        ("[held]", "(held)"), ("[Security]", "(Security)"), ("[BREAKFIX]", "(BREAKFIX)"),
        ("[breaking]", "(breaking)"), ("[breaKing]", "(breaKing)"),
    ])
    def test_a_quoted_marker_becomes_plain_text(self, quoted, shown):
        assert lint.neutralise_markers(f"* {quoted} title by @dev") == f"* {shown} title by @dev"

    def test_other_brackets_are_left_alone(self):
        text = "* [docs] keep [this](https://example.invalid) and [securityx] by @dev"
        assert lint.neutralise_markers(text) == text


class TestComposeNotes:
    @pytest.mark.parametrize("cls", ["security", "breakfix", "feature"])
    @pytest.mark.parametrize("breaking", [True, False])
    def test_composed_notes_verify_as_listed(self, tmp_path, cls, breaking):
        """The v0.11.5 failure: generated notes quoting a '[held] ...' PR
        title made verify refuse the draft."""
        files = write_tree(tmp_path, "0.12.0", [("0.12.0", cls, breaking)])
        plan = lint.plan_release("v0.12.0", files["releases"], files["pyproject"])
        notes = lint.compose_notes(plan.notes, CHANGELOG)
        lint.verify_release(plan.title, notes, cls, breaking)

    def test_preamble_first_and_kept_verbatim(self):
        notes = lint.compose_notes("[security] Security release.\n", CHANGELOG)
        assert notes.startswith("[security] Security release.\n\n## What's Changed\n")
        assert "(held) marker for the GitHub fallback" in notes
        assert "**Full Changelog**: https://github.com/o/r/compare/v0.11.4...v0.11.5" in notes

    def test_a_wrong_preamble_is_still_caught_by_verify(self):
        notes = lint.compose_notes("[security] Security release.\n", CHANGELOG)
        with pytest.raises(lint.ReleaseLintError, match="security"):
            lint.verify_release("v0.11.6", notes, "feature", False)
        notes = lint.compose_notes("[breaking] Breaking release.\n", CHANGELOG)
        with pytest.raises(lint.ReleaseLintError, match="breaking"):
            lint.verify_release("v0.11.6", notes, "feature", False)

    def test_a_wrong_title_is_still_caught_by_verify(self):
        notes = lint.compose_notes("Feature release.\n", CHANGELOG)
        with pytest.raises(lint.ReleaseLintError, match="security"):
            lint.verify_release("v0.11.6 [security]", notes, "feature", False)
        notes = lint.compose_notes("[security] Security release.\n", CHANGELOG)
        with pytest.raises(lint.ReleaseLintError, match="title"):
            lint.verify_release("v0.11.6", notes, "security", False)


class TestNotesCli:
    def test_notes_reads_the_generate_notes_answer(self, tmp_path):
        preamble, generated, out = (tmp_path / n for n in ("p.md", "g.json", "notes.md"))
        preamble.write_text("Feature release.\n")
        generated.write_text(json.dumps({"name": "v0.11.6", "body": CHANGELOG}))
        proc = subprocess.run([sys.executable, str(SCRIPT), "notes", "--preamble", str(preamble),
                               "--generated-json", str(generated), "--out", str(out)],
                              capture_output=True, text=True, check=False)
        assert proc.returncode == 0, proc.stderr
        assert out.read_text() == lint.compose_notes("Feature release.\n", CHANGELOG)

    def test_an_answer_without_a_body_is_refused(self, tmp_path):
        generated = tmp_path / "g.json"
        generated.write_text(json.dumps({"message": "Not Found"}))
        (tmp_path / "p.md").write_text("Feature release.\n")
        proc = subprocess.run([sys.executable, str(SCRIPT), "notes", "--preamble",
                               str(tmp_path / "p.md"), "--generated-json", str(generated),
                               "--out", str(tmp_path / "o.md")],
                              capture_output=True, text=True, check=False)
        assert proc.returncode == 1
        assert proc.stderr.startswith("ERROR:") and "body" in proc.stderr


class TestWorkflowComposesTheNotes:
    @staticmethod
    def _publish_steps() -> list[dict]:
        workflow = yaml.safe_load((REPO / ".github" / "workflows" / "release.yml").read_text())
        return workflow["jobs"]["publish"]["steps"]

    def _index(self, steps: list[dict], needle: str) -> int:
        hits = [i for i, s in enumerate(steps) if needle in (s.get("run") or "")]
        assert hits, f"no publish step runs {needle!r}"
        return hits[0]

    def test_notes_are_generated_then_neutralised_before_the_draft(self):
        steps = self._publish_steps()
        create = next(i for i, s in enumerate(steps)
                      if "action-gh-release" in (s.get("uses") or ""))
        generate = self._index(steps, "releases/generate-notes")
        compose = self._index(steps, "release-lint.py notes")
        assert generate < create and compose < create
        assert "--generated-json" in steps[compose]["run"]

    def test_the_draft_carries_only_the_composed_notes(self):
        steps = self._publish_steps()
        create = next(s for s in steps if "action-gh-release" in (s.get("uses") or ""))
        assert "generate_release_notes" not in create["with"]
        assert create["with"]["body_path"] == "dist/release-notes.md"
