# SPDX-License-Identifier: Apache-2.0
"""scripts/release-lint.py and upgrade notes: `check` refuses a release
without valid notes, and `upgrade-notes` compiles the upgrade-notes.json the
release workflow signs and publishes."""
from __future__ import annotations

import json
import subprocess
import sys
import tomllib

import pytest

from boxmunge import upgrade_floor
from boxmunge.upgrade_notes import ReleaseInfo, parse_notes
from tests.release_lint_helpers import REPO, SCRIPT, lint, write_notes, write_tree

RELEASES = [("0.11.0", "feature", True), ("0.11.8", "breakfix"), ("0.12.0", "feature", True)]
ENTRY = {"id": "0.12.0-python-floor", "scope": "box", "when": "before", "kind": "required",
         "title": "Python 3.13", "change": "Upgrade the host to Debian 13.",
         "verify": "python3 --version prints 3.13", "files": [], "superseded_by": None,
         "refs": ["#231"]}


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(SCRIPT), *args],
                          capture_output=True, text=True, check=False)


def _tree(tmp_path) -> dict:
    files = write_tree(tmp_path, "0.12.0", RELEASES)
    write_notes(files["notes"], "0.11.8")
    return files


def _check(files: dict, tmp_path) -> subprocess.CompletedProcess:
    return _run("check", "--tag", "v0.12.0", "--releases", str(files["releases"]),
                "--pyproject", str(files["pyproject"]), "--notes-dir", str(files["notes"]),
                "--floor-module", str(files["floor"]),
                "--github-output", str(tmp_path / "o"), "--notes-out", str(tmp_path / "n"))


def _compile(files: dict, out, tag: str = "v0.12.0") -> subprocess.CompletedProcess:
    return _run("upgrade-notes", "--tag", tag, "--out", str(out),
                "--notes-dir", str(files["notes"]), "--releases", str(files["releases"]),
                "--floor-module", str(files["floor"]))


class TestCheck:
    def test_check_passes_with_notes(self, tmp_path):
        proc = _check(_tree(tmp_path), tmp_path)
        assert proc.returncode == 0, proc.stderr
        assert "upgrade notes" in proc.stdout

    def test_check_refuses_a_release_with_no_notes_file(self, tmp_path):
        files = _tree(tmp_path)
        (files["notes"] / "0.12.0.json").unlink()
        proc = _check(files, tmp_path)
        assert proc.returncode == 1
        assert proc.stderr.startswith("ERROR: no upgrade-notes/0.12.0.json")
        assert "entries" in proc.stderr and '"no_project_action": true' in proc.stderr
        assert not (tmp_path / "o").exists(), "outputs written for a refused release"

    @pytest.mark.parametrize("version", ["0.11.8", "0.12.0", "0.12.1"])
    def test_check_validates_every_notes_file(self, tmp_path, version):
        """Earlier files, the release's own, and later ones (a release cut
        while the next one's entries are being written)."""
        files = _tree(tmp_path)
        write_notes(files["notes"], version, {"version": version, "no_project_action": False,
                                              "entries": [dict(ENTRY, id=f"{version}-x",
                                                               kind="maybe")]})
        proc = _check(files, tmp_path)
        assert proc.returncode == 1
        assert f"upgrade-notes/{version}.json" in proc.stderr and "kind" in proc.stderr

    def test_check_refuses_a_floor_module_without_the_constants(self, tmp_path):
        files = _tree(tmp_path)
        files["floor"].write_text('UPGRADE_FLOOR = "0.11.0"\n')
        proc = _check(files, tmp_path)
        assert proc.returncode == 1 and "BRIDGE_RELEASE" in proc.stderr


class TestUpgradeNotesSubcommand:
    def test_upgrade_notes_subcommand_writes_compiled_doc(self, tmp_path):
        # The repository's floor module, as the workflow runs it, so the
        # release is one above any floor the repository will set.
        files = write_tree(tmp_path, "99.0.0", [("99.0.0", "feature", True)])
        write_notes(files["notes"], "99.0.0", {"version": "99.0.0", "no_project_action": False,
                                               "entries": [dict(ENTRY, id="99.0.0-x")]})
        out = tmp_path / "dist" / "upgrade-notes.json"
        out.parent.mkdir()
        proc = _run("upgrade-notes", "--tag", "v99.0.0", "--out", str(out),
                    "--notes-dir", str(files["notes"]), "--releases", str(files["releases"]))
        assert proc.returncode == 0, proc.stderr
        notes = parse_notes(json.loads(out.read_bytes()))
        assert (notes.floor, notes.bridge) == (upgrade_floor.UPGRADE_FLOOR,
                                               upgrade_floor.BRIDGE_RELEASE)
        assert notes.release == "99.0.0" and notes.no_action == ()
        assert [e.id for e in notes.entries] == ["99.0.0-x"]
        assert notes.releases == {"99.0.0": ReleaseInfo("feature", True)}

    @pytest.mark.parametrize("tag", ["0.12.0", "v0.12", "v0.12.0-rc.1"])
    def test_refuses_a_bad_tag(self, tmp_path, tag):
        out = tmp_path / "upgrade-notes.json"
        proc = _compile(_tree(tmp_path), out, tag=tag)
        assert proc.returncode == 1 and "tag" in proc.stderr
        assert not out.exists()

    def test_failure_is_loud_and_writes_nothing(self, tmp_path):
        files = _tree(tmp_path)
        (files["notes"] / "0.12.0.json").unlink()
        out = tmp_path / "upgrade-notes.json"
        proc = _compile(files, out)
        assert proc.returncode == 1 and proc.stderr.startswith("ERROR:")
        assert not out.exists()

    def test_output_is_deterministic(self, tmp_path):
        files = _tree(tmp_path)
        first, second = tmp_path / "a.json", tmp_path / "b.json"
        assert _compile(files, first).returncode == 0
        assert _compile(files, second).returncode == 0
        assert first.read_bytes() == second.read_bytes()


def test_floor_regex_matches_the_module():
    assert lint.floor_values(lint.FLOOR_MODULE) == (upgrade_floor.UPGRADE_FLOOR,
                                                    upgrade_floor.BRIDGE_RELEASE)


def test_repository_notes_compile_for_the_pyproject_version():
    """What `check` will run when this version is tagged."""
    version = tomllib.loads((REPO / "pyproject.toml").read_text())["project"]["version"]
    doc = json.loads(lint.compiled_notes(version, lint.NOTES_DIR, lint.RELEASES_JSON,
                                         lint.FLOOR_MODULE))
    assert parse_notes(doc).release == version
