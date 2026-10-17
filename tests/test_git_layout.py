# SPDX-License-Identifier: Apache-2.0
"""Git projects whose links an older upgrade replaced are found and reported.

Upgrades before this fix renamed a migrated manifest over `<p>/manifest.yml`,
leaving a regular file where the link into `repo/` was. Such a project keeps
deploying that frozen copy. The upgrade (dry run and apply), `check` and
`doctor` say so, with the commands that put the links back.
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from boxmunge.commands.check import run_check
from boxmunge.commands.upgrade_steps import check_upgrade
from boxmunge.fileutil import project_lock
from boxmunge.git_layout import relink_advice, unlinked_files, unlinked_projects
from boxmunge.manifest import CURRENT_SCHEMA_VERSION, ManifestError, write_manifest
from boxmunge.paths import BoxPaths
from boxmunge.project_alerts import alert_state
from boxmunge.upgrade_exclusions import apply_projects

NAME = "gitapp"
MANIFEST = {
    "schema_version": CURRENT_SCHEMA_VERSION, "id": "01HZZZZZZZZZZZZZZZZZZZZZZZ",
    "project": NAME, "source": "git", "repo": "https://example.com/gitapp.git",
    "hosts": ["gitapp.example.com"],
    "services": {"web": {"port": 3000, "routes": [{"path": "/"}]}},
}


@pytest.fixture
def project(paths: BoxPaths) -> Path:
    """A git project laid out as add-git-project leaves it."""
    pdir = paths.project_dir(NAME)
    repo = pdir / "repo"
    repo.mkdir(parents=True)
    (repo / "manifest.yml").write_text(yaml.safe_dump(MANIFEST))
    (repo / "compose.yml").write_text("services:\n  web:\n    image: nginx:1.25\n")
    for name in ("manifest.yml", "compose.yml"):
        (pdir / name).symlink_to(repo / name)
    return pdir


def _damage(pdir: Path) -> None:
    """What an older upgrade did: a frozen regular copy over the link."""
    content = (pdir / "manifest.yml").read_text()
    (pdir / "manifest.yml").unlink()
    (pdir / "manifest.yml").write_text(content)


class TestDetection:
    def test_intact_layout(self, project: Path) -> None:
        assert unlinked_files(project, MANIFEST) == []

    def test_regular_file_is_unlinked(self, project: Path) -> None:
        _damage(project)
        assert unlinked_files(project, MANIFEST) == ["manifest.yml"]

    def test_link_outside_repo_is_unlinked(self, project: Path, tmp_path: Path) -> None:
        elsewhere = tmp_path / "elsewhere.yml"
        elsewhere.write_text("services: {}\n")
        (project / "compose.yml").unlink()
        (project / "compose.yml").symlink_to(elsewhere)
        assert unlinked_files(project, MANIFEST) == ["compose.yml"]

    def test_bundle_project_is_not_checked(self, project: Path) -> None:
        _damage(project)
        assert unlinked_files(project, {**MANIFEST, "source": "bundle"}) == []

    def test_git_manifest_without_checkout_is_not_checked(self, project: Path) -> None:
        _damage(project)
        (project / "compose.yml").unlink()
        subprocess.run(["rm", "-r", str(project / "repo")], check=True)
        assert unlinked_files(project, MANIFEST) == []

    def test_advice_commands_restore_the_layout(self, project: Path) -> None:
        _damage(project)
        advice = relink_advice(project, ["manifest.yml"])
        command = f"ln -sfn repo/manifest.yml {project}/manifest.yml"
        assert command in advice
        assert f"diff {project}/manifest.yml {project}/repo/manifest.yml" in advice
        subprocess.run(command, shell=True, check=True, cwd="/")
        assert unlinked_files(project, MANIFEST) == []

    def test_doctor_lists_damaged_projects(self, paths: BoxPaths, project: Path) -> None:
        assert unlinked_projects(paths) == {}
        _damage(project)
        assert "ln -sfn repo/manifest.yml" in unlinked_projects(paths)[NAME]

    def test_check_prints_the_fix(self, paths: BoxPaths, project: Path, capsys) -> None:
        _damage(project)
        run_check(NAME, paths)
        out = capsys.readouterr().out
        assert "git:      WARNING" in out and "ln -sfn repo/manifest.yml" in out


class TestUpgradeReports:
    def test_dry_run_warns(self, paths: BoxPaths, project: Path) -> None:
        _damage(project)
        report = check_upgrade(paths)
        assert any(line.startswith("WARNING") and "ln -sfn repo/manifest.yml" in line
                   for line in report)

    def test_apply_alerts_once_and_again_after_a_fix_breaks(
        self, paths: BoxPaths, project: Path,
    ) -> None:
        _damage(project)
        with patch("boxmunge.project_alerts.notify", return_value=True) as notify:
            result = apply_projects(paths)[0]
            apply_projects(paths)[0]
        assert "ln -sfn repo/manifest.yml" in result.unlinked[NAME]
        notify.assert_called_once()
        assert "ln -sfn repo/manifest.yml" in notify.call_args.args[2]

        subprocess.run(["ln", "-sfn", "repo/manifest.yml", str(project / "manifest.yml")],
                       check=True)
        with patch("boxmunge.project_alerts.notify", return_value=True) as notify:
            assert apply_projects(paths)[0].unlinked == {}
        notify.assert_not_called()
        assert not alert_state(paths, NAME, "git-layout").exists()

        _damage(project)
        with patch("boxmunge.project_alerts.notify", return_value=True) as notify:
            apply_projects(paths)[0]
        notify.assert_called_once()

    def test_absent_schema_version_alert_says_to_set_it(
        self, paths: BoxPaths, project: Path,
    ) -> None:
        bare = {k: v for k, v in MANIFEST.items() if k != "schema_version"}
        (project / "repo" / "manifest.yml").write_text(yaml.safe_dump(bare))
        with patch("boxmunge.project_alerts.notify", return_value=True) as notify:
            assert apply_projects(paths)[0].in_memory == [NAME]
        body = notify.call_args.args[2]
        assert "has no schema_version" in body
        assert f"Set schema_version: {CURRENT_SCHEMA_VERSION} in the repository" in body
        assert "migrates" not in body


class TestWriteGuards:
    def test_link_swapped_in_before_the_rename_is_refused(self, tmp_path: Path) -> None:
        path = tmp_path / "manifest.yml"
        path.write_text(yaml.safe_dump(MANIFEST))
        target = tmp_path / "repo-manifest.yml"
        target.write_text("# the repository's\n")

        def swap(fd: int, name: str) -> None:
            path.unlink()
            path.symlink_to(target)

        with patch("boxmunge.fileutil.fchown_deploy", side_effect=swap):
            with pytest.raises(ManifestError, match="is a symlink"):
                write_manifest(path, MANIFEST)
        assert path.is_symlink() and target.read_text() == "# the repository's\n"
        assert not list(tmp_path.glob(".manifest.*.tmp"))

    def test_migration_skips_a_locked_project(self, paths: BoxPaths) -> None:
        pdir = paths.project_dir("bundled")
        pdir.mkdir(parents=True)
        old = yaml.safe_dump({**MANIFEST, "project": "bundled", "source": "bundle",
                              "schema_version": 2})
        (pdir / "manifest.yml").write_text(old)
        with project_lock("bundled", paths):
            migration, _regen, excluded = apply_projects(paths)
        assert (migration.written, excluded.busy) == ([], ["bundled"])
        assert (pdir / "manifest.yml").read_text() == old
        assert apply_projects(paths)[0].written == ["bundled"]
