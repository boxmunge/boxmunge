"""Tests for boxmunge validate command."""

import json
import pytest

from boxmunge.commands.validate import run_validate, cmd_validate
from boxmunge.paths import BoxPaths


VALID_MANIFEST = """\
id: 01TESTULID0000000000000000
source: bundle
project: myapp
repo: git@github.com:org/myapp.git
ref: main
hosts:
  - myapp.example.com
services:
  frontend:
    type: frontend
    port: 3000
    routes:
      - path: /
    smoke: boxmunge-scripts/smoke.sh
backup:
  type: none
"""


def _setup_project(paths: BoxPaths, name: str, manifest: str) -> None:
    project_dir = paths.project_dir(name)
    project_dir.mkdir(parents=True)
    (project_dir / "manifest.yml").write_text(manifest)
    (project_dir / "project.env").write_text("KEY=value\n")
    (project_dir / "compose.yml").write_text("services:\n  frontend:\n    image: nginx\n")
    (project_dir / "boxmunge-scripts").mkdir()
    (project_dir / "boxmunge-scripts" / "smoke.sh").write_text("#!/bin/sh\n")


class TestValidate:
    def test_valid_project_returns_zero(self, paths: BoxPaths) -> None:
        _setup_project(paths, "myapp", VALID_MANIFEST)
        exit_code = run_validate("myapp", paths)
        assert exit_code == 0

    def test_undeclared_compose_service_warns(self, paths: BoxPaths, capsys) -> None:
        _setup_project(paths, "myapp", VALID_MANIFEST)
        (paths.project_dir("myapp") / "compose.yml").write_text(
            "services:\n  frontend:\n    image: nginx\n  db:\n    image: postgres\n"
        )
        assert run_validate("myapp", paths) == 0
        out = capsys.readouterr().out
        assert "WARN:  myapp/db is in compose.yml but not declared" in out

    def test_missing_project_returns_one(self, paths: BoxPaths) -> None:
        exit_code = run_validate("nope", paths)
        assert exit_code == 1

    def test_invalid_manifest_returns_one(self, paths: BoxPaths) -> None:
        bad = VALID_MANIFEST.replace("hosts:\n  - myapp.example.com", "hosts: []")
        _setup_project(paths, "myapp", bad)
        exit_code = run_validate("myapp", paths)
        assert exit_code == 1

    def test_an_env_files_key_is_warned_as_ignored(self, paths: BoxPaths, capsys) -> None:
        _setup_project(paths, "myapp", VALID_MANIFEST + "env_files:\n  - other.env\n")
        assert run_validate("myapp", paths) == 0  # existing manifests keep validating
        out = capsys.readouterr().out
        assert "VALID (with warnings)" in out
        assert "manifest key 'env_files' is ignored" in out
        assert "remove the key" in out

    def test_a_strict_posture_without_read_only_is_refused_as_deploy_refuses_it(
            self, paths: BoxPaths, capsys) -> None:
        """validate runs deploy's compose checks: the same message, exit 3."""
        _setup_project(paths, "myapp", "schema_version: 3\n" + VALID_MANIFEST
                       + "security:\n  posture: strict\n")
        (paths.project_dir("myapp") / "compose.yml").write_text(
            "services:\n  frontend:\n    image: nginx\n    read_only: false\n")
        assert run_validate("myapp", paths) == 3
        captured = capsys.readouterr()
        assert "myapp: INVALID" in captured.out
        assert "posture 'strict' requires read_only: true" in captured.err

    def test_a_missing_smoke_script_is_an_error(self, paths: BoxPaths, capsys) -> None:
        _setup_project(paths, "myapp", VALID_MANIFEST)
        (paths.project_dir("myapp") / "boxmunge-scripts" / "smoke.sh").unlink()
        assert run_validate("myapp", paths) == 1
        err = capsys.readouterr().err
        assert "smoke 'boxmunge-scripts/smoke.sh' runs /boxmunge-scripts/smoke.sh" in err
        assert "upload a new bundle" in err

    def test_a_git_projects_scripts_are_read_from_its_repository(
            self, paths: BoxPaths, capsys) -> None:
        """Before its next checkout installs them, the commit's scripts count."""
        _setup_project(paths, "myapp", VALID_MANIFEST)
        project_dir = paths.project_dir("myapp")
        (project_dir / "boxmunge-scripts" / "smoke.sh").unlink()
        (project_dir / "boxmunge-scripts").rmdir()
        (project_dir / "repo").mkdir()
        assert run_validate("myapp", paths) == 1
        assert "the repository has no boxmunge-scripts/smoke.sh" in capsys.readouterr().err
        (project_dir / "repo" / "boxmunge-scripts").mkdir()
        (project_dir / "repo" / "boxmunge-scripts" / "smoke.sh").write_text("#!/bin/sh\n")
        assert run_validate("myapp", paths) == 0

    def test_a_missing_compose_file_is_an_error(self, paths: BoxPaths, capsys) -> None:
        _setup_project(paths, "myapp", VALID_MANIFEST)
        (paths.project_dir("myapp") / "compose.yml").unlink()
        assert run_validate("myapp", paths) == 1
        assert "Compose file missing: compose.yml" in capsys.readouterr().err

    def test_pre_registered_returns_error(self, paths: BoxPaths, capsys) -> None:
        pdir = paths.project_dir("myapp")
        pdir.mkdir(parents=True)
        (pdir / "secrets.env").write_text("KEY=val\n")

        exit_code = run_validate("myapp", paths)
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "pre-registered" in captured.err
        assert "boxmunge prod-deploy myapp" in captured.err


class TestValidateJson:
    """Audit H-3: `boxmunge validate <project> --json` for agents."""

    def test_json_valid_project(
        self, paths: BoxPaths, capsys, monkeypatch,
    ) -> None:
        _setup_project(paths, "myapp", VALID_MANIFEST)
        monkeypatch.setattr(
            "boxmunge.commands.validate.BoxPaths", lambda: paths,
        )
        with pytest.raises(SystemExit) as exc:
            cmd_validate(["myapp", "--json"])
        assert exc.value.code == 0
        payload = json.loads(capsys.readouterr().out)
        # Manifest may produce non-blocking warnings (e.g. resource limits);
        # the contract is "valid + errors empty" — warnings just travel.
        assert payload["project"] == "myapp"
        assert payload["valid"] is True
        assert payload["errors"] == []
        assert isinstance(payload["warnings"], list)

    def test_json_invalid_project(
        self, paths: BoxPaths, capsys, monkeypatch,
    ) -> None:
        bad = VALID_MANIFEST.replace(
            "hosts:\n  - myapp.example.com", "hosts: []",
        )
        _setup_project(paths, "myapp", bad)
        monkeypatch.setattr(
            "boxmunge.commands.validate.BoxPaths", lambda: paths,
        )
        with pytest.raises(SystemExit) as exc:
            cmd_validate(["myapp", "--json"])
        assert exc.value.code == 1
        payload = json.loads(capsys.readouterr().out)
        assert payload["project"] == "myapp"
        assert payload["valid"] is False
        assert payload["errors"]


class TestValidateUnknownArg:
    """Audit H-N1: cmd_validate rejects unknown flags."""

    def test_unknown_flag_exits_2(self, capsys) -> None:
        from boxmunge.commands.validate import cmd_validate
        with pytest.raises(SystemExit) as exc:
            cmd_validate(["myapp", "--not-a-flag"])
        assert exc.value.code == 2
        err = capsys.readouterr().err
        assert "ERROR" in err
        assert "--not-a-flag" in err
