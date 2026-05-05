"""Tests for boxmunge resume."""
from pathlib import Path
from unittest.mock import patch, MagicMock
import yaml

from boxmunge.paths import BoxPaths


def _setup_paused(tmp_path: Path, *, with_image_service: bool = True) -> tuple[BoxPaths, str]:
    paths = BoxPaths(root=tmp_path / "bm")
    for d in ["config", "projects/myapp", "state/deploy",
              "state/health", "caddy/sites", "logs"]:
        (paths.root / d).mkdir(parents=True, exist_ok=True)
    paths.config_file.write_text("hostname: t\nadmin_email: a@b\n")
    services: dict = {"web": {"port": 8080, "routes": [{"path": "/"}]}}
    (paths.project_dir("myapp") / "manifest.yml").write_text(yaml.dump({
        "schema_version": 1, "id": "01TEST", "project": "myapp",
        "source": "bundle", "hosts": ["myapp.test"],
        "services": services,
    }))
    if with_image_service:
        (paths.project_dir("myapp") / "compose.yml").write_text(
            "services:\n  web:\n    image: nginx:1.25\n"
        )
    else:
        (paths.project_dir("myapp") / "compose.yml").write_text(
            "services:\n  web:\n    build: .\n"
        )
    paths.project_caddy_site("myapp").write_text("# maintenance fragment\n")
    # Mark paused.
    from boxmunge.pause import write_paused_state
    write_paused_state("myapp", paths)
    return paths, "myapp"


class TestRunResume:
    @patch("boxmunge.commands.resume_cmd.prepare_compose_override")
    @patch("boxmunge.commands.resume_cmd.prepare_caddy_config")
    @patch("boxmunge.commands.resume_cmd.compose_pull")
    @patch("boxmunge.commands.resume_cmd.compose_up")
    @patch("boxmunge.commands.resume_cmd.caddy_reload")
    @patch("boxmunge.commands.resume_cmd.run_smoke")
    def test_clears_paused_state(self, mock_smoke, _reload, _up, _pull, _caddy, _override, tmp_path):
        mock_smoke.return_value = (True, "ok")
        from boxmunge.commands.resume_cmd import run_resume
        from boxmunge.pause import is_paused
        paths, name = _setup_paused(tmp_path)
        rc = run_resume(name, paths, yes=True)
        assert rc == 0
        assert not is_paused(name, paths)

    @patch("boxmunge.commands.resume_cmd.prepare_compose_override")
    @patch("boxmunge.commands.resume_cmd.prepare_caddy_config")
    @patch("boxmunge.commands.resume_cmd.compose_pull")
    @patch("boxmunge.commands.resume_cmd.compose_up")
    @patch("boxmunge.commands.resume_cmd.caddy_reload")
    @patch("boxmunge.commands.resume_cmd.run_smoke")
    def test_pulls_images_by_default(self, mock_smoke, _reload, _up, mock_pull, _caddy, _override, tmp_path):
        mock_smoke.return_value = (True, "ok")
        from boxmunge.commands.resume_cmd import run_resume
        paths, name = _setup_paused(tmp_path)
        run_resume(name, paths, yes=True)
        mock_pull.assert_called_once()

    @patch("boxmunge.commands.resume_cmd.prepare_compose_override")
    @patch("boxmunge.commands.resume_cmd.prepare_caddy_config")
    @patch("boxmunge.commands.resume_cmd.compose_pull")
    @patch("boxmunge.commands.resume_cmd.compose_up")
    @patch("boxmunge.commands.resume_cmd.caddy_reload")
    @patch("boxmunge.commands.resume_cmd.run_smoke")
    def test_skips_pull_when_no_image_services(self, mock_smoke, _reload, _up, mock_pull, _caddy, _override, tmp_path):
        mock_smoke.return_value = (True, "ok")
        from boxmunge.commands.resume_cmd import run_resume
        paths, name = _setup_paused(tmp_path, with_image_service=False)
        rc = run_resume(name, paths, yes=True)
        assert rc == 0
        mock_pull.assert_not_called()

    @patch("boxmunge.commands.resume_cmd.prepare_compose_override")
    @patch("boxmunge.commands.resume_cmd.prepare_caddy_config")
    @patch("boxmunge.commands.resume_cmd.compose_pull")
    @patch("boxmunge.commands.resume_cmd.compose_up")
    @patch("boxmunge.commands.resume_cmd.caddy_reload")
    @patch("boxmunge.commands.resume_cmd.run_smoke")
    def test_aborts_on_pull_failure(self, mock_smoke, _reload, _up, mock_pull, _caddy, _override, tmp_path):
        from boxmunge.docker import DockerError
        mock_pull.side_effect = DockerError("registry down")
        mock_smoke.return_value = (True, "ok")
        from boxmunge.commands.resume_cmd import run_resume
        from boxmunge.pause import is_paused
        paths, name = _setup_paused(tmp_path)
        rc = run_resume(name, paths, yes=True)
        assert rc == 1
        # Project remains paused (we aborted before swapping Caddy).
        assert is_paused(name, paths)

    def test_refuses_when_not_paused(self, tmp_path):
        from boxmunge.commands.resume_cmd import run_resume
        paths, name = _setup_paused(tmp_path)
        from boxmunge.pause import clear_paused_state
        clear_paused_state(name, paths)
        rc = run_resume(name, paths, yes=True)
        assert rc == 1

    def test_refuses_unknown_project(self, tmp_path):
        from boxmunge.commands.resume_cmd import run_resume
        paths, _ = _setup_paused(tmp_path)
        rc = run_resume("ghost", paths, yes=True)
        assert rc == 1


class TestSkipSecurityChecks:
    @patch("boxmunge.commands.resume_cmd.prepare_compose_override")
    @patch("boxmunge.commands.resume_cmd.prepare_caddy_config")
    @patch("boxmunge.commands.resume_cmd.compose_pull")
    @patch("boxmunge.commands.resume_cmd.compose_up")
    @patch("boxmunge.commands.resume_cmd.caddy_reload")
    @patch("boxmunge.commands.resume_cmd.run_smoke")
    def test_skip_flag_skips_pull(self, mock_smoke, _reload, _up, mock_pull, _caddy, _override, tmp_path):
        mock_smoke.return_value = (True, "ok")
        from boxmunge.commands.resume_cmd import run_resume
        paths, name = _setup_paused(tmp_path)
        run_resume(name, paths, yes=True, skip_security_checks=True)
        mock_pull.assert_not_called()

    @patch("boxmunge.commands.resume_cmd.prepare_compose_override")
    @patch("boxmunge.commands.resume_cmd.prepare_caddy_config")
    @patch("boxmunge.commands.resume_cmd.compose_pull")
    @patch("boxmunge.commands.resume_cmd.compose_up")
    @patch("boxmunge.commands.resume_cmd.caddy_reload")
    @patch("boxmunge.commands.resume_cmd.run_smoke")
    def test_skip_flag_still_runs_smoke(self, mock_smoke, _reload, _up, _pull, _caddy, _override, tmp_path):
        mock_smoke.return_value = (True, "ok")
        from boxmunge.commands.resume_cmd import run_resume
        paths, name = _setup_paused(tmp_path)
        run_resume(name, paths, yes=True, skip_security_checks=True)
        mock_smoke.assert_called_once()

    def test_cmd_resume_parses_skip_flag(self, tmp_path, monkeypatch):
        from boxmunge.commands.resume_cmd import cmd_resume
        called_with = {}
        monkeypatch.setattr(
            "boxmunge.commands.resume_cmd.run_resume",
            lambda *a, **kw: (called_with.update(kw), 0)[1],
        )
        import pytest
        with pytest.raises(SystemExit):
            cmd_resume(["myapp", "--skip-security-checks", "--yes"])
        assert called_with.get("skip_security_checks") is True
        assert called_with.get("yes") is True
