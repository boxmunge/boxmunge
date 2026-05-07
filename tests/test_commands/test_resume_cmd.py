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


class TestResumeRefusesQuarantined:
    """Wave 1: the pause-resume command must NOT silently un-quarantine.
    Quarantine lift is owned by `boxmunge security resume`, which re-scans
    first."""

    @patch("boxmunge.commands.resume_cmd.compose_pull")
    @patch("boxmunge.commands.resume_cmd.compose_up")
    @patch("boxmunge.commands.resume_cmd.caddy_reload")
    def test_refuses_quarantined_project(
        self, _reload, mock_up, mock_pull, tmp_path, capsys,
    ):
        from boxmunge.commands.resume_cmd import run_resume
        paths, name = _setup_paused(tmp_path)
        # Mark quarantined alongside paused.
        paths.project_quarantine_state(name).parent.mkdir(
            parents=True, exist_ok=True,
        )
        paths.project_quarantine_state(name).write_text("{}")
        rc = run_resume(name, paths, yes=True)
        assert rc == 1
        err = capsys.readouterr().err
        assert "quarantine" in err.lower()
        assert "security resume" in err
        # Mutating side effects MUST NOT have run.
        mock_pull.assert_not_called()
        mock_up.assert_not_called()


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

    @patch("boxmunge.commands.resume_cmd.prepare_compose_override")
    @patch("boxmunge.commands.resume_cmd.prepare_caddy_config")
    @patch("boxmunge.commands.resume_cmd.compose_pull")
    @patch("boxmunge.commands.resume_cmd.compose_up")
    @patch("boxmunge.commands.resume_cmd.caddy_reload")
    @patch("boxmunge.commands.resume_cmd.run_smoke")
    @patch("boxmunge.commands.resume_cmd.send_notification")
    def test_pushover_send_failures_logged_not_swallowed(
        self, mock_send, mock_smoke, _reload, _up, _pull,
        _caddy, _override, tmp_path,
    ):
        """ConfigError / OSError / KeyError during the post-smoke-fail
        Pushover path must be logged via log_warning. AttributeError
        (programming error) must propagate."""
        from boxmunge.commands.resume_cmd import run_resume
        from boxmunge.config import ConfigError
        import pytest

        from boxmunge.pause import write_paused_state

        paths, name = _setup_paused(tmp_path)
        mock_smoke.return_value = (False, "smoke went wrong")

        for exc in (ConfigError("bad"), OSError("disk"), KeyError("x")):
            write_paused_state(name, paths)
            mock_send.reset_mock()
            mock_send.side_effect = exc
            with patch("boxmunge.commands.resume_cmd.log_warning") as mw:
                rc = run_resume(name, paths, yes=True,
                                skip_security_checks=True)
                assert rc == 0
                pushover_logs = [
                    c for c in mw.call_args_list
                    if "Pushover" in c.args[1]
                ]
                assert len(pushover_logs) == 1, (
                    f"expected log_warning for Pushover failure "
                    f"({type(exc).__name__}); got {mw.call_args_list}"
                )

        # AttributeError must propagate.
        write_paused_state(name, paths)
        mock_send.reset_mock()
        mock_send.side_effect = AttributeError("typo")
        with pytest.raises(AttributeError):
            run_resume(name, paths, yes=True, skip_security_checks=True)

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


class TestResumeValidatesBeforeUp:
    """A-NEW-1: resume must validate user compose.yml BEFORE compose_pull
    and BEFORE compose_up. A hostile compose.yml introduced while paused
    must not start the privileged container before the validator rejects.
    """

    @patch("boxmunge.commands.resume_cmd.prepare_compose_override")
    @patch("boxmunge.commands.resume_cmd.prepare_caddy_config")
    @patch("boxmunge.commands.resume_cmd.compose_pull")
    @patch("boxmunge.commands.resume_cmd.compose_up")
    @patch("boxmunge.commands.resume_cmd.caddy_reload")
    @patch("boxmunge.commands.resume_cmd.run_smoke")
    def test_hostile_compose_blocks_before_compose_up(
        self, mock_smoke, _reload, mock_up, mock_pull, _caddy, _override, tmp_path,
    ):
        mock_smoke.return_value = (True, "ok")
        from boxmunge.commands.resume_cmd import run_resume
        from boxmunge.pause import is_paused
        paths, name = _setup_paused(tmp_path)
        # Replace compose.yml with a hostile one (privileged: true).
        (paths.project_dir(name) / "compose.yml").write_text(
            "services:\n  web:\n    image: nginx\n    privileged: true\n"
        )
        rc = run_resume(name, paths, yes=True)
        # Audit H-N2: hardening rejection is exit code 3, not generic 1.
        assert rc == 3
        # Critical: neither compose_pull nor compose_up may run on a hostile
        # compose.yml. Resume must reject before any container action.
        mock_pull.assert_not_called()
        mock_up.assert_not_called()
        # Project remains paused — resume bailed out clean.
        assert is_paused(name, paths)

    @patch("boxmunge.commands.resume_cmd.prepare_compose_override")
    @patch("boxmunge.commands.resume_cmd.prepare_caddy_config")
    @patch("boxmunge.commands.resume_cmd.compose_pull")
    @patch("boxmunge.commands.resume_cmd.compose_up")
    @patch("boxmunge.commands.resume_cmd.caddy_reload")
    @patch("boxmunge.commands.resume_cmd.run_smoke")
    def test_validate_runs_before_pull_and_up_call_order(
        self, mock_smoke, _reload, mock_up, mock_pull, _caddy, _override, tmp_path,
    ):
        """Assert ordering: validate -> pull -> up (validate is first)."""
        mock_smoke.return_value = (True, "ok")
        from boxmunge.commands.resume_cmd import run_resume

        paths, name = _setup_paused(tmp_path)

        order: list[str] = []
        mock_pull.side_effect = lambda *a, **kw: order.append("pull")
        mock_up.side_effect = lambda *a, **kw: order.append("up")

        with patch(
            "boxmunge.commands.resume_cmd.validate_user_compose"
        ) as mock_validate:
            mock_validate.side_effect = lambda *a, **kw: order.append("validate")
            rc = run_resume(name, paths, yes=True)

        assert rc == 0
        assert order[0] == "validate", (
            f"validate must run before pull/up — order: {order}"
        )
        assert "pull" in order and "up" in order
        assert order.index("validate") < order.index("pull")
        assert order.index("validate") < order.index("up")


class TestCvePolicyValidatorWiring:
    """C-1 regression: resume_cmd must pass the manifest's `security` block
    as `cve_policy` to validate_user_compose. Mirrors the deploy.py canonical
    test in test_deploy.py::TestCvePolicyValidatorWiring.
    """

    def _setup_paused_with_security(self, tmp_path: Path) -> tuple[BoxPaths, str]:
        """Same as _setup_paused, but with manifest.security.posture=strict
        and read_only on every service so validate_user_compose passes its
        cross-validators (we still mock it, but want the wiring real)."""
        paths = BoxPaths(root=tmp_path / "bm")
        for d in ["config", "projects/myapp", "state/deploy",
                  "state/health", "caddy/sites", "logs"]:
            (paths.root / d).mkdir(parents=True, exist_ok=True)
        paths.config_file.write_text("hostname: t\nadmin_email: a@b\n")
        (paths.project_dir("myapp") / "manifest.yml").write_text(yaml.dump({
            "schema_version": 2, "id": "01TEST", "project": "myapp",
            "source": "bundle", "hosts": ["myapp.test"],
            "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
            "security": {"posture": "strict"},
        }))
        (paths.project_dir("myapp") / "compose.yml").write_text(
            "services:\n  web:\n    image: nginx:1.25\n    read_only: true\n"
        )
        paths.project_caddy_site("myapp").write_text("# maintenance fragment\n")
        from boxmunge.pause import write_paused_state
        write_paused_state("myapp", paths)
        return paths, "myapp"

    @patch("boxmunge.commands.resume_cmd.prepare_compose_override")
    @patch("boxmunge.commands.resume_cmd.prepare_caddy_config")
    @patch("boxmunge.commands.resume_cmd.compose_pull")
    @patch("boxmunge.commands.resume_cmd.compose_up")
    @patch("boxmunge.commands.resume_cmd.caddy_reload")
    @patch("boxmunge.commands.resume_cmd.run_smoke")
    def test_resume_passes_security_block_as_cve_policy(
        self, mock_smoke, _reload, _up, _pull, _caddy, _override, tmp_path,
    ):
        mock_smoke.return_value = (True, "ok")
        from boxmunge.commands.resume_cmd import run_resume
        paths, name = self._setup_paused_with_security(tmp_path)
        with patch(
            "boxmunge.commands.resume_cmd.validate_user_compose",
        ) as mock_validate:
            run_resume(name, paths, yes=True)
        kwargs = mock_validate.call_args.kwargs
        assert kwargs.get("cve_policy") == {"posture": "strict"}, (
            f"validate_user_compose called with cve_policy="
            f"{kwargs.get('cve_policy')!r}; expected manifest's security block"
        )
