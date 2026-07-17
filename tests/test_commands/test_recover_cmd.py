"""Tests for boxmunge recover — un-stop a health-monitor-stopped prod."""
from pathlib import Path
from unittest.mock import patch
import yaml

from boxmunge.paths import BoxPaths
from boxmunge.state import read_state, write_state


def _setup(tmp_path: Path, *, status: str = "critical_stopped") -> tuple[BoxPaths, str]:
    paths = BoxPaths(root=tmp_path / "bm")
    for d in ["config", "projects/myapp", "state/deploy",
              "state/health", "caddy/sites", "logs"]:
        (paths.root / d).mkdir(parents=True, exist_ok=True)
    paths.config_file.write_text("hostname: t\nadmin_email: a@b\n")
    (paths.project_dir("myapp") / "manifest.yml").write_text(yaml.dump({
        "schema_version": 1, "id": "01TEST", "project": "myapp",
        "source": "bundle", "hosts": ["myapp.test"],
        "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
    }))
    (paths.project_dir("myapp") / "compose.yml").write_text(
        "services:\n  web:\n    image: nginx:1.25\n"
    )
    paths.project_caddy_site("myapp").write_text("# site\n")
    if status:
        write_state(paths.project_health_state("myapp"), {
            "status": status,
            "failure_reason": "smoke could not run",
            "consecutive_failures": 1,
            "alerted": True,
        })
    return paths, "myapp"


def _patched(fn):
    # Applied innermost-first so the mock arg order matches the test signature
    # (run_smoke -> first arg, ... prepare_compose_override -> last arg).
    for target in (
        "boxmunge.commands.recover_cmd.run_smoke",
        "boxmunge.commands.recover_cmd.caddy_reload",
        "boxmunge.commands.recover_cmd.compose_up",
        "boxmunge.commands.recover_cmd.prepare_caddy_config",
        "boxmunge.commands.recover_cmd.prepare_compose_override",
    ):
        fn = patch(target)(fn)
    return fn


class TestRunRecover:
    @_patched
    def test_recovers_monitor_stopped_prod(
        self, mock_smoke, _reload, _up, _caddy, _override, tmp_path,
    ):
        mock_smoke.return_value = (True, "ok")
        from boxmunge.commands.recover_cmd import run_recover
        paths, name = _setup(tmp_path)
        rc = run_recover(name, paths, yes=True)
        assert rc == 0
        _up.assert_called_once()
        # Health state reset to ok so `status` no longer shows CRITICAL (stopped).
        assert read_state(paths.project_health_state(name))["status"] == "ok"

    @_patched
    def test_does_not_pull_or_rebuild_images(
        self, mock_smoke, _reload, mock_up, _caddy, _override, tmp_path,
    ):
        """Recover restores the exact stopped build — it must not pull latest
        images (that would silently change what prod runs)."""
        mock_smoke.return_value = (True, "ok")
        from boxmunge.commands import recover_cmd
        # The module must not even import compose_pull into its namespace.
        assert not hasattr(recover_cmd, "compose_pull")
        paths, name = _setup(tmp_path)
        rc = recover_cmd.run_recover(name, paths, yes=True)
        assert rc == 0
        # compose_up called without a --build / pull flag.
        _, kwargs = mock_up.call_args
        assert "build" not in kwargs

    @_patched
    def test_refuses_when_not_stopped(
        self, mock_smoke, _reload, _up, _caddy, _override, tmp_path, capsys,
    ):
        mock_smoke.return_value = (True, "ok")
        from boxmunge.commands.recover_cmd import run_recover
        paths, name = _setup(tmp_path, status="ok")
        rc = run_recover(name, paths, yes=True)
        assert rc == 1
        assert "not" in capsys.readouterr().err.lower()
        _up.assert_not_called()

    @_patched
    def test_refuses_when_paused_points_to_resume(
        self, mock_smoke, _reload, _up, _caddy, _override, tmp_path, capsys,
    ):
        mock_smoke.return_value = (True, "ok")
        from boxmunge.commands.recover_cmd import run_recover
        paths, name = _setup(tmp_path, status="")
        from boxmunge.pause import write_paused_state
        write_paused_state(name, paths)
        rc = run_recover(name, paths, yes=True)
        assert rc == 1
        assert "resume" in capsys.readouterr().err.lower()
        _up.assert_not_called()

    @_patched
    def test_smoke_fail_leaves_project_up(
        self, mock_smoke, _reload, _up, _caddy, _override, tmp_path,
    ):
        mock_smoke.return_value = (False, "still failing")
        from boxmunge.commands.recover_cmd import run_recover
        paths, name = _setup(tmp_path)
        rc = run_recover(name, paths, yes=True)
        # Started, but honestly reports the smoke failure (non-zero).
        _up.assert_called_once()
        assert rc == 1
