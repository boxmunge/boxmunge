"""Tests for boxmunge promote command."""
import pytest
from unittest.mock import patch, MagicMock
from boxmunge.commands.promote_cmd import run_promote
from boxmunge.paths import BoxPaths
from boxmunge.state import write_state
from boxmunge.project_registry import add_project

VALID_MANIFEST = """\
id: 01TESTULID0000000000000000
source: bundle
project: testapp
hosts:
  - testapp.example.com
services:
  web:
    port: 8080
    routes:
      - path: /
backup:
  type: none
"""

class TestRunPromote:
    def _setup_staged(self, paths):
        pdir = paths.project_dir("testapp")
        pdir.mkdir(parents=True, exist_ok=True)
        (pdir / "manifest.yml").write_text(VALID_MANIFEST)
        (pdir / "compose.yml").write_text("services:\n  web:\n    image: nginx\n")
        paths.project_staging_compose_override("testapp").write_text(
            "networks:\n  boxmunge-proxy:\n    external: true\n")
        paths.project_staging_caddy_site("testapp").write_text(
            "staging.testapp.example.com {}\n")
        write_state(paths.project_staging_state("testapp"), {"active": True})

    @patch("boxmunge.commands.promote_cmd.run_deploy")
    @patch("boxmunge.commands.promote_cmd.run_unstage")
    def test_unstages_then_deploys(self, mock_unstage, mock_deploy, paths):
        self._setup_staged(paths)
        mock_unstage.return_value = 0
        mock_deploy.return_value = 0
        result = run_promote("testapp", paths)
        assert result == 0
        mock_unstage.assert_called_once()
        mock_deploy.assert_called_once()

    def test_fails_no_active_staging(self, paths):
        pdir = paths.project_dir("testapp")
        pdir.mkdir(parents=True, exist_ok=True)
        (pdir / "manifest.yml").write_text(VALID_MANIFEST)
        result = run_promote("testapp", paths)
        assert result == 1

    @patch("boxmunge.commands.promote_cmd.run_deploy")
    @patch("boxmunge.commands.promote_cmd.run_unstage")
    def test_deploys_to_production(self, mock_unstage, mock_deploy, paths):
        self._setup_staged(paths)
        mock_unstage.return_value = 0
        mock_deploy.return_value = 0
        run_promote("testapp", paths)
        deploy_call = mock_deploy.call_args
        assert deploy_call[0][0] == "testapp"


class TestRefusesPaused:
    def test_refuses_paused_project(self, paths, capsys):
        from boxmunge.pause import write_paused_state
        pdir = paths.project_dir("testapp")
        pdir.mkdir(parents=True, exist_ok=True)
        (pdir / "manifest.yml").write_text(VALID_MANIFEST)
        write_state(paths.project_staging_state("testapp"), {"active": True})
        write_paused_state("testapp", paths)
        rc = run_promote("testapp", paths)
        assert rc == 1
        err = capsys.readouterr().err
        assert "paused" in err.lower()


class TestRefusesQuarantined:
    """Wave 1: promote must refuse a CVE-quarantined project."""

    @patch("boxmunge.commands.promote_cmd.run_deploy")
    @patch("boxmunge.commands.promote_cmd.run_unstage")
    def test_refuses_quarantined_project(
        self, mock_unstage, mock_deploy, paths, capsys,
    ):
        pdir = paths.project_dir("testapp")
        pdir.mkdir(parents=True, exist_ok=True)
        (pdir / "manifest.yml").write_text(VALID_MANIFEST)
        write_state(paths.project_staging_state("testapp"), {"active": True})
        paths.project_quarantine_state("testapp").parent.mkdir(
            parents=True, exist_ok=True,
        )
        paths.project_quarantine_state("testapp").write_text("{}")
        rc = run_promote("testapp", paths)
        assert rc == 1
        err = capsys.readouterr().err
        assert "quarantine" in err.lower()
        assert "security resume" in err
        # Underlying mutating helpers MUST NOT have run.
        mock_deploy.assert_not_called()
        mock_unstage.assert_not_called()


class TestPromoteComponentTagging:
    """Audit G-1: promote must tag SECURITY OFF logs with component="promote".

    The promote -> run_deploy -> prepare_compose_override -> warn_off_services
    chain receives the component explicitly. Without the fix, warn_off_services
    sees component="deploy" and the SECURITY OFF entry is mis-attributed.
    """

    def test_promote_passes_component_to_run_deploy(self, paths) -> None:
        pdir = paths.project_dir("testapp")
        pdir.mkdir(parents=True, exist_ok=True)
        (pdir / "manifest.yml").write_text(VALID_MANIFEST)
        write_state(paths.project_staging_state("testapp"), {"active": True})

        with patch(
            "boxmunge.commands.promote_cmd.run_deploy",
        ) as mock_deploy, patch(
            "boxmunge.commands.promote_cmd.run_unstage",
        ) as mock_unstage:
            mock_deploy.return_value = 0
            mock_unstage.return_value = 0
            run_promote("testapp", paths)
        # The whole point of the audit fix: component="promote" is forwarded.
        assert mock_deploy.call_args.kwargs["component"] == "promote"

    def test_run_deploy_threads_component_to_compose_override(
        self, paths, monkeypatch,
    ) -> None:
        """Audit G-1 chain test: run_deploy(component='promote') flows the
        label through to prepare_compose_override (which passes it on to
        warn_off_services). We stub everything past the call to capture
        the component arg observed at the boundary.
        """
        from boxmunge.commands import deploy as deploy_mod

        pdir = paths.project_dir("testapp")
        pdir.mkdir(parents=True, exist_ok=True)
        (pdir / "manifest.yml").write_text(VALID_MANIFEST)
        (pdir / "compose.yml").write_text("services:\n  web:\n    image: nginx\n")
        add_project("testapp", paths)

        observed: list[str] = []

        def fake_prepare_compose_override(
            paths, manifest, component: str = "deploy",
        ) -> None:
            observed.append(component)

        # Stub side-effecting steps; we only care about the component plumbing.
        monkeypatch.setattr(deploy_mod, "prepare_caddy_config", lambda *a, **k: None)
        monkeypatch.setattr(
            deploy_mod, "prepare_compose_override", fake_prepare_compose_override,
        )
        monkeypatch.setattr(deploy_mod, "compose_up", lambda *a, **k: None)
        monkeypatch.setattr(deploy_mod, "caddy_reload", lambda *a, **k: None)
        # Avoid any git/snapshot work by passing no_snapshot=True and no ref.
        monkeypatch.setattr(deploy_mod.subprocess, "run", MagicMock(
            return_value=MagicMock(returncode=0, stdout="abc", stderr=""),
        ))

        from boxmunge.commands.deploy import run_deploy
        run_deploy(
            "testapp", paths, no_snapshot=True, _lock_held=True,
            component="promote",
        )
        assert observed == ["promote"]


class TestPromoteUnknownArg:
    """Audit H-N1: cmd_promote rejects unknown flags."""

    def test_unknown_flag_exits_2(self, capsys) -> None:
        import pytest
        from boxmunge.commands.promote_cmd import cmd_promote
        with pytest.raises(SystemExit) as exc:
            cmd_promote(["myapp", "--not-a-flag"])
        assert exc.value.code == 2
        err = capsys.readouterr().err
        assert "ERROR" in err
        assert "--not-a-flag" in err


class TestPromoteComposeRejectionExit3:
    """Audit H-N2: hardening rejection from underlying deploy returns 3."""

    @patch("boxmunge.commands.promote_cmd.run_deploy")
    @patch("boxmunge.commands.promote_cmd.run_unstage")
    def test_hardening_rejection_propagates_3(
        self, mock_unstage, mock_deploy, paths,
    ):
        # Reuse setup fixture from TestRunPromote.
        pdir = paths.project_dir("testapp")
        pdir.mkdir(parents=True, exist_ok=True)
        (pdir / "manifest.yml").write_text(VALID_MANIFEST)
        (pdir / "compose.yml").write_text("services:\n  web:\n    image: nginx\n")
        paths.project_staging_compose_override("testapp").write_text(
            "networks:\n  boxmunge-proxy:\n    external: true\n")
        paths.project_staging_caddy_site("testapp").write_text(
            "staging.testapp.example.com {}\n")
        write_state(paths.project_staging_state("testapp"), {"active": True})

        # Underlying deploy hits compose validation and returns 3.
        mock_deploy.return_value = 3
        result = run_promote("testapp", paths)
        assert result == 3
        # Unstage must NOT run — production is hostile, staging stays live.
        mock_unstage.assert_not_called()
