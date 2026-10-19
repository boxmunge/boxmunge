"""Tests for boxmunge promote command."""
import pytest
from unittest.mock import patch, MagicMock
from boxmunge.commands.promote_cmd import run_promote
from boxmunge.state import write_state
from boxmunge.project_registry import add_project
from tests.stage_helpers import prod_and_stage

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
    def test_fails_no_active_staging(self, paths, capsys):
        add_project("testapp", paths)
        pdir = paths.project_dir("testapp")
        pdir.mkdir(parents=True, exist_ok=True)
        (pdir / "manifest.yml").write_text(VALID_MANIFEST)
        result = run_promote("testapp", paths)
        assert result == 1
        assert "No staged release for 'testapp'" in capsys.readouterr().err


class TestRefusesPaused:
    def test_refuses_paused_project(self, paths, capsys):
        from boxmunge.pause import write_paused_state
        prod_and_stage(paths)
        write_paused_state("myapp", paths)
        rc = run_promote("myapp", paths)
        assert rc == 1
        err = capsys.readouterr().err
        assert "paused" in err.lower()


class TestQuarantinedPromote:
    """A quarantined project may promote a fix: the install core scans
    what it would start before the hook (quarantine_gate); a pause still
    refuses."""

    @patch("boxmunge.commands.promote_cmd.deploy_tree_locked", return_value=1)
    @patch("boxmunge.commands.promote_cmd.teardown_staging_locked")
    def test_quarantine_alone_reaches_the_install_core(
        self, mock_teardown, mock_deploy, paths, capsys,
    ):
        from tests.test_commands.cve_helpers import seed_quarantine
        prod_and_stage(paths)
        seed_quarantine(paths, "myapp")
        assert run_promote("myapp", paths) == 1
        assert "scanned before anything starts" in capsys.readouterr().out
        mock_deploy.assert_called_once()
        mock_teardown.assert_not_called()

    @patch("boxmunge.commands.promote_cmd.deploy_tree_locked")
    @patch("boxmunge.commands.promote_cmd.teardown_staging_locked")
    def test_paused_and_quarantined_is_refused(
        self, mock_teardown, mock_deploy, paths, capsys,
    ):
        from boxmunge.pause import write_paused_state
        from tests.test_commands.cve_helpers import seed_quarantine
        prod_and_stage(paths)
        seed_quarantine(paths, "myapp")
        write_paused_state("myapp", paths)
        assert run_promote("myapp", paths) == 1
        assert "paused and CVE-quarantined" in capsys.readouterr().err
        mock_deploy.assert_not_called()
        mock_teardown.assert_not_called()


class TestPromoteComponentTagging:
    """Audit G-1: promote must tag SECURITY OFF logs with component="promote".

    The promote -> deploy_locked -> prepare_compose_override -> warn_off_services
    chain receives the component explicitly. Without the fix, warn_off_services
    sees component="deploy" and the SECURITY OFF entry is mis-attributed.
    """

    def test_promote_passes_component_to_deploy(self, paths) -> None:
        from boxmunge.commands import release_config as deploy_mod
        from tests.stage_helpers import staging_docker_off as _docker
        prod_and_stage(paths)
        observed: list[str] = []
        real = deploy_mod.prepare_compose_override

        def recording(paths_, manifest, component="deploy", **kw):
            observed.append(component)
            return real(paths_, manifest, component=component, **kw)
        with _docker(), patch.object(deploy_mod, "prepare_compose_override", recording):
            assert run_promote("myapp", paths) == 0
        # The whole point of the audit fix: component="promote" is forwarded.
        assert observed == ["promote"]

    def test_deploy_threads_component_to_compose_override(
        self, paths, monkeypatch,
    ) -> None:
        """Audit G-1 chain test: deploy_locked(component='promote') flows the
        label through to prepare_compose_override (which passes it on to
        warn_off_services). We stub everything past the call to capture
        the component arg observed at the boundary.
        """
        from boxmunge.commands import deploy as deploy_cmd
        from boxmunge.commands import release_config as deploy_mod

        pdir = paths.project_dir("testapp")
        pdir.mkdir(parents=True, exist_ok=True)
        (pdir / "manifest.yml").write_text(VALID_MANIFEST)
        (pdir / "compose.yml").write_text("services:\n  web:\n    image: nginx\n")
        add_project("testapp", paths)
        # A previously recorded deploy: the release already on disk.
        write_state(paths.project_deploy_state("testapp"), {"current_ref": "testapp-1"})

        observed: list[str] = []

        def fake_prepare_compose_override(
            paths, manifest, component: str = "deploy", **kw,
        ) -> None:
            observed.append(component)

        # Stub side-effecting steps; we only care about the component plumbing.
        monkeypatch.setattr(deploy_mod, "prepare_caddy_config", lambda *a, **k: None)
        monkeypatch.setattr(
            deploy_mod, "prepare_compose_override", fake_prepare_compose_override,
        )
        monkeypatch.setattr("boxmunge.compose_guard.compose_up", lambda *a, **k: None)
        monkeypatch.setattr(deploy_cmd, "caddy_reload", lambda *a, **k: None)
        # Avoid any git/snapshot work by passing no_snapshot=True and no ref.
        monkeypatch.setattr(deploy_cmd.subprocess, "run", MagicMock(
            return_value=MagicMock(returncode=0, stdout="abc", stderr=""),
        ))

        from boxmunge.commands.deploy import deploy_locked
        deploy_locked("testapp", paths, no_snapshot=True, component="promote")
        assert observed == ["promote"]


class TestPromoteUnknownArg:
    """Audit H-N1: cmd_promote rejects unknown flags."""

    def test_unknown_flag_exits_2(self, capsys) -> None:
        from boxmunge.commands.promote_cmd import cmd_promote
        with pytest.raises(SystemExit) as exc:
            cmd_promote(["myapp", "--not-a-flag"])
        assert exc.value.code == 2
        err = capsys.readouterr().err
        assert "ERROR" in err
        assert "--not-a-flag" in err


class TestPromoteComposeRejectionExit3:
    """Audit H-N2: hardening rejection from underlying deploy returns 3."""

    @patch("boxmunge.commands.promote_cmd.deploy_tree_locked", return_value=3)
    @patch("boxmunge.commands.promote_cmd.teardown_staging_locked")
    def test_hardening_rejection_propagates_3(
        self, mock_teardown, mock_deploy, paths,
    ):
        prod_and_stage(paths)
        assert run_promote("myapp", paths) == 3
        mock_deploy.assert_called_once()
        # Teardown must NOT run — production is hostile, staging stays live.
        mock_teardown.assert_not_called()
