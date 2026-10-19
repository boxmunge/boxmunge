"""Tests for deploy command — state management and flow logic."""

import tarfile
from unittest.mock import patch

import pytest

from boxmunge.caddy import prepare_caddy_config
from boxmunge.commands.deploy import cmd_deploy, record_deploy_state, run_deploy
from boxmunge.compose import prepare_compose_override
from boxmunge.paths import BoxPaths
from boxmunge.project_registry import add_project
from boxmunge.state import read_state


MANIFEST = {
    "project": "myapp",
    "repo": "git@github.com:org/myapp.git",
    "ref": "main",
    "hosts": ["myapp.example.com"],
    "services": {
        "frontend": {
            "type": "frontend",
            "port": 3000,
            "routes": [{"path": "/"}],
        },
    },
    "backup": {"type": "none"},
    "deploy": {"snapshot_before_deploy": True},
    "env_files": ["project.env"],
}


class TestRecordDeployState:
    def test_records_current_ref(self, paths: BoxPaths) -> None:
        record_deploy_state(paths, "myapp", "abc123", None)
        state = read_state(paths.project_deploy_state("myapp"))
        assert state["current_ref"] == "abc123"
        assert "deployed_at" in state

    def test_pushes_previous_to_history(self, paths: BoxPaths) -> None:
        record_deploy_state(paths, "myapp", "ref1", "snap1.age")
        record_deploy_state(paths, "myapp", "ref2", "snap2.age")
        state = read_state(paths.project_deploy_state("myapp"))
        assert state["current_ref"] == "ref2"
        assert len(state["history"]) == 1
        assert state["history"][0]["ref"] == "ref1"


class TestPrepareCaddyConfig:
    def test_writes_caddy_site_config(self, paths: BoxPaths) -> None:
        prepare_caddy_config(paths, MANIFEST)
        site_conf = paths.project_caddy_site("myapp")
        assert site_conf.exists()
        content = site_conf.read_text()
        assert "myapp.example.com" in content
        assert "myapp-frontend:3000" in content

    def test_uses_override_if_present(self, paths: BoxPaths) -> None:
        override = paths.project_caddy_override("myapp")
        override.parent.mkdir(parents=True, exist_ok=True)
        override.write_text("custom caddy config\n")
        prepare_caddy_config(paths, MANIFEST)
        site_conf = paths.project_caddy_site("myapp")
        assert site_conf.read_text() == "custom caddy config\n"


class TestPrepareComposeOverride:
    def test_writes_override_file(self, paths: BoxPaths) -> None:
        project_dir = paths.project_dir("myapp")
        project_dir.mkdir(parents=True)
        (project_dir / "compose.yml").write_text("services:\n  frontend:\n    image: nginx\n")
        prepare_compose_override(paths, MANIFEST)
        override = paths.project_compose_override("myapp")
        assert override.exists()
        assert "boxmunge-proxy" in override.read_text()


BUNDLE_MANIFEST = """\
id: 01TESTULID0000000000000000
project: testapp
source: bundle
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


def _place_deploy_bundle(paths, timestamp="2026-03-31T091500000000"):
    staging = paths.root / "tmp_staging" / "testapp"
    staging.mkdir(parents=True, exist_ok=True)
    (staging / "manifest.yml").write_text(BUNDLE_MANIFEST)
    (staging / "compose.yml").write_text("services:\n  web:\n    image: nginx\n")
    filename = f"testapp-{timestamp}.tar.gz"
    bundle_path = paths.inbox / filename
    with tarfile.open(bundle_path, "w:gz") as tar:
        tar.add(staging, arcname="testapp")
    return bundle_path


class TestBundleSourceDeploy:
    @patch("boxmunge.compose_guard.compose_up")
    @patch("boxmunge.commands.deploy.caddy_reload")
    def test_deploy_from_inbox(self, mock_reload, mock_up, paths):
        add_project("testapp", paths)
        _place_deploy_bundle(paths)
        result = run_deploy("testapp", paths)
        assert result == 0
        assert paths.project_dir("testapp").exists()
        assert (paths.project_dir("testapp") / "manifest.yml").exists()


class TestProjectRegistrationEnforcement:
    def test_rejects_unregistered_project(self, paths: BoxPaths, capsys) -> None:
        result = run_deploy("unregistered", paths)
        assert result == 1
        captured = capsys.readouterr()
        assert "not registered" in captured.err


class TestRefusesPaused:
    def test_refuses_paused_project(self, paths: BoxPaths, capsys) -> None:
        from boxmunge.pause import write_paused_state
        add_project("myapp", paths)
        write_paused_state("myapp", paths)
        rc = run_deploy("myapp", paths)
        assert rc == 1
        err = capsys.readouterr().err
        assert "paused" in err.lower()


class TestQuarantinedDeploy:
    """A deploy is how a quarantined project ships its fix: it passes the
    quarantine gate only through the scan of the images its release would
    start (commands/quarantine_gate, tested there), refused before
    anything starts, and lifts the quarantine once it is live."""

    def _quarantine(self, paths: BoxPaths) -> None:
        from tests.test_commands.cve_helpers import seed_quarantine
        add_project("testapp", paths)
        _place_deploy_bundle(paths)
        seed_quarantine(paths, "testapp")

    @patch("boxmunge.compose_guard.compose_up")
    @patch("boxmunge.commands.deploy.caddy_reload")
    def test_vulnerable_release_is_refused_and_nothing_starts(
        self, mock_reload, mock_up, paths: BoxPaths, capsys, monkeypatch,
    ) -> None:
        from boxmunge.commands.quarantine_gate import QuarantineRefused
        self._quarantine(paths)
        removed = []

        def refuse(paths_, target, manifest, previous):
            raise QuarantineRefused(["CVE-2026-0001 (Critical) in openssl 1, service web"])
        monkeypatch.setattr("boxmunge.commands.release_config.clear_release", refuse)
        monkeypatch.setattr("boxmunge.commands.release_config.remove_candidates",
                            removed.append)
        assert run_deploy("testapp", paths) == 1
        err = capsys.readouterr().err
        assert "CVE-2026-0001 (Critical) in openssl 1, service web" in err
        assert "--abandon" in err  # the install is left abandonable
        assert removed == ["testapp", "testapp"]  # before the build, and after the refusal
        assert paths.project_quarantine_state("testapp").exists()
        mock_up.assert_not_called()
        mock_reload.assert_not_called()
        assert "current_ref" not in read_state(paths.project_deploy_state("testapp"))

    @patch("boxmunge.compose_guard.compose_up")
    @patch("boxmunge.commands.deploy.caddy_reload")
    def test_clean_release_deploys_then_lifts(
        self, mock_reload, mock_up, paths: BoxPaths, capsys, monkeypatch,
    ) -> None:
        from boxmunge.commands import quarantine_gate
        from boxmunge.cve.quarantine import clear_quarantine_state
        self._quarantine(paths)
        from tests.test_commands.cve_helpers import BALANCED, make_clearance
        clearance = make_clearance("testapp", {"web": ("nginx", "sha256:x")}, before=BALANCED)
        scans = []
        monkeypatch.setattr("boxmunge.commands.deploy_tree.manifest_in_force",
                            lambda paths_, project: {"security": {"posture": "strict"}})
        monkeypatch.setattr("boxmunge.commands.release_config.clear_release",
                            lambda *a: scans.append(a) or clearance)
        checked, lifted, pinned = [], [], []
        monkeypatch.setattr("boxmunge.commands.deploy_tree.require_unchanged",
                            lambda paths_, c: checked.append(c))
        monkeypatch.setattr(quarantine_gate, "_verify_running",
                            lambda paths_, c, component, **kw: {"testapp-web-1": "web"})
        monkeypatch.setattr(quarantine_gate, "_release_policies",
                            lambda paths_, project, services: {"testapp-web-1": "always"})
        mock_up.side_effect = lambda *a, **k: pinned.append(k["pinned"])

        def lift(project, paths_, **kw):
            lifted.append((project, kw))
            clear_quarantine_state(project, paths_)
        monkeypatch.setattr(quarantine_gate, "lift_quarantine", lift)
        assert run_deploy("testapp", paths) == 0
        out = capsys.readouterr().out
        assert checked == [clearance]
        # The manifest the install replaced is the baseline for the lift's report.
        assert scans[0][3]["security"] == {"posture": "strict"}
        ((project, kw),) = lifted
        assert project == "testapp" and kw["restore"] == {"testapp-web-1": "always"}
        assert pinned == [True]  # only the scanned local images: no pull, no build
        assert kw["txn"] is not None  # the lift's start belongs to this install
        assert "testapp-web:8080" in kw["project_caddy_site_content"]  # the routed site
        assert "Quarantine (CVE-2026-0001) lifted by deploying" in out
        mock_up.assert_called()

    def test_paused_and_quarantined_is_refused(self, paths: BoxPaths, capsys) -> None:
        from boxmunge.pause import write_paused_state
        self._quarantine(paths)
        write_paused_state("testapp", paths)
        assert run_deploy("testapp", paths) == 1
        err = capsys.readouterr().err
        assert "paused and CVE-quarantined" in err
        assert not (paths.project_dir("testapp") / "manifest.yml").exists()


class TestCvePolicyValidatorWiring:
    """Regression: validate_user_compose must receive the manifest's security
    block as cve_policy, otherwise posture/dangerously_disable_quarantine
    cross-validation rules silently never fire (caught in v0.6.0 smoke).

    Same pattern is applied in stage_cmd, resume_cmd, upgrade_cmd — this
    test in deploy is the canonical one.
    """

    def _bundle_with_security(self, paths: BoxPaths) -> None:
        manifest = (
            "id: 01TESTULID0000000000000000\n"
            "schema_version: 2\n"
            "project: testapp\n"
            "source: bundle\n"
            "hosts:\n"
            "  - testapp.example.com\n"
            "services:\n"
            "  web:\n"
            "    port: 8080\n"
            "    routes:\n"
            "      - path: /\n"
            "backup:\n"
            "  type: none\n"
            "security:\n"
            "  posture: strict\n"
        )
        staging = paths.root / "tmp_staging" / "testapp"
        staging.mkdir(parents=True, exist_ok=True)
        (staging / "manifest.yml").write_text(manifest)
        (staging / "compose.yml").write_text(
            "services:\n  web:\n    image: nginx\n    read_only: true\n"
        )
        bundle_path = paths.inbox / "testapp-2026-05-07T000000000000.tar.gz"
        with tarfile.open(bundle_path, "w:gz") as tar:
            tar.add(staging, arcname="testapp")

    @patch("boxmunge.compose_guard.compose_up")
    @patch("boxmunge.commands.deploy.caddy_reload")
    def test_deploy_passes_security_block_as_cve_policy(
        self, _reload, _up, paths: BoxPaths,
    ) -> None:
        add_project("testapp", paths)
        self._bundle_with_security(paths)
        with patch(
            "boxmunge.intake.validate_user_compose",
        ) as mock_validate:
            run_deploy("testapp", paths)
        # Caller MUST pass cve_policy={'posture': 'strict'} — the manifest's
        # security block. Otherwise posture/dangerously rules never fire.
        kwargs = mock_validate.call_args.kwargs
        assert kwargs.get("cve_policy") == {"posture": "strict"}, (
            f"validate_user_compose called with cve_policy="
            f"{kwargs.get('cve_policy')!r}; expected manifest's security block"
        )


class TestRejectsUnknownArgs:
    """Audit H-1b: silent-drop for unknown args was a footgun. Reject loudly."""

    def test_unknown_flag_returns_2(self, capfd) -> None:
        with pytest.raises(SystemExit) as exc:
            cmd_deploy(["myapp", "--not-a-flag"])
        assert exc.value.code == 2
        captured = capfd.readouterr()
        assert "ERROR" in captured.err
        assert "--not-a-flag" in captured.err


class TestDeployComposeRejectionExit3:
    """Audit H-N2: hardening rejection returns exit code 3, not 1."""

    def test_hostile_compose_returns_3(self, paths: BoxPaths) -> None:
        add_project("testapp", paths)
        _place_deploy_bundle(paths)
        # Replace just-extracted compose.yml after first deploy run? Easier:
        # mock validate_user_compose to raise ComposeSecurityError directly.
        from boxmunge.compose_validate import ComposeSecurityError
        with patch(
            "boxmunge.intake.validate_user_compose",
            side_effect=ComposeSecurityError("simulated hostile key: privileged"),
        ):
            with patch("boxmunge.compose_guard.compose_up"):
                with patch("boxmunge.commands.deploy.caddy_reload"):
                    rc = run_deploy("testapp", paths)
        assert rc == 3
