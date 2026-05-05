from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest
import yaml
from boxmunge.paths import BoxPaths
from boxmunge.commands.container_update_cmd import run_container_update


@pytest.fixture
def paths(tmp_path):
    p = BoxPaths(root=tmp_path / "bm")
    p.config.mkdir(parents=True)
    p.projects.mkdir(parents=True)
    p.caddy.mkdir(parents=True)
    p.upgrade_state.mkdir(parents=True)
    p.state.mkdir(parents=True, exist_ok=True)
    (p.caddy / "compose.yml").write_text(
        "services:\n  caddy:\n    image: caddy:2-alpine\n    container_name: boxmunge-caddy\n"
    )
    p.config_file.write_text("hostname: t\nadmin_email: t@t\n")
    return p


class TestProbationGate:
    def test_skips_when_probation_active(self, paths):
        paths.probation.write_text('{"version":"0.2.1"}')
        with patch("boxmunge.commands.container_update_cmd.update_target") as mock_update:
            rc = run_container_update(paths)
        assert rc == 0
        mock_update.assert_not_called()

    def test_runs_when_no_probation(self, paths):
        with patch("boxmunge.commands.container_update_cmd.update_target") as mock_update:
            mock_update.return_value = {"name": "caddy", "status": "succeeded"}
            rc = run_container_update(paths)
        # Update was called at least once (for caddy)
        assert mock_update.called

    def test_force_skips_probation(self, paths):
        paths.probation.write_text('{"version":"0.2.1"}')
        with patch("boxmunge.commands.container_update_cmd.update_target") as mock_update:
            mock_update.return_value = {"name": "caddy", "status": "succeeded"}
            run_container_update(paths, force=False)
            run_container_update(paths, force=True)
        assert mock_update.called  # called via the force=True path


class TestDisabledMaster:
    def test_skips_when_box_disabled(self, paths):
        paths.config_file.write_text(
            "hostname: t\nadmin_email: t@t\n"
            "container_updates:\n  enabled: false\n"
        )
        with patch("boxmunge.commands.container_update_cmd.update_target") as mock_update:
            rc = run_container_update(paths)
        assert rc == 0
        mock_update.assert_not_called()


class TestCaddyAbortCascade:
    def test_caddy_failure_aborts_loop(self, paths):
        # Add a user project
        pdir = paths.project_dir("myapp")
        pdir.mkdir(parents=True)
        (pdir / "manifest.yml").write_text(yaml.dump({
            "schema_version": 1, "id": "01TEST", "project": "myapp",
            "source": "bundle", "hosts": ["myapp.test"],
            "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
        }))
        (pdir / "compose.yml").write_text(
            "services:\n  web:\n    image: nginx:1.25\n    container_name: myapp_web\n"
        )

        call_log = []
        def fake_update(paths, target):
            call_log.append(target.name)
            if target.name == "caddy":
                return {"name": "caddy", "status": "failed", "reason": "test"}
            return {"name": target.name, "status": "succeeded"}

        with patch("boxmunge.commands.container_update_cmd.update_target", side_effect=fake_update):
            rc = run_container_update(paths)

        assert call_log == ["caddy"]  # myapp NOT called
        assert rc == 1


class TestProjectIsolation:
    def test_one_project_failure_does_not_block_others(self, paths):
        for name in ["app-a", "app-b", "app-c"]:
            pdir = paths.project_dir(name)
            pdir.mkdir(parents=True)
            (pdir / "manifest.yml").write_text(yaml.dump({
                "schema_version": 1, "id": "01" + name.upper().replace("-", ""),
                "project": name, "source": "bundle", "hosts": [f"{name}.test"],
                "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
            }))
            (pdir / "compose.yml").write_text(
                f"services:\n  web:\n    image: nginx:1.25\n    container_name: {name}_web\n"
            )

        call_log = []
        def fake_update(paths, target):
            call_log.append(target.name)
            if target.name == "app-b":
                return {"name": target.name, "status": "failed", "reason": "test"}
            return {"name": target.name, "status": "succeeded"}

        with patch("boxmunge.commands.container_update_cmd.update_target", side_effect=fake_update):
            rc = run_container_update(paths)

        assert "app-a" in call_log
        assert "app-b" in call_log
        assert "app-c" in call_log
        assert rc == 1  # because one failure


class TestDryRun:
    @patch("boxmunge.commands.container_update_cmd.update_target")
    @patch("boxmunge.commands.container_update_cmd._dry_run_target")
    def test_dry_run_does_not_call_update_target(
        self, mock_dry, mock_update, paths
    ):
        mock_dry.return_value = {"name": "caddy", "status": "no_change"}
        rc = run_container_update(paths, dry_run=True)
        mock_update.assert_not_called()
        mock_dry.assert_called()
        assert rc == 0


def _make_paused_project(paths, name="paused-app"):
    """Helper: write a project file tree and mark it paused."""
    from boxmunge.pause import write_paused_state
    pdir = paths.project_dir(name)
    pdir.mkdir(parents=True)
    (pdir / "manifest.yml").write_text(yaml.dump({
        "schema_version": 1, "id": "01" + name.upper().replace("-", ""),
        "project": name, "source": "bundle", "hosts": [f"{name}.test"],
        "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
    }))
    (pdir / "compose.yml").write_text(
        f"services:\n  web:\n    image: nginx:1.25\n    container_name: {name}_web\n"
    )
    write_paused_state(name, paths)


class TestSkipsPausedProjects:
    def test_paused_project_not_updated(self, paths):
        """Paused projects MUST NOT be applied (no compose recreate)."""
        _make_paused_project(paths, "paused-app")

        # Active project
        adir = paths.project_dir("active-app")
        adir.mkdir(parents=True)
        (adir / "manifest.yml").write_text(yaml.dump({
            "schema_version": 1, "id": "01ACTIVE", "project": "active-app",
            "source": "bundle", "hosts": ["active-app.test"],
            "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
        }))
        (adir / "compose.yml").write_text(
            "services:\n  web:\n    image: nginx:1.25\n    container_name: active_web\n"
        )

        update_call_log = []
        def fake_update(paths, target):
            update_call_log.append(target.name)
            return {"name": target.name, "status": "succeeded"}

        # Stub the dry-run too so the paused-project pre-fetch doesn't try to shell out
        def fake_dry(paths, target):
            return {"name": target.name, "status": "no_change",
                    "previous_digests": {}, "current_digests": {}}

        with patch("boxmunge.commands.container_update_cmd.update_target", side_effect=fake_update), \
             patch("boxmunge.commands.container_update_cmd._dry_run_target", side_effect=fake_dry):
            rc = run_container_update(paths)

        # Paused project must NOT be in the apply path
        assert "paused-app" not in update_call_log
        # Active and caddy MUST be applied
        assert "active-app" in update_call_log
        assert "caddy" in update_call_log
        assert rc == 0

    def test_paused_project_dry_run_pulls_pre_emptively(self, paths):
        """While paused, container-update pre-fetches images so resume is fast.

        Implements the `_dry_run_target` path for paused projects, which pulls
        but does NOT recreate. Logs the result so the operator can see what's
        pending.
        """
        _make_paused_project(paths, "paused-app")

        dry_call_log = []
        def fake_dry(paths, target):
            dry_call_log.append(target.name)
            return {
                "name": target.name, "status": "would_change",
                "previous_digests": {"web": "sha256:old"},
                "current_digests": {"web": "sha256:new"},
            }

        def fake_update(paths, target):
            return {"name": target.name, "status": "succeeded"}

        with patch("boxmunge.commands.container_update_cmd._dry_run_target", side_effect=fake_dry), \
             patch("boxmunge.commands.container_update_cmd.update_target", side_effect=fake_update):
            rc = run_container_update(paths)

        assert "paused-app" in dry_call_log
        assert rc == 0

    def test_paused_project_appears_in_results_with_paused_status(self, paths):
        """Paused projects show up in the run summary with status='paused'."""
        _make_paused_project(paths, "paused-app")

        captured_results: list = []

        def fake_dry(paths, target):
            return {
                "name": target.name, "status": "would_change",
                "previous_digests": {"web": "sha256:old"},
                "current_digests": {"web": "sha256:new"},
            }

        def fake_log_op(component, message, paths, **kwargs):
            if "paused" in message.lower() and kwargs.get("project") == "paused-app":
                captured_results.append((message, kwargs))

        with patch("boxmunge.commands.container_update_cmd._dry_run_target", side_effect=fake_dry), \
             patch("boxmunge.commands.container_update_cmd.update_target", return_value={"name": "caddy", "status": "succeeded"}), \
             patch("boxmunge.commands.container_update_cmd.log_operation", side_effect=fake_log_op):
            rc = run_container_update(paths)

        assert rc == 0
        assert captured_results, "expected a 'paused' log entry for paused-app"
        message, kwargs = captured_results[0]
        # The log line MUST include the pending services list so an operator
        # reading logs knows why resume might take a moment.
        assert "web" in message or "web" in str(kwargs.get("detail", {}))

    def test_paused_project_dry_run_failure_does_not_fail_run(self, paths):
        """If the pre-fetch pull fails (registry outage etc), the daily run still succeeds."""
        _make_paused_project(paths, "paused-app")

        def failing_dry(paths, target):
            return {"name": target.name, "status": "failed",
                    "reason": "pull_failed: network",
                    "previous_digests": {}, "current_digests": {}}

        with patch("boxmunge.commands.container_update_cmd._dry_run_target", side_effect=failing_dry), \
             patch("boxmunge.commands.container_update_cmd.update_target", return_value={"name": "caddy", "status": "succeeded"}):
            rc = run_container_update(paths)

        assert rc == 0  # paused-project pre-fetch failure is non-fatal

    def test_paused_project_no_pending_logs_quietly(self, paths):
        """No-change pre-fetch still logs the skip but with empty pending list."""
        _make_paused_project(paths, "paused-app")

        captured_logs: list = []
        def fake_dry(paths, target):
            return {"name": target.name, "status": "no_change",
                    "previous_digests": {"web": "sha256:same"},
                    "current_digests": {"web": "sha256:same"}}

        def fake_log_op(component, message, paths, **kwargs):
            if kwargs.get("project") == "paused-app":
                captured_logs.append((message, kwargs))

        with patch("boxmunge.commands.container_update_cmd._dry_run_target", side_effect=fake_dry), \
             patch("boxmunge.commands.container_update_cmd.update_target", return_value={"name": "caddy", "status": "succeeded"}), \
             patch("boxmunge.commands.container_update_cmd.log_operation", side_effect=fake_log_op):
            rc = run_container_update(paths)

        assert rc == 0
        assert captured_logs, "expected at least one log entry for paused-app"

    def test_paused_project_skipped_in_dry_run(self, paths):
        """In a top-level --dry-run, paused projects still go through the dry-run helper
        (no double-pull); update_target is never invoked."""
        _make_paused_project(paths, "paused-app")

        update_calls = []
        def fake_update(paths, target):
            update_calls.append(target.name)
            return {"name": target.name, "status": "succeeded"}

        def fake_dry(paths, target):
            return {"name": target.name, "status": "no_change",
                    "previous_digests": {}, "current_digests": {}}

        with patch("boxmunge.commands.container_update_cmd._dry_run_target", side_effect=fake_dry), \
             patch("boxmunge.commands.container_update_cmd.update_target", side_effect=fake_update):
            rc = run_container_update(paths, dry_run=True)

        assert update_calls == []  # update_target never called in dry-run
        assert rc == 0


class TestLock:
    def test_skips_when_lock_held(self, paths):
        paths.container_update_state.mkdir(parents=True)
        # Simulate held lock
        import fcntl
        f = open(paths.container_update_lock, "w")
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            with patch("boxmunge.commands.container_update_cmd.update_target") as mock_update:
                rc = run_container_update(paths)
            assert rc == 0
            mock_update.assert_not_called()
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)
            f.close()
