from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest
import yaml
from boxmunge.paths import BoxPaths
from boxmunge.container_update import (
    UpdateTarget, build_targets, resolve_strategy,
)


@pytest.fixture
def paths(tmp_path):
    p = BoxPaths(root=tmp_path / "bm")
    p.config.mkdir(parents=True)
    p.projects.mkdir(parents=True)
    p.caddy.mkdir(parents=True)
    (p.caddy / "compose.yml").write_text(
        "services:\n  caddy:\n    image: caddy:2-alpine\n    container_name: boxmunge-caddy\n"
    )
    p.config_file.write_text("hostname: t\nadmin_email: t@t\n")
    return p


def _write_project(paths, name, manifest_extra=None, with_backup=False):
    pdir = paths.project_dir(name)
    pdir.mkdir(parents=True)
    manifest = {
        "schema_version": 1, "id": "01TEST", "project": name,
        "source": "bundle", "hosts": [f"{name}.test"],
        "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
    }
    if with_backup:
        manifest["backup"] = {"type": "postgres", "service": "db", "dump_command": "pg_dump x"}
    if manifest_extra:
        manifest.update(manifest_extra)
    (pdir / "manifest.yml").write_text(yaml.dump(manifest))
    (pdir / "compose.yml").write_text(
        "services:\n  web:\n    image: nginx:1.25\n    container_name: " + name + "_web_1\n"
    )


class TestResolveStrategy:
    def test_box_default(self):
        box = {"strategy": "leave_broken"}
        assert resolve_strategy(box, project=None) == "leave_broken"

    def test_project_overrides_box(self):
        box = {"strategy": "leave_broken"}
        proj = {"strategy": "rollback_to_previous"}
        assert resolve_strategy(box, project=proj) == "rollback_to_previous"

    def test_project_no_override(self):
        box = {"strategy": "leave_broken"}
        proj = {"enabled": True}
        assert resolve_strategy(box, project=proj) == "leave_broken"


class TestBuildTargets:
    def test_caddy_always_first(self, paths):
        _write_project(paths, "myapp")
        config = {"container_updates": {"enabled": True, "strategy": "leave_broken"}}
        targets = build_targets(paths, config)
        assert targets[0].name == "caddy"

    def test_includes_enabled_projects(self, paths):
        _write_project(paths, "myapp")
        config = {"container_updates": {"enabled": True, "strategy": "leave_broken"}}
        targets = build_targets(paths, config)
        names = [t.name for t in targets]
        assert "myapp" in names

    def test_skips_opt_out_projects(self, paths):
        _write_project(paths, "myapp", manifest_extra={"container_updates": {"enabled": False}})
        config = {"container_updates": {"enabled": True, "strategy": "leave_broken"}}
        targets = build_targets(paths, config)
        names = [t.name for t in targets]
        assert "myapp" not in names

    def test_per_project_strategy_override(self, paths):
        _write_project(paths, "myapp", manifest_extra={
            "container_updates": {"strategy": "rollback_to_previous"}
        })
        config = {"container_updates": {"enabled": True, "strategy": "leave_broken"}}
        targets = build_targets(paths, config)
        myapp = next(t for t in targets if t.name == "myapp")
        assert myapp.strategy == "rollback_to_previous"

    def test_caddy_uses_box_strategy(self, paths):
        config = {"container_updates": {"enabled": True, "strategy": "rollback_to_previous"}}
        targets = build_targets(paths, config)
        caddy = targets[0]
        assert caddy.strategy == "rollback_to_previous"

    def test_has_backup_set_when_manifest_has_backup(self, paths):
        _write_project(paths, "stateful", with_backup=True)
        config = {"container_updates": {"enabled": True, "strategy": "leave_broken"}}
        targets = build_targets(paths, config)
        stateful = next(t for t in targets if t.name == "stateful")
        assert stateful.has_backup is True

    def test_caddy_has_no_backup(self, paths):
        config = {"container_updates": {"enabled": True, "strategy": "leave_broken"}}
        targets = build_targets(paths, config)
        caddy = targets[0]
        assert caddy.has_backup is False


class TestTargetState:
    def test_read_missing_returns_none(self, paths):
        from boxmunge.container_update import read_target_state
        assert read_target_state(paths, "nope") is None

    def test_write_then_read(self, paths):
        from boxmunge.container_update import write_target_state, read_target_state
        paths.container_update_state.mkdir(parents=True)
        state = {
            "last_check": "2026-05-04T03:00:00Z",
            "last_change": "2026-05-02T03:00:00Z",
            "last_status": "succeeded",
            "current_digests": {"caddy": "sha256:abc"},
            "previous_digests": {"caddy": "sha256:def"},
        }
        write_target_state(paths, "caddy", state)
        assert read_target_state(paths, "caddy") == state

    def test_write_creates_state_dir(self, paths):
        from boxmunge.container_update import write_target_state
        # state dir does NOT exist yet
        assert not paths.container_update_state.exists()
        write_target_state(paths, "caddy", {"last_status": "succeeded"})
        assert paths.container_update_state.exists()


class TestUpdateTarget:
    @patch("boxmunge.container_update.image_digest", return_value="sha256:same")
    @patch("boxmunge.container_update.compose_pull")
    @patch("boxmunge.container_update.compose_up")
    @patch("boxmunge.container_update._capture_service_digests")
    @patch("boxmunge.container_update._wait_healthy")
    def test_no_change_when_digests_unchanged(
        self, mock_wait, mock_capture, mock_up, mock_pull, mock_image_digest, paths
    ):
        from boxmunge.container_update import update_target, UpdateTarget
        target = UpdateTarget(
            name="caddy", project_dir=paths.caddy,
            compose_files=["compose.yml"], strategy="leave_broken",
            has_backup=False, is_caddy=True,
        )
        # Only one capture happens (before pull); local image digest matches → no change
        mock_capture.return_value = {"caddy": "sha256:same"}
        result = update_target(paths, target)
        assert result["status"] == "no_change"
        mock_up.assert_not_called()

    @patch("boxmunge.container_update.image_digest", return_value="sha256:new")
    @patch("boxmunge.container_update.compose_pull")
    @patch("boxmunge.container_update.compose_up")
    @patch("boxmunge.container_update._capture_service_digests")
    @patch("boxmunge.container_update._wait_healthy")
    def test_succeeds_on_digest_change_and_healthy(
        self, mock_wait, mock_capture, mock_up, mock_pull, mock_image_digest, paths
    ):
        from boxmunge.container_update import update_target, UpdateTarget
        target = UpdateTarget(
            name="caddy", project_dir=paths.caddy,
            compose_files=["compose.yml"], strategy="leave_broken",
            has_backup=False, is_caddy=True,
        )
        mock_capture.side_effect = [
            {"caddy": "sha256:old"},   # before pull
            {"caddy": "sha256:new"},   # after recreate
        ]
        mock_wait.return_value = (True, [])  # all healthy
        result = update_target(paths, target)
        assert result["status"] == "succeeded"
        mock_up.assert_called_once()

    @patch("boxmunge.container_update.compose_pull", side_effect=__import__("boxmunge.docker", fromlist=["DockerError"]).DockerError("network"))
    @patch("boxmunge.container_update._capture_service_digests")
    def test_failed_when_pull_fails(self, mock_capture, mock_pull, paths):
        from boxmunge.container_update import update_target, UpdateTarget
        target = UpdateTarget(
            name="caddy", project_dir=paths.caddy,
            compose_files=["compose.yml"], strategy="leave_broken",
            has_backup=False, is_caddy=True,
        )
        mock_capture.return_value = {"caddy": "sha256:old"}
        result = update_target(paths, target)
        assert result["status"] == "failed"
        assert "pull" in result.get("reason", "").lower()

    @patch("boxmunge.container_update.image_digest", return_value="sha256:new")
    @patch("boxmunge.container_update.compose_pull")
    @patch("boxmunge.container_update.compose_up")
    @patch("boxmunge.container_update._capture_service_digests")
    @patch("boxmunge.container_update._wait_healthy")
    def test_leave_broken_strategy_does_not_rollback(
        self, mock_wait, mock_capture, mock_up, mock_pull, mock_image_digest, paths
    ):
        from boxmunge.container_update import update_target, UpdateTarget
        target = UpdateTarget(
            name="caddy", project_dir=paths.caddy,
            compose_files=["compose.yml"], strategy="leave_broken",
            has_backup=False, is_caddy=True,
        )
        mock_capture.side_effect = [
            {"caddy": "sha256:old"},   # before pull
            {"caddy": "sha256:new"},   # after recreate
        ]
        mock_wait.return_value = (False, ["caddy"])  # unhealthy
        result = update_target(paths, target)
        assert result["status"] == "failed"
        assert result["rollback_attempted"] is False
        # compose up called once, NOT a second time for rollback
        assert mock_up.call_count == 1

    @patch("boxmunge.container_update.image_digest", return_value="sha256:new")
    @patch("boxmunge.container_update.tag_image")
    @patch("boxmunge.container_update.compose_pull")
    @patch("boxmunge.container_update.compose_up")
    @patch("boxmunge.container_update._capture_service_digests")
    @patch("boxmunge.container_update._wait_healthy")
    def test_rollback_strategy_retags_and_recreates(
        self, mock_wait, mock_capture, mock_up, mock_pull, mock_tag, mock_image_digest, paths
    ):
        from boxmunge.container_update import update_target, UpdateTarget
        target = UpdateTarget(
            name="caddy", project_dir=paths.caddy,
            compose_files=["compose.yml"], strategy="rollback_to_previous",
            has_backup=False, is_caddy=True,
        )
        mock_capture.side_effect = [
            {"caddy": "sha256:old"},   # before pull
            {"caddy": "sha256:new"},   # after recreate
        ]
        # First wait: unhealthy. Second wait (after rollback): healthy.
        mock_wait.side_effect = [(False, ["caddy"]), (True, [])]
        result = update_target(paths, target)
        assert result["status"] == "failed"
        assert result["rollback_attempted"] is True
        assert result["rollback_succeeded"] is True
        # tag_image was called to retag the previous digest
        mock_tag.assert_called()
        # compose up called twice (initial + rollback recreate)
        assert mock_up.call_count == 2

    @patch("boxmunge.container_update.image_digest", return_value="sha256:old")
    @patch("boxmunge.container_update.run_backup")
    @patch("boxmunge.container_update.compose_pull")
    @patch("boxmunge.container_update._capture_service_digests")
    def test_backup_runs_first_when_target_has_backup(
        self, mock_capture, mock_pull, mock_backup, mock_image_digest, paths
    ):
        from boxmunge.container_update import update_target, UpdateTarget
        _write_project(paths, "stateful", with_backup=True)
        target = UpdateTarget(
            name="stateful", project_dir=paths.project_dir("stateful"),
            compose_files=["compose.yml"], strategy="leave_broken",
            has_backup=True, is_caddy=False,
        )
        # Only one capture (before pull); local image digest matches → no change
        mock_capture.return_value = {"web": "sha256:old"}
        mock_backup.return_value = 0
        update_target(paths, target)
        mock_backup.assert_called_once_with("stateful", paths)

    @patch("boxmunge.container_update.run_backup", return_value=1)
    @patch("boxmunge.container_update.compose_pull")
    def test_aborts_when_backup_fails(self, mock_pull, mock_backup, paths):
        from boxmunge.container_update import update_target, UpdateTarget
        _write_project(paths, "stateful", with_backup=True)
        target = UpdateTarget(
            name="stateful", project_dir=paths.project_dir("stateful"),
            compose_files=["compose.yml"], strategy="leave_broken",
            has_backup=True, is_caddy=False,
        )
        result = update_target(paths, target)
        assert result["status"] == "failed"
        assert "backup" in result.get("reason", "").lower()
        mock_pull.assert_not_called()
