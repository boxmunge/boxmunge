from pathlib import Path
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
