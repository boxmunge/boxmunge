import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest
from boxmunge.paths import BoxPaths
from boxmunge.health_checks.container_updates import check_container_updates


@pytest.fixture
def paths(tmp_path):
    p = BoxPaths(root=tmp_path / "bm")
    p.container_update_state.mkdir(parents=True)
    return p


def _write_state(paths, name, status, last_check_iso=None):
    last_check = last_check_iso or datetime.now(timezone.utc).isoformat()
    paths.container_update_target_state(name).write_text(json.dumps({
        "last_check": last_check,
        "last_change": last_check,
        "last_status": status,
        "current_digests": {},
        "previous_digests": {},
    }))


class TestContainerUpdatesCheck:
    def test_ok_when_no_state_files(self, paths):
        c = check_container_updates(paths)
        assert c.status == "ok"

    def test_ok_when_all_succeeded(self, paths):
        _write_state(paths, "caddy", "succeeded")
        _write_state(paths, "myapp", "succeeded")
        c = check_container_updates(paths)
        assert c.status == "ok"

    def test_warn_when_any_failed(self, paths):
        _write_state(paths, "caddy", "succeeded")
        _write_state(paths, "myapp", "failed")
        c = check_container_updates(paths)
        assert c.status == "warn"
        assert "myapp" in c.detail

    def test_warn_when_check_stale(self, paths):
        old = (datetime.now(timezone.utc) - timedelta(hours=49)).isoformat()
        _write_state(paths, "caddy", "succeeded", last_check_iso=old)
        c = check_container_updates(paths)
        assert c.status == "warn"
        assert "stale" in c.detail.lower() or "48" in c.detail

    def test_no_change_status_is_ok(self, paths):
        _write_state(paths, "caddy", "no_change")
        c = check_container_updates(paths)
        assert c.status == "ok"
