"""Tests for health-check command behaviors."""
from __future__ import annotations

import yaml

from boxmunge.commands.health_cmd import check_project_containers
from boxmunge.paths import BoxPaths
from boxmunge.pause import write_paused_state


class TestHealthSkipsPaused:
    def test_paused_project_not_checked(self, tmp_path):
        paths = BoxPaths(root=tmp_path / "bm")
        for d in ["projects/myapp", "state/deploy", "logs"]:
            (paths.root / d).mkdir(parents=True, exist_ok=True)
        (paths.project_dir("myapp") / "manifest.yml").write_text(yaml.dump({
            "schema_version": 1, "id": "01TEST", "project": "myapp",
            "source": "bundle", "hosts": ["myapp.test"],
            "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
        }))
        write_paused_state("myapp", paths)
        check = check_project_containers(paths)
        # Result for paused project should not be a "FAIL" — paused project
        # is omitted from the per-project check entirely.
        assert "myapp" not in (check.detail or "")
