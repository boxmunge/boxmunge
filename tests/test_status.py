"""Tests for boxmunge status."""
from pathlib import Path
import yaml

from boxmunge.paths import BoxPaths
from boxmunge.commands.status import run_status
from boxmunge.pause import write_paused_state


def _setup(tmp_path: Path) -> BoxPaths:
    paths = BoxPaths(root=tmp_path / "bm")
    for d in ["projects/myapp", "state/deploy", "state/health", "logs"]:
        (paths.root / d).mkdir(parents=True, exist_ok=True)
    (paths.project_dir("myapp") / "manifest.yml").write_text(yaml.dump({
        "schema_version": 1, "id": "01TEST", "project": "myapp",
        "source": "bundle", "hosts": ["myapp.test"],
        "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
    }))
    return paths


class TestStatusPaused:
    def test_paused_project_shows_paused(self, tmp_path, capsys):
        paths = _setup(tmp_path)
        write_paused_state("myapp", paths)
        run_status(paths)
        out = capsys.readouterr().out
        assert "PAUSED" in out

    def test_paused_overrides_health_status(self, tmp_path, capsys):
        import json
        paths = _setup(tmp_path)
        # Health says failing, but pause should win.
        paths.project_health_state("myapp").write_text(json.dumps({
            "status": "failing", "last_check": "2026-05-05T00:00:00Z"
        }))
        write_paused_state("myapp", paths)
        run_status(paths)
        out = capsys.readouterr().out
        assert "PAUSED" in out
        assert "FAILING" not in out
