"""Tests for boxmunge status."""
import json
from pathlib import Path

import yaml

from boxmunge.commands.status import run_status
from boxmunge.pause import write_paused_state
from boxmunge.paths import BoxPaths


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


def _write_quarantine(paths: BoxPaths, name: str, **fields: object) -> None:
    """Write a quarantine marker. Keys mirror cve.quarantine.write_quarantine_state."""
    payload = {
        "quarantined_at": "2026-05-28T03:11:49+00:00",
        "cve_id": "CVE-2026-42496",
        "severity": "Critical",
        "effective_severity": "Critical",
        "explanation": "Critical, no upstream fix. Meets balanced threshold — quarantine.",
        "image_ref": "sha256:abc",
    }
    payload.update(fields)
    paths.project_quarantine_state(name).write_text(json.dumps(payload))


class TestStatusQuarantined:
    def test_quarantined_project_shows_quarantined(self, tmp_path, capsys):
        paths = _setup(tmp_path)
        _write_quarantine(paths, "myapp")
        run_status(paths)
        out = capsys.readouterr().out
        assert "QUARANTINED" in out

    def test_quarantine_rationale_surfaced(self, tmp_path, capsys):
        paths = _setup(tmp_path)
        _write_quarantine(paths, "myapp")
        run_status(paths)
        out = capsys.readouterr().out
        # CVE id, severity, since-timestamp, explanation, and lift command
        # must all appear in the rationale block.
        assert "CVE-2026-42496" in out
        assert "Critical" in out
        assert "2026-05-28 03:11:49" in out
        assert "Critical, no upstream fix" in out
        assert "security resume myapp" in out

    def test_quarantine_overrides_health_status(self, tmp_path, capsys):
        paths = _setup(tmp_path)
        paths.project_health_state("myapp").write_text(json.dumps({
            "status": "ok", "last_check": "2026-05-28T03:09:25Z",
        }))
        _write_quarantine(paths, "myapp")
        run_status(paths)
        out = capsys.readouterr().out
        # The pre-fix bug: OK from stale health state masked the quarantine.
        assert "QUARANTINED" in out
        # OK row for myapp should not be emitted (only the rationale block
        # under "Quarantined projects:" may legitimately use the word).
        rows_section = out.split("Quarantined projects:")[0]
        assert "myapp" in rows_section
        assert " OK " not in rows_section

    def test_quarantine_overrides_pause(self, tmp_path, capsys):
        paths = _setup(tmp_path)
        write_paused_state("myapp", paths)
        _write_quarantine(paths, "myapp")
        run_status(paths)
        out = capsys.readouterr().out
        # Mirrors lifecycle.is_blocked precedence: quarantine wins.
        assert "QUARANTINED" in out
        assert "PAUSED" not in out

    def test_quarantine_json_includes_rationale(self, tmp_path, capsys):
        paths = _setup(tmp_path)
        _write_quarantine(paths, "myapp")
        run_status(paths, as_json=True)
        rows = json.loads(capsys.readouterr().out)
        myapp = next(r for r in rows if r["project"] == "myapp")
        assert myapp["raw_status"] == "quarantined"
        assert myapp["cve_id"] == "CVE-2026-42496"
        assert myapp["severity"] == "Critical"
        assert "no upstream fix" in myapp["explanation"]
        assert myapp["quarantined_at"].startswith("2026-05-28")
