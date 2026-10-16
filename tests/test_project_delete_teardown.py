"""project-delete fails loudly on teardown errors and clears all per-project state.

Audit D-09 / C-18: a failed ``compose down`` was swallowed and the compose
files deleted, orphaning the containers; pause and quarantine markers and
other per-project state survived, so re-creating the name came up paused or
quarantined.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

from boxmunge.docker import DockerError
from boxmunge.lifecycle import is_blocked
from boxmunge.paths import BoxPaths
from boxmunge.project_alerts import alert_state
from boxmunge.project_registry import add_project, is_registered
from boxmunge.state import write_state

NAME = "myapp"


def _state_files(paths: BoxPaths) -> list[Path]:
    return [
        paths.project_health_state(NAME),
        paths.project_deploy_state(NAME),
        paths.project_paused_state(NAME),
        paths.project_quarantine_state(NAME),
        paths.project_scan_state(NAME),
        paths.project_staging_state(NAME),
        paths.container_update_target_state(NAME),
        alert_state(paths, NAME, "manifest-schema"),
        alert_state(paths, NAME, "git-layout"),
        paths.project_caddy_site(NAME),
        paths.project_staging_caddy_site(NAME),
    ]


@pytest.fixture
def box(paths: BoxPaths) -> BoxPaths:
    paths.config_file.write_text("hostname: t\nadmin_email: a@b\n")
    pdir = paths.project_dir(NAME)
    pdir.mkdir(parents=True)
    (pdir / "manifest.yml").write_text(yaml.dump({
        "schema_version": 1, "id": "01TEST", "project": NAME, "source": "bundle",
        "hosts": [f"{NAME}.test"],
        "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
    }))
    (pdir / "compose.yml").write_text("services:\n  web:\n    image: nginx\n")
    (pdir / "compose.boxmunge.yml").write_text("services: {}\n")
    (pdir / "compose.boxmunge-staging.yml").write_text("services: {}\n")
    for f in _state_files(paths):
        if f.suffix == ".conf":
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text("# site\n")
        else:
            write_state(f, {"x": 1})
    add_project(NAME, paths)
    return paths


def _delete(paths: BoxPaths, down, reload_=None, **kw) -> int:
    from boxmunge.commands import project_delete_cmd
    with patch.object(project_delete_cmd, "compose_down", down), \
         patch.object(project_delete_cmd, "caddy_reload", reload_ or MagicMock()):
        return project_delete_cmd.run_project_delete(NAME, paths, yes=True, **kw)


class TestTeardownFailure:
    @pytest.mark.parametrize("failing", ["prod", "staging"])
    def test_failed_teardown_deletes_nothing(self, box, failing, capsys):
        def down(project_dir, compose_files=None, project_name=None):
            is_staging = project_name == f"{NAME}-staging"
            if (failing == "staging") == is_staging:
                raise DockerError("daemon unreachable")

        reload_ = MagicMock()
        assert _delete(box, down, reload_) == 1
        err = capsys.readouterr().err
        assert "daemon unreachable" in err and "--force" in err
        pdir = box.project_dir(NAME)
        assert (pdir / "compose.yml").exists(), "compose files kept for the retry"
        assert (pdir / "compose.boxmunge.yml").exists()
        assert all(f.exists() for f in _state_files(box))
        assert is_registered(NAME, box)
        reload_.assert_not_called()

    def test_force_deletes_despite_teardown_failure(self, box, capsys):
        down = MagicMock(side_effect=DockerError("daemon unreachable"))
        assert _delete(box, down, force=True) == 0
        assert not box.project_dir(NAME).exists()
        assert "WARN" in capsys.readouterr().out


class TestCompleteRemoval:
    def test_removes_every_per_project_file_and_staging(self, box):
        down = MagicMock()
        assert _delete(box, down) == 0
        assert not box.project_dir(NAME).exists()
        leftover = [str(f) for f in _state_files(box) if f.exists()]
        assert leftover == []
        assert not box.project_alerts_dir(NAME).exists()
        assert not is_registered(NAME, box)
        staging = [c for c in down.call_args_list
                   if c.kwargs.get("project_name") == f"{NAME}-staging"]
        assert len(staging) == 1

    def test_recreated_name_is_not_paused_or_quarantined(self, box):
        assert is_blocked(NAME, box) is not None  # markers present before
        assert _delete(box, MagicMock()) == 0
        add_project(NAME, box)
        assert is_blocked(NAME, box) is None

    def test_caddy_reload_failure_is_reported(self, box, capsys):
        reload_ = MagicMock(side_effect=DockerError("caddy validate failed"))
        assert _delete(box, MagicMock(), reload_) == 1
        assert not box.project_dir(NAME).exists()
        assert "caddy validate failed" in capsys.readouterr().err


def test_damaged_registry_refused_before_anything_is_deleted(box, capsys):
    """Deregistering is the last step; a registry it cannot rewrite must stop
    the delete before the first one, not after the files are gone."""
    registry = box.state / "projects.txt"
    registry.write_text(f"{NAME}\n../x\n")
    down = MagicMock()
    assert _delete(box, down) == 1
    assert f"{registry}:2: " in capsys.readouterr().err
    down.assert_not_called()
    assert box.project_dir(NAME).is_dir()
    assert all(f.exists() for f in _state_files(box))
