"""Tests for health-check command behaviors."""
from __future__ import annotations

import yaml

from boxmunge.commands.health_cmd import check_project_containers
from boxmunge.health_checks.security import check_security_profiles
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


def _write_manifest(paths: BoxPaths, project: str, manifest: dict) -> None:
    paths.project_dir(project).mkdir(parents=True, exist_ok=True)
    paths.project_manifest(project).write_text(yaml.dump(manifest))


class TestCheckSecurityProfiles:
    """Task 19: profile: off must surface in `boxmunge health` output."""

    def test_off_project_warning_in_report(self, tmp_path):
        paths = BoxPaths(root=tmp_path / "bm")
        paths.projects.mkdir(parents=True, exist_ok=True)
        _write_manifest(paths, "myapp", {
            "schema_version": 1, "id": "01TEST", "project": "myapp",
            "source": "bundle", "hosts": ["myapp.test"],
            "security": {"profile": "off", "reason": "legacy binary needs raw caps"},
            "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
        })

        check = check_security_profiles(paths)
        assert check.status == "warn"
        assert "SECURITY OFF" in check.detail
        assert "myapp/web" in check.detail
        assert "legacy binary needs raw caps" in check.detail

    def test_default_profile_no_security_message(self, tmp_path):
        paths = BoxPaths(root=tmp_path / "bm")
        paths.projects.mkdir(parents=True, exist_ok=True)
        _write_manifest(paths, "myapp", {
            "schema_version": 1, "id": "01TEST", "project": "myapp",
            "source": "bundle", "hosts": ["myapp.test"],
            "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
        })

        check = check_security_profiles(paths)
        assert check.status == "ok"
        assert "SECURITY OFF" not in check.detail

    def test_no_projects_is_ok(self, tmp_path):
        paths = BoxPaths(root=tmp_path / "bm")
        check = check_security_profiles(paths)
        assert check.status == "ok"

    def test_per_service_off_overrides_default_project(self, tmp_path):
        paths = BoxPaths(root=tmp_path / "bm")
        paths.projects.mkdir(parents=True, exist_ok=True)
        _write_manifest(paths, "myapp", {
            "schema_version": 1, "id": "01TEST", "project": "myapp",
            "source": "bundle", "hosts": ["myapp.test"],
            "services": {
                "web": {"port": 8080, "routes": [{"path": "/"}]},
                "legacy": {
                    "port": 9000, "routes": [{"path": "/legacy/*"}],
                    "security": {"profile": "off", "reason": "vendor blob"},
                },
            },
        })

        check = check_security_profiles(paths)
        assert check.status == "warn"
        assert "myapp/legacy" in check.detail
        assert "myapp/web" not in check.detail
        assert "vendor blob" in check.detail

    def test_lists_all_off_projects(self, tmp_path):
        paths = BoxPaths(root=tmp_path / "bm")
        paths.projects.mkdir(parents=True, exist_ok=True)
        _write_manifest(paths, "alpha", {
            "schema_version": 1, "id": "01A", "project": "alpha",
            "source": "bundle", "hosts": ["a.test"],
            "security": {"profile": "off", "reason": "alpha-reason"},
            "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
        })
        _write_manifest(paths, "beta", {
            "schema_version": 1, "id": "01B", "project": "beta",
            "source": "bundle", "hosts": ["b.test"],
            "security": {"profile": "off", "reason": "beta-reason"},
            "services": {"web": {"port": 8080, "routes": [{"path": "/"}]}},
        })

        check = check_security_profiles(paths)
        assert check.status == "warn"
        assert "alpha/web" in check.detail
        assert "beta/web" in check.detail
