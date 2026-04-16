"""Smoke tests for the vendored bundle command."""

import tarfile
import yaml
from pathlib import Path

from boxmunge_cli.bundle_cmd import run_bundle


def _create_project(tmp_path: Path, name: str = "testapp") -> Path:
    project = tmp_path / name
    project.mkdir()
    (project / "manifest.yml").write_text(yaml.dump({
        "id": "01TESTULID0000000000000000",
        "project": name,
        "source": "bundle",
        "hosts": [f"{name}.example.com"],
        "services": {
            "web": {"port": 8080, "routes": [{"path": "/"}]},
        },
        "backup": {"type": "none"},
    }, sort_keys=False))
    (project / "compose.yml").write_text("services:\n  web:\n    image: nginx\n")
    return project


class TestRunBundle:
    def test_creates_tarball(self, tmp_path: Path) -> None:
        project = _create_project(tmp_path)
        result = run_bundle(str(project))
        assert result == 0
        tarballs = list(tmp_path.glob("testapp-*.tar.gz"))
        assert len(tarballs) == 1

    def test_tarball_contains_manifest(self, tmp_path: Path) -> None:
        project = _create_project(tmp_path)
        run_bundle(str(project))
        tarball = next(tmp_path.glob("testapp-*.tar.gz"))
        with tarfile.open(tarball) as tar:
            names = tar.getnames()
            assert "testapp/manifest.yml" in names
            assert "testapp/compose.yml" in names

    def test_validate_only(self, tmp_path: Path) -> None:
        project = _create_project(tmp_path)
        result = run_bundle(str(project), validate_only=True)
        assert result == 0
        assert not list(tmp_path.glob("*.tar.gz"))

    def test_missing_manifest_fails(self, tmp_path: Path) -> None:
        project = tmp_path / "empty"
        project.mkdir()
        result = run_bundle(str(project))
        assert result == 1
