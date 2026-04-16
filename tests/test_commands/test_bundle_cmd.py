"""Tests for boxmunge bundle command."""
import tarfile
import pytest
from pathlib import Path
import yaml
from boxmunge.commands.bundle_cmd import run_bundle

VALID_MANIFEST = """\
id: 01TESTULID0000000000000000
project: testapp
source: bundle
hosts:
  - testapp.example.com
services:
  web:
    port: 8080
    routes:
      - path: /
"""

MANIFEST_NO_ID = """\
project: testapp
source: bundle
hosts:
  - testapp.example.com
services:
  web:
    port: 8080
    routes:
      - path: /
"""

def _make_project_dir(tmp_path, manifest=VALID_MANIFEST):
    project_dir = tmp_path / "testapp"
    project_dir.mkdir()
    (project_dir / "manifest.yml").write_text(manifest)
    (project_dir / "compose.yml").write_text("services:\n  web:\n    image: nginx\n")
    (project_dir / "src").mkdir()
    (project_dir / "src" / "app.py").write_text("print('hello')\n")
    return project_dir

class TestRunBundle:
    def test_creates_tarball(self, tmp_path):
        project_dir = _make_project_dir(tmp_path)
        result = run_bundle(str(project_dir))
        assert result == 0
        tarballs = list(tmp_path.glob("testapp-*.tar.gz"))
        assert len(tarballs) == 1

    def test_tarball_contains_project_dir(self, tmp_path):
        project_dir = _make_project_dir(tmp_path)
        run_bundle(str(project_dir))
        tarballs = list(tmp_path.glob("testapp-*.tar.gz"))
        with tarfile.open(tarballs[0], "r:gz") as tar:
            names = tar.getnames()
            assert any("testapp/manifest.yml" in n for n in names)
            assert any("testapp/compose.yml" in n for n in names)

    def test_custom_output_dir(self, tmp_path):
        project_dir = _make_project_dir(tmp_path)
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        result = run_bundle(str(project_dir), output=str(output_dir))
        assert result == 0
        assert len(list(output_dir.glob("testapp-*.tar.gz"))) == 1

    def test_generates_ulid_if_missing(self, tmp_path):
        project_dir = _make_project_dir(tmp_path, manifest=MANIFEST_NO_ID)
        result = run_bundle(str(project_dir))
        assert result == 0
        manifest = yaml.safe_load((project_dir / "manifest.yml").read_text())
        assert "id" in manifest
        assert len(manifest["id"]) == 26

    def test_validate_only(self, tmp_path):
        project_dir = _make_project_dir(tmp_path)
        result = run_bundle(str(project_dir), validate_only=True)
        assert result == 0
        assert len(list(tmp_path.glob("testapp-*.tar.gz"))) == 0

    def test_rejects_missing_manifest(self, tmp_path):
        project_dir = tmp_path / "noproject"
        project_dir.mkdir()
        (project_dir / "compose.yml").write_text("services:\n  web:\n    image: nginx\n")
        assert run_bundle(str(project_dir)) == 1

    def test_rejects_missing_compose(self, tmp_path):
        project_dir = tmp_path / "nocompose"
        project_dir.mkdir()
        (project_dir / "manifest.yml").write_text(VALID_MANIFEST)
        assert run_bundle(str(project_dir)) == 1

    def test_rejects_invalid_manifest(self, tmp_path):
        project_dir = tmp_path / "badmanifest"
        project_dir.mkdir()
        (project_dir / "manifest.yml").write_text("project: badmanifest\nhosts: []\nservices: {}\n")
        (project_dir / "compose.yml").write_text("services:\n  web:\n    image: nginx\n")
        assert run_bundle(str(project_dir)) == 1
