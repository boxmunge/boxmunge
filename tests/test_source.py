"""Tests for source resolution — finding the right bundle or git ref to deploy."""
import tarfile
import pytest
from pathlib import Path

from boxmunge.source import resolve_bundle_source, SourceError
from boxmunge.paths import BoxPaths

VALID_MANIFEST = """\
project: testapp
hosts:
  - testapp.example.com
services:
  web:
    port: 8080
    routes:
      - path: /
"""


def _place_real_bundle(paths: BoxPaths, project: str = "testapp",
                       timestamp: str = "2026-03-31T091500000000",
                       manifest: str = VALID_MANIFEST) -> Path:
    staging = paths.root / "tmp_staging" / project
    staging.mkdir(parents=True, exist_ok=True)
    (staging / "manifest.yml").write_text(manifest)
    (staging / "compose.yml").write_text("services:\n  web:\n    image: nginx\n")
    bundle_path = paths.inbox / f"{project}-{timestamp}.tar.gz"
    with tarfile.open(bundle_path, "w:gz") as tar:
        tar.add(staging, arcname=project)
    return bundle_path


class TestResolveBundleSource:
    def test_finds_latest_bundle(self, paths: BoxPaths) -> None:
        _place_real_bundle(paths, "testapp", "2026-03-31T091500000000")
        _place_real_bundle(paths, "testapp", "2026-03-31T102300000000")
        result = resolve_bundle_source("testapp", paths)
        assert "102300" in result.name

    def test_finds_specific_ref(self, paths: BoxPaths) -> None:
        _place_real_bundle(paths, "testapp", "2026-03-31T091500000000")
        _place_real_bundle(paths, "testapp", "2026-03-31T102300000000")
        result = resolve_bundle_source("testapp", paths, ref="2026-03-31T091500")
        assert "091500" in result.name

    def test_errors_no_bundles(self, paths: BoxPaths) -> None:
        with pytest.raises(SourceError, match="No bundles"):
            resolve_bundle_source("testapp", paths)

    def test_errors_ref_not_found(self, paths: BoxPaths) -> None:
        _place_real_bundle(paths, "testapp", "2026-03-31T091500000000")
        with pytest.raises(SourceError, match="No bundle matching"):
            resolve_bundle_source("testapp", paths, ref="2026-12-25T000000")

    def test_ignores_other_projects(self, paths: BoxPaths) -> None:
        _place_real_bundle(paths, "other", "2026-03-31T091500000000")
        with pytest.raises(SourceError, match="No bundles"):
            resolve_bundle_source("testapp", paths)

    def test_returns_existing_path(self, paths: BoxPaths) -> None:
        _place_real_bundle(paths, "testapp", "2026-03-31T091500000000")
        result = resolve_bundle_source("testapp", paths)
        assert result.exists()
        assert result.suffix == ".gz"
