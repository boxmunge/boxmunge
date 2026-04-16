"""Tests for bundle reception handler."""

import tarfile
import pytest
from pathlib import Path

from boxmunge.reception import peek_manifest_from_bundle, receive_bundle
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


def _make_bundle(tmp_path: Path, name: str = "testapp",
                 manifest: str = VALID_MANIFEST,
                 include_manifest: bool = True) -> Path:
    """Create a test bundle tar.gz."""
    staging = tmp_path / "staging" / name
    staging.mkdir(parents=True)
    if include_manifest:
        (staging / "manifest.yml").write_text(manifest)
    (staging / "compose.yml").write_text("services:\n  web:\n    image: nginx\n")
    bundle_path = tmp_path / f"{name}.tar.gz"
    with tarfile.open(bundle_path, "w:gz") as tar:
        tar.add(staging, arcname=name)
    return bundle_path


class TestPeekManifest:
    def test_reads_project_name(self, tmp_path: Path) -> None:
        bundle = _make_bundle(tmp_path)
        manifest = peek_manifest_from_bundle(bundle)
        assert manifest["project"] == "testapp"

    def test_reads_hosts(self, tmp_path: Path) -> None:
        bundle = _make_bundle(tmp_path)
        manifest = peek_manifest_from_bundle(bundle)
        assert manifest["hosts"] == ["testapp.example.com"]

    def test_rejects_missing_manifest(self, tmp_path: Path) -> None:
        bundle = _make_bundle(tmp_path, include_manifest=False)
        with pytest.raises(ValueError, match="No manifest.yml found"):
            peek_manifest_from_bundle(bundle)

    def test_rejects_non_tarfile(self, tmp_path: Path) -> None:
        bad_file = tmp_path / "nottar.tar.gz"
        bad_file.write_text("this is not a tar file")
        with pytest.raises(ValueError, match="Not a valid tar.gz"):
            peek_manifest_from_bundle(bad_file)

    def test_rejects_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="not found"):
            peek_manifest_from_bundle(tmp_path / "nope.tar.gz")


class TestReceiveBundle:
    def test_moves_to_inbox_with_timestamp(self, paths: BoxPaths,
                                           tmp_path: Path) -> None:
        bundle = _make_bundle(tmp_path)
        result = receive_bundle(bundle, paths)
        assert result.parent == paths.inbox
        assert result.name.startswith("testapp-")
        assert result.name.endswith(".tar.gz")
        assert result.exists()
        # Original should be gone (moved, not copied)
        assert not bundle.exists()

    def test_multiple_uploads_dont_clobber(self, paths: BoxPaths,
                                           tmp_path: Path) -> None:
        bundle1 = _make_bundle(tmp_path, name="testapp")
        result1 = receive_bundle(bundle1, paths)

        # Make a second bundle (need different staging dir)
        staging2 = tmp_path / "staging2" / "testapp"
        staging2.mkdir(parents=True)
        (staging2 / "manifest.yml").write_text(VALID_MANIFEST)
        (staging2 / "compose.yml").write_text("services:\n  web:\n    image: nginx\n")
        bundle2 = tmp_path / "testapp2.tar.gz"
        with tarfile.open(bundle2, "w:gz") as tar:
            tar.add(staging2, arcname="testapp")
        result2 = receive_bundle(bundle2, paths)

        assert result1 != result2
        assert result1.exists()
        assert result2.exists()

    def test_rejects_invalid_bundle(self, paths: BoxPaths,
                                    tmp_path: Path) -> None:
        bad_file = tmp_path / "bad.tar.gz"
        bad_file.write_text("not a tar")
        with pytest.raises(ValueError, match="Not a valid tar.gz"):
            receive_bundle(bad_file, paths)

    def test_rejects_bundle_without_manifest(self, paths: BoxPaths,
                                              tmp_path: Path) -> None:
        bundle = _make_bundle(tmp_path, include_manifest=False)
        with pytest.raises(ValueError, match="No manifest.yml"):
            receive_bundle(bundle, paths)

    def test_rejects_bundle_without_project_name(self, paths: BoxPaths,
                                                  tmp_path: Path) -> None:
        bad_manifest = "hosts:\n  - example.com\n"
        bundle = _make_bundle(tmp_path, manifest=bad_manifest)
        with pytest.raises(ValueError, match="missing 'project'"):
            receive_bundle(bundle, paths)


class TestUploadIntegrity:
    def test_rejects_truncated_tarfile(self, paths: BoxPaths, tmp_path: Path) -> None:
        import gzip
        truncated = tmp_path / "truncated.tar.gz"
        truncated.write_bytes(gzip.compress(b"partial data")[:10])
        with pytest.raises(ValueError, match="Not a valid tar.gz"):
            receive_bundle(truncated, paths)

    def test_rejects_empty_file(self, paths: BoxPaths, tmp_path: Path) -> None:
        empty = tmp_path / "empty.tar.gz"
        empty.write_bytes(b"")
        with pytest.raises(ValueError, match="Not a valid tar.gz"):
            receive_bundle(empty, paths)


class TestInboxOrdering:
    def test_resolve_picks_newest_bundle(self, paths: BoxPaths, tmp_path: Path) -> None:
        from boxmunge.source import resolve_bundle_source
        import time

        bundle1 = _make_bundle(tmp_path / "b1", name="testapp")
        dest1 = receive_bundle(bundle1, paths)
        time.sleep(0.01)

        bundle2_staging = tmp_path / "b2" / "staging" / "testapp"
        bundle2_staging.mkdir(parents=True)
        (bundle2_staging / "manifest.yml").write_text(VALID_MANIFEST)
        (bundle2_staging / "compose.yml").write_text("services:\n  web:\n    image: nginx\n")
        bundle2 = tmp_path / "b2" / "testapp.tar.gz"
        with tarfile.open(bundle2, "w:gz") as tar:
            tar.add(bundle2_staging, arcname="testapp")
        dest2 = receive_bundle(bundle2, paths)

        resolved = resolve_bundle_source("testapp", paths)
        assert resolved == dest2
