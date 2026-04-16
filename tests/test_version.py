"""Tests for boxmunge version tracking."""

from pathlib import Path

from boxmunge.version import (
    parse_version_string, format_version_string, read_installed_version,
    write_installed_version, FALLBACK_VERSION,
)
from boxmunge.paths import BoxPaths


class TestParseVersion:
    def test_parses_full_version(self) -> None:
        semver, commit = parse_version_string("0.2.0+abc1234")
        assert semver == "0.2.0"
        assert commit == "abc1234"

    def test_parses_semver_only(self) -> None:
        semver, commit = parse_version_string("0.1.2")
        assert semver == "0.1.2"
        assert commit is None

    def test_parses_empty_returns_fallback(self) -> None:
        semver, commit = parse_version_string("")
        assert semver == FALLBACK_VERSION
        assert commit is None


class TestFormatVersion:
    def test_with_commit(self) -> None:
        assert format_version_string("0.2.0", "abc1234") == "0.2.0+abc1234"

    def test_without_commit(self) -> None:
        assert format_version_string("0.2.0") == "0.2.0"


class TestInstalledVersion:
    def test_write_and_read(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path / "bm")
        paths.config.mkdir(parents=True)
        write_installed_version(paths, "0.2.0", "abc1234")
        version = read_installed_version(paths)
        assert version == "0.2.0+abc1234"

    def test_missing_file_returns_fallback(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path / "bm")
        version = read_installed_version(paths)
        assert version == FALLBACK_VERSION
