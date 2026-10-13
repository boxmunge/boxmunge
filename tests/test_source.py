"""Tests for source resolution — finding the right bundle or git ref to deploy."""
import tarfile
import pytest
from pathlib import Path

from boxmunge.source import consume_bundle, resolve_bundle_source, SourceError
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


class TestExactProjectMatch:
    """E cross-area: inbox lookup was a prefix match, so deploying `foo`
    picked up `foo-bar`'s bundle (it sorts higher) and consumed it."""

    def test_foo_never_picks_foo_bar(self, paths: BoxPaths) -> None:
        own = _place_real_bundle(paths, "foo", "2026-03-31T091500000000")
        _place_real_bundle(paths, "foo-bar", "2026-03-31T102300000000")
        assert resolve_bundle_source("foo", paths) == own

    def test_only_other_project_with_shared_prefix(self, paths: BoxPaths) -> None:
        _place_real_bundle(paths, "foo-bar", "2026-03-31T102300000000")
        with pytest.raises(SourceError, match="No bundles"):
            resolve_bundle_source("foo", paths)

    def test_ignores_names_without_an_inbox_timestamp(self, paths: BoxPaths) -> None:
        stray = paths.inbox / "testapp-latest.tar.gz"
        stray.write_bytes(b"")
        with pytest.raises(SourceError, match="No bundles"):
            resolve_bundle_source("testapp", paths)


class TestRefMatching:
    def test_full_bundle_name_selects_it(self, paths: BoxPaths) -> None:
        older = _place_real_bundle(paths, "testapp", "2026-03-31T091500000000")
        _place_real_bundle(paths, "testapp", "2026-03-31T102300000000")
        ref = "testapp-2026-03-31T091500000000"
        assert resolve_bundle_source("testapp", paths, ref=ref) == older

    def test_ambiguous_ref_is_an_error(self, paths: BoxPaths) -> None:
        _place_real_bundle(paths, "testapp", "2026-03-31T091500000000")
        _place_real_bundle(paths, "testapp", "2026-03-31T102300000000")
        with pytest.raises(SourceError, match="matches 2 bundles"):
            resolve_bundle_source("testapp", paths, ref="2026-03-31")

    def test_project_name_alone_is_not_a_ref(self, paths: BoxPaths) -> None:
        _place_real_bundle(paths, "testapp", "2026-03-31T091500000000")
        with pytest.raises(SourceError, match="No bundle matching"):
            resolve_bundle_source("testapp", paths, ref="testapp")


class TestConsume:
    def test_resolve_has_no_side_effects(self, paths: BoxPaths) -> None:
        a = _place_real_bundle(paths, "testapp", "2026-03-31T091500000000")
        b = _place_real_bundle(paths, "testapp", "2026-03-31T102300000000")
        resolve_bundle_source("testapp", paths)
        assert a.exists() and b.exists()

    def test_consume_supersedes_older_bundles_of_that_project_only(
        self, paths: BoxPaths,
    ) -> None:
        old = _place_real_bundle(paths, "testapp", "2026-03-31T091500000000")
        new = _place_real_bundle(paths, "testapp", "2026-03-31T102300000000")
        other = _place_real_bundle(paths, "testapp-two", "2026-03-30T000000000000")
        consume_bundle(new, "testapp", paths)
        assert not new.exists() and not old.exists()
        assert other.exists()
        consumed = {p.name for p in paths.inbox_consumed.iterdir()}
        assert consumed == {new.name, old.name}
