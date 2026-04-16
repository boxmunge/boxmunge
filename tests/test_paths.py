"""Tests for BoxPaths path resolution."""

from pathlib import Path

from boxmunge.paths import BoxPaths


class TestInboxPaths:
    def test_inbox_path(self, paths: BoxPaths) -> None:
        assert paths.inbox == paths.root / "inbox"

    def test_inbox_tmp_path(self, paths: BoxPaths) -> None:
        assert paths.inbox_tmp == paths.root / "inbox" / ".tmp"

    def test_inbox_consumed_path(self, paths: BoxPaths) -> None:
        assert paths.inbox_consumed == paths.root / "inbox" / ".consumed"


class TestSecretsPaths:
    def test_host_secrets(self, paths: BoxPaths) -> None:
        assert paths.host_secrets == paths.config / "secrets.env"

    def test_project_secrets(self, paths: BoxPaths) -> None:
        assert paths.project_secrets("myapp") == paths.projects / "myapp" / "secrets.env"


class TestStagingPaths:
    def test_staging_caddy_site(self, paths: BoxPaths) -> None:
        assert paths.project_staging_caddy_site("myapp") == \
            paths.caddy_sites / "myapp-staging.conf"

    def test_staging_compose_override(self, paths: BoxPaths) -> None:
        assert paths.project_staging_compose_override("myapp") == \
            paths.projects / "myapp" / "compose.boxmunge-staging.yml"

    def test_staging_state(self, paths: BoxPaths) -> None:
        assert paths.project_staging_state("myapp") == \
            paths.state / "staging" / "myapp.json"


class TestPreRegistered:
    def test_true_when_dir_exists_no_manifest(self, paths: BoxPaths) -> None:
        pdir = paths.project_dir("myapp")
        pdir.mkdir(parents=True)
        (pdir / "secrets.env").write_text("KEY=val\n")
        assert paths.is_project_pre_registered("myapp") is True

    def test_false_when_manifest_exists(self, paths: BoxPaths) -> None:
        pdir = paths.project_dir("myapp")
        pdir.mkdir(parents=True)
        (pdir / "manifest.yml").write_text("project: myapp\n")
        assert paths.is_project_pre_registered("myapp") is False

    def test_false_when_dir_missing(self, paths: BoxPaths) -> None:
        assert paths.is_project_pre_registered("nope") is False
