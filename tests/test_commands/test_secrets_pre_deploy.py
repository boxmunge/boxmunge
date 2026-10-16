"""Tests for setting secrets before first deploy."""

from pathlib import Path

from boxmunge.commands.secrets_cmd import run_secrets
from boxmunge.paths import BoxPaths


class TestSecretsBeforeDeploy:
    def test_set_secret_creates_project_dir(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path / "bm")
        paths.projects.mkdir(parents=True)
        paths.inbox.mkdir(parents=True)

        result = run_secrets(["set", "newproject", "DB_URL=postgres://..."], paths)
        assert result == 0
        assert paths.project_secrets("newproject").exists()

    def test_get_secret_on_pre_registered_project(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path / "bm")
        paths.projects.mkdir(parents=True)
        paths.inbox.mkdir(parents=True)

        run_secrets(["set", "newproject", "DB_URL=postgres://host/db"], paths)
        from boxmunge.secrets import SecretsFile, get_key
        value = get_key(SecretsFile.project(paths, "newproject"), "DB_URL")
        assert value == "postgres://host/db"

    def test_list_secrets_on_pre_registered_project(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path / "bm")
        paths.projects.mkdir(parents=True)
        paths.inbox.mkdir(parents=True)

        run_secrets(["set", "newproject", "KEY1=val1"], paths)
        run_secrets(["set", "newproject", "KEY2=val2"], paths)
        from boxmunge.secrets import SecretsFile, list_keys
        keys = list_keys(SecretsFile.project(paths, "newproject"))
        assert keys == ["KEY1", "KEY2"]
