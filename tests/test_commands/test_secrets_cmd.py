"""Tests for boxmunge secrets command."""
from boxmunge.commands.secrets_cmd import run_secrets
from boxmunge.paths import BoxPaths
from boxmunge.secrets import read_dotenv


class TestSecretsSet:
    def test_set_project_secret(self, paths: BoxPaths) -> None:
        paths.project_dir("myapp").mkdir(parents=True)
        result = run_secrets(["set", "myapp", "DB_URL=postgres://localhost/db"], paths)
        assert result == 0
        assert read_dotenv(paths.project_secrets("myapp"))["DB_URL"] == "postgres://localhost/db"

    def test_set_host_secret(self, paths: BoxPaths) -> None:
        result = run_secrets(["set", "--host", "GITHUB_TOKEN=ghp_xxx"], paths)
        assert result == 0
        assert read_dotenv(paths.host_secrets)["GITHUB_TOKEN"] == "ghp_xxx"

    def test_set_creates_project_dir_on_fly(self, paths: BoxPaths) -> None:
        """Setting secrets for a new project auto-creates the project directory."""
        assert not paths.project_dir("newapp").exists()
        result = run_secrets(["set", "newapp", "KEY=val"], paths)
        assert result == 0
        assert paths.project_dir("newapp").exists()
        assert read_dotenv(paths.project_secrets("newapp"))["KEY"] == "val"

    def test_auto_created_project_dir_has_no_manifest(self, paths: BoxPaths) -> None:
        """The auto-created project dir shouldn't have a manifest (deploy creates it)."""
        run_secrets(["set", "newapp", "KEY=val"], paths)
        assert not paths.project_manifest("newapp").exists()


class TestSecretsGet:
    def test_get_project_secret(self, paths, capsys) -> None:
        paths.project_dir("myapp").mkdir(parents=True)
        run_secrets(["set", "myapp", "KEY=value"], paths)
        result = run_secrets(["get", "myapp", "KEY"], paths)
        assert result == 0
        assert "value" in capsys.readouterr().out

    def test_get_host_secret(self, paths, capsys) -> None:
        run_secrets(["set", "--host", "KEY=value"], paths)
        result = run_secrets(["get", "--host", "KEY"], paths)
        assert result == 0
        assert "value" in capsys.readouterr().out

    def test_get_missing_key(self, paths) -> None:
        paths.project_dir("myapp").mkdir(parents=True)
        result = run_secrets(["get", "myapp", "NOPE"], paths)
        assert result == 1


class TestSecretsList:
    def test_list_project_secrets(self, paths, capsys) -> None:
        paths.project_dir("myapp").mkdir(parents=True)
        run_secrets(["set", "myapp", "KEY_A=a"], paths)
        run_secrets(["set", "myapp", "KEY_B=b"], paths)
        result = run_secrets(["list", "myapp"], paths)
        assert result == 0
        output = capsys.readouterr().out
        assert "KEY_A" in output and "KEY_B" in output

    def test_list_host_secrets(self, paths, capsys) -> None:
        run_secrets(["set", "--host", "TOKEN=x"], paths)
        result = run_secrets(["list", "--host"], paths)
        assert result == 0
        assert "TOKEN" in capsys.readouterr().out


class TestSecretsUnset:
    def test_unset_project_secret(self, paths) -> None:
        paths.project_dir("myapp").mkdir(parents=True)
        run_secrets(["set", "myapp", "KEY=val"], paths)
        result = run_secrets(["unset", "myapp", "KEY"], paths)
        assert result == 0
        assert "KEY" not in read_dotenv(paths.project_secrets("myapp"))
