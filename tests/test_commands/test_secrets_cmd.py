"""Tests for boxmunge secrets command."""
import json

from boxmunge.commands.secrets_cmd import run_secrets
from boxmunge.log import _reset_logger
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


def _read_log_entries(paths: BoxPaths) -> list[dict]:
    """Parse boxmunge.log JSON-lines into dicts."""
    if not paths.log_file.exists():
        return []
    return [
        json.loads(line)
        for line in paths.log_file.read_text().strip().splitlines()
        if line
    ]


class TestSecretsLogging:
    def setup_method(self):
        _reset_logger()

    def teardown_method(self):
        _reset_logger()

    def test_set_project_secret_logs_action(self, paths: BoxPaths) -> None:
        paths.project_dir("myapp").mkdir(parents=True)
        run_secrets(["set", "myapp", "DB_URL=postgres://secret/db"], paths)
        entries = [e for e in _read_log_entries(paths)
                   if e.get("component") == "secrets"]
        assert len(entries) == 1
        entry = entries[0]
        assert entry["component"] == "secrets"
        assert entry["project"] == "myapp"
        assert "DB_URL" in entry["msg"]
        # The value MUST never appear in the log.
        assert "postgres://secret/db" not in json.dumps(entry)

    def test_set_host_secret_logs_with_no_project(self, paths: BoxPaths) -> None:
        run_secrets(["set", "--host", "GITHUB_TOKEN=ghp_secret_xxxx"], paths)
        entries = [e for e in _read_log_entries(paths)
                   if e.get("component") == "secrets"]
        assert len(entries) == 1
        entry = entries[0]
        assert entry["project"] is None
        assert "GITHUB_TOKEN" in entry["msg"]
        assert "ghp_secret_xxxx" not in json.dumps(entry)

    def test_unset_project_secret_logs_action(self, paths: BoxPaths) -> None:
        paths.project_dir("myapp").mkdir(parents=True)
        run_secrets(["set", "myapp", "KEY=val"], paths)
        run_secrets(["unset", "myapp", "KEY"], paths)
        entries = [e for e in _read_log_entries(paths)
                   if e.get("component") == "secrets"]
        # set + unset
        assert len(entries) == 2
        unset_entry = entries[-1]
        assert unset_entry["component"] == "secrets"
        assert unset_entry["project"] == "myapp"
        assert "unset" in unset_entry["msg"]
        assert "KEY" in unset_entry["msg"]

    def test_get_does_not_log(self, paths: BoxPaths) -> None:
        paths.project_dir("myapp").mkdir(parents=True)
        run_secrets(["set", "myapp", "KEY=val"], paths)
        # Drop the set entry so we can isolate get behaviour.
        if paths.log_file.exists():
            paths.log_file.unlink()
        run_secrets(["get", "myapp", "KEY"], paths)
        entries = _read_log_entries(paths)
        # `get` must not be logged — read-only.
        assert all(e.get("component") != "secrets" for e in entries)
