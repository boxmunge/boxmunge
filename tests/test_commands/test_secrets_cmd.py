"""Tests for boxmunge secrets command."""
import json

from boxmunge.commands.secrets_cmd import run_secrets
from boxmunge.log import _reset_logger
from boxmunge.paths import BoxPaths
from boxmunge.secrets import SecretsFile, get_key


class TestSecretsSet:
    def test_set_project_secret(self, paths: BoxPaths) -> None:
        paths.project_dir("myapp").mkdir(parents=True)
        result = run_secrets(["set", "myapp", "DB_URL=postgres://localhost/db"], paths)
        assert result == 0
        assert get_key(SecretsFile.project(paths, "myapp"), "DB_URL") == "postgres://localhost/db"

    def test_set_host_secret(self, paths: BoxPaths) -> None:
        result = run_secrets(["set", "--host", "GITHUB_TOKEN=ghp_xxx"], paths)
        assert result == 0
        assert get_key(SecretsFile.host(paths), "GITHUB_TOKEN") == "ghp_xxx"

    def test_set_creates_project_dir_on_fly(self, paths: BoxPaths) -> None:
        """Setting secrets for a new project auto-creates the project directory."""
        assert not paths.project_dir("newapp").exists()
        result = run_secrets(["set", "newapp", "KEY=val"], paths)
        assert result == 0
        assert paths.project_dir("newapp").exists()
        assert get_key(SecretsFile.project(paths, "newapp"), "KEY") == "val"

    def test_auto_created_project_dir_has_no_manifest(self, paths: BoxPaths) -> None:
        """The auto-created project dir shouldn't have a manifest (deploy creates it)."""
        run_secrets(["set", "newapp", "KEY=val"], paths)
        assert not paths.project_manifest("newapp").exists()


    def test_set_rejects_newline_injection(self, paths: BoxPaths, capsys) -> None:
        paths.project_dir("myapp").mkdir(parents=True)
        result = run_secrets(["set", "myapp", "KEY=ok\nADMIN=1"], paths)
        assert result == 1
        assert "ERROR:" in capsys.readouterr().err
        assert not paths.project_secrets("myapp").exists()

    def test_set_rejects_bad_key(self, paths: BoxPaths, capsys) -> None:
        result = run_secrets(["set", "--host", "BAD KEY=v"], paths)
        assert result == 1
        assert "ERROR:" in capsys.readouterr().err


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
        assert get_key(SecretsFile.project(paths, "myapp"), "KEY") is None


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


class TestSecretsUsageExitCodes:
    """Audit H-2c: usage errors must return 2, operational errors return 1."""

    def test_no_subcommand_returns_2(self, paths: BoxPaths) -> None:
        # No args at all — usage error
        assert run_secrets([], paths) == 2

    def test_unknown_subcommand_returns_2(self, paths: BoxPaths) -> None:
        assert run_secrets(["bogus"], paths) == 2

    def test_missing_key_returns_1_not_2(self, paths) -> None:
        # Real failure (key not found) — operational, exit 1
        paths.project_dir("myapp").mkdir(parents=True)
        assert run_secrets(["get", "myapp", "NOPE"], paths) == 1


class TestSecretsLiteralValues:
    def test_get_prints_the_value_exactly_as_set(self, paths: BoxPaths, capsys) -> None:
        value = "pa${X}ss # it's \"q\"  "
        assert run_secrets(["set", "--host", f"KEY={value}"], paths) == 0
        capsys.readouterr()
        assert run_secrets(["get", "--host", "KEY"], paths) == 0
        assert capsys.readouterr().out == value + "\n"

    def test_unicode_line_separator_in_a_value_is_stored_and_read_back(
            self, paths: BoxPaths, capsys) -> None:
        assert run_secrets(["set", "--host", "A=x\u2028y"], paths) == 0
        assert run_secrets(["set", "--host", "B=z"], paths) == 0
        capsys.readouterr()
        assert run_secrets(["get", "--host", "A"], paths) == 0
        assert capsys.readouterr().out == "x\u2028y\n"
        assert run_secrets(["list", "--host"], paths) == 0
        assert capsys.readouterr().out == "A\nB\n"

    def test_set_refuses_a_value_it_cannot_store_literally(self, paths: BoxPaths, capsys) -> None:
        assert run_secrets(["set", "--host", "KEY=trailing\\"], paths) == 1
        assert "base64-encode" in capsys.readouterr().err
        assert not paths.host_secrets.exists()


class TestSecretsLegacyFiles:
    """Secrets files written unquoted by older versions of boxmunge."""

    def setup_method(self):
        _reset_logger()

    def teardown_method(self):
        _reset_logger()

    def test_get_of_an_ambiguous_value_fails_and_says_how_to_fix(self, paths, capsys) -> None:
        paths.project_dir("myapp").mkdir(parents=True)
        paths.project_secrets("myapp").write_text("PW=pa$word\n")
        assert run_secrets(["get", "myapp", "PW"], paths) == 1
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "'pa$word'" in captured.err
        assert "secrets set myapp 'PW=<value>'" in captured.err

    def test_list_and_set_warn_about_ambiguous_keys(self, paths, capsys) -> None:
        paths.config.mkdir(parents=True, exist_ok=True)
        paths.host_secrets.write_text("PW=pa$word\n")
        assert run_secrets(["list", "--host"], paths) == 0
        captured = capsys.readouterr()
        assert captured.out == "PW\n"
        assert "WARNING: PW in --host secrets" in captured.err
        assert run_secrets(["set", "--host", "OTHER=x"], paths) == 0
        assert "WARNING: PW" in capsys.readouterr().err
        entries = [e for e in _read_log_entries(paths) if e.get("component") == "secrets"]
        assert entries[-1]["msg"] == "set OTHER; old lines kept as stored: PW"
        assert paths.host_secrets.read_text() == "OTHER='x'\nPW=pa$word\n"
        assert run_secrets(["set", "--host", "PW=pa$word"], paths) == 0
        assert "WARNING" not in capsys.readouterr().err

    def test_reencoding_plain_lines_is_logged(self, paths) -> None:
        paths.project_dir("myapp").mkdir(parents=True)
        paths.project_secrets("myapp").write_text("OLD=plain\n")
        assert run_secrets(["set", "myapp", "NEW=x"], paths) == 0
        entries = [e for e in _read_log_entries(paths) if e.get("component") == "secrets"]
        assert [e["msg"] for e in entries] == ["set NEW; re-encoded as literal values: OLD"]
        assert "plain" not in json.dumps(entries)

    def test_misnamed_keys_are_listed_with_a_warning_and_can_be_unset(self, paths, capsys) -> None:
        paths.config.mkdir(parents=True, exist_ok=True)
        paths.host_secrets.write_text("MY-KEY=x\n")
        assert run_secrets(["list", "--host"], paths) == 0
        captured = capsys.readouterr()
        assert captured.out == "MY-KEY\n"
        assert "'MY-KEY'" in captured.err and "not valid key names" in captured.err
        assert run_secrets(["get", "--host", "MY-KEY"], paths) == 1
        assert "not a valid key name" in capsys.readouterr().err
        assert run_secrets(["unset", "--host", "MY-KEY"], paths) == 0
        assert paths.host_secrets.read_text() == ""

    def test_old_staging_auth_keys_get_a_note_not_a_warning(self, paths, capsys) -> None:
        paths.project_dir("myapp").mkdir(parents=True)
        paths.project_secrets("myapp").write_text("STAGING_AUTH_PASS=Xk9$qL2#z\n")
        assert run_secrets(["list", "myapp"], paths) == 0
        err = capsys.readouterr().err
        assert "WARNING" not in err
        assert "stage reads them as before" in err
        assert run_secrets(["get", "myapp", "STAGING_AUTH_PASS"], paths) == 0
        assert capsys.readouterr().out == "Xk9$qL2#z\n"

    def test_corrupt_file_is_an_error_for_every_subcommand(self, paths, capsys) -> None:
        paths.config.mkdir(parents=True, exist_ok=True)
        paths.host_secrets.write_text("not an assignment\n")
        for args in (["get", "--host", "K"], ["list", "--host"], ["set", "--host", "K=v"],
                     ["unset", "--host", "K"]):
            assert run_secrets(args, paths) == 1
            assert "line 1" in capsys.readouterr().err
