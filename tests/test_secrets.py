"""Tests for secrets dotenv file operations."""
import pytest
from pathlib import Path
from boxmunge.secrets import read_dotenv, write_dotenv, set_key, get_key, unset_key, list_keys


class TestReadDotenv:
    def test_reads_key_value_pairs(self, tmp_path: Path) -> None:
        env_file = tmp_path / "test.env"
        env_file.write_text("KEY1=value1\nKEY2=value2\n")
        result = read_dotenv(env_file)
        assert result == {"KEY1": "value1", "KEY2": "value2"}

    def test_ignores_comments(self, tmp_path: Path) -> None:
        env_file = tmp_path / "test.env"
        env_file.write_text("# comment\nKEY=value\n")
        assert read_dotenv(env_file) == {"KEY": "value"}

    def test_ignores_blank_lines(self, tmp_path: Path) -> None:
        env_file = tmp_path / "test.env"
        env_file.write_text("KEY1=value1\n\nKEY2=value2\n")
        assert read_dotenv(env_file) == {"KEY1": "value1", "KEY2": "value2"}

    def test_handles_values_with_equals(self, tmp_path: Path) -> None:
        env_file = tmp_path / "test.env"
        env_file.write_text("DB_URL=postgres://user:pass@host/db?opt=1\n")
        assert read_dotenv(env_file)["DB_URL"] == "postgres://user:pass@host/db?opt=1"

    def test_handles_quoted_values(self, tmp_path: Path) -> None:
        env_file = tmp_path / "test.env"
        env_file.write_text('KEY="value with spaces"\n')
        assert read_dotenv(env_file)["KEY"] == "value with spaces"

    def test_returns_empty_for_missing_file(self, tmp_path: Path) -> None:
        assert read_dotenv(tmp_path / "nope.env") == {}


class TestWriteDotenv:
    def test_writes_key_value_pairs(self, tmp_path: Path) -> None:
        env_file = tmp_path / "test.env"
        write_dotenv(env_file, {"KEY1": "value1", "KEY2": "value2"})
        content = env_file.read_text()
        assert "KEY1=value1\n" in content
        assert "KEY2=value2\n" in content

    def test_sorts_keys(self, tmp_path: Path) -> None:
        env_file = tmp_path / "test.env"
        write_dotenv(env_file, {"ZEBRA": "z", "ALPHA": "a"})
        lines = env_file.read_text().strip().split("\n")
        assert lines[0].startswith("ALPHA=")
        assert lines[1].startswith("ZEBRA=")


class TestSetKey:
    def test_sets_new_key(self, tmp_path: Path) -> None:
        env_file = tmp_path / "test.env"
        set_key(env_file, "KEY", "value")
        assert get_key(env_file, "KEY") == "value"

    def test_overwrites_existing_key(self, tmp_path: Path) -> None:
        env_file = tmp_path / "test.env"
        set_key(env_file, "KEY", "old")
        set_key(env_file, "KEY", "new")
        assert get_key(env_file, "KEY") == "new"

    def test_creates_file_if_missing(self, tmp_path: Path) -> None:
        env_file = tmp_path / "new.env"
        set_key(env_file, "KEY", "value")
        assert env_file.exists()
        assert get_key(env_file, "KEY") == "value"


class TestGetKey:
    def test_returns_value(self, tmp_path: Path) -> None:
        env_file = tmp_path / "test.env"
        env_file.write_text("KEY=value\n")
        assert get_key(env_file, "KEY") == "value"

    def test_returns_none_for_missing_key(self, tmp_path: Path) -> None:
        env_file = tmp_path / "test.env"
        env_file.write_text("OTHER=value\n")
        assert get_key(env_file, "KEY") is None

    def test_returns_none_for_missing_file(self, tmp_path: Path) -> None:
        assert get_key(tmp_path / "nope.env", "KEY") is None


class TestUnsetKey:
    def test_removes_key(self, tmp_path: Path) -> None:
        env_file = tmp_path / "test.env"
        env_file.write_text("KEY1=a\nKEY2=b\n")
        unset_key(env_file, "KEY1")
        result = read_dotenv(env_file)
        assert "KEY1" not in result
        assert "KEY2" in result

    def test_noop_for_missing_key(self, tmp_path: Path) -> None:
        env_file = tmp_path / "test.env"
        env_file.write_text("KEY=value\n")
        unset_key(env_file, "OTHER")
        assert get_key(env_file, "KEY") == "value"


class TestListKeys:
    def test_returns_sorted_keys(self, tmp_path: Path) -> None:
        env_file = tmp_path / "test.env"
        env_file.write_text("ZEBRA=z\nALPHA=a\n")
        assert list_keys(env_file) == ["ALPHA", "ZEBRA"]

    def test_returns_empty_for_missing_file(self, tmp_path: Path) -> None:
        assert list_keys(tmp_path / "nope.env") == []
