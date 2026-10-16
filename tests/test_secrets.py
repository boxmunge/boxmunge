"""Tests for secrets env-file storage: literal values, legacy lines, locking."""
import threading
from pathlib import Path
from unittest.mock import patch

import pytest

import boxmunge.secrets as secrets_mod
from boxmunge.paths import BoxPaths
from boxmunge.secrets import (
    LegacySecretError, SecretsFile, SecretsFileError,
    get_internal_key, get_key, inventory, list_keys, set_key, unset_key,
)

# Values the old unquoted format corrupted, and ones that need escaping.
TRICKY_VALUES = [
    "pa${UNSET_VAR}ss", "$HOME", "cost$$5", "alpha # omega", "#leading", "'quoted'",
    '"double"', "it's", "back\\slash", "two\\\\x", "even\\\\", "esc\\\\'q",
    "  padded  ", "\tleading tab", "a=b=c", "=leading", "café \U0001f600", "",
    "postgres://u:p@h/db?a=1&b=2", "line\u2028sep", "para\u2029sep", "nel\u0085x",
    "\u2028",
]


@pytest.fixture
def sf(tmp_path: Path) -> SecretsFile:
    return SecretsFile(tmp_path / "secrets.env", tmp_path / "locks" / "secrets.lock")


class TestLiteralRoundTrip:
    @pytest.mark.parametrize("value", TRICKY_VALUES)
    def test_get_returns_exactly_what_was_set(self, sf: SecretsFile, value: str) -> None:
        set_key(sf, "KEY", value)
        assert get_key(sf, "KEY") == value

    def test_values_are_written_single_quoted(self, sf: SecretsFile) -> None:
        set_key(sf, "A", "it's $x")
        assert sf.path.read_text() == "A='it\\'s $x'\n"

    def test_file_is_owner_only(self, sf: SecretsFile) -> None:
        set_key(sf, "A", "x")
        assert sf.path.stat().st_mode & 0o777 == 0o600

    def test_keys_are_sorted(self, sf: SecretsFile) -> None:
        set_key(sf, "ZEBRA", "z")
        set_key(sf, "ALPHA", "a")
        assert sf.path.read_text().splitlines() == ["ALPHA='a'", "ZEBRA='z'"]

    @pytest.mark.parametrize("value", ["ends\\", "odd\\\\\\", "a\\'b", "x\\\\\\'y"])
    def test_unrepresentable_values_are_refused(self, sf: SecretsFile, value: str) -> None:
        set_key(sf, "SAFE", "kept")
        with pytest.raises(ValueError, match="base64-encode"):
            set_key(sf, "KEY", value)
        assert sf.path.read_text() == "SAFE='kept'\n"


class TestBasics:
    def test_missing_file(self, sf: SecretsFile) -> None:
        assert get_key(sf, "KEY") is None
        assert list_keys(sf) == []

    def test_overwrite_and_unset(self, sf: SecretsFile) -> None:
        set_key(sf, "KEY", "old")
        set_key(sf, "KEY", "new")
        set_key(sf, "OTHER", "o")
        assert get_key(sf, "KEY") == "new"
        unset_key(sf, "KEY")
        assert list_keys(sf) == ["OTHER"]

    def test_unset_missing_key_writes_nothing(self, sf: SecretsFile) -> None:
        unset_key(sf, "NOPE")
        assert not sf.path.exists()

    def test_comments_and_blank_lines_are_ignored(self, sf: SecretsFile) -> None:
        sf.path.write_text("# note\n\nKEY='v'\n")
        assert list_keys(sf) == ["KEY"]

    @pytest.mark.parametrize("content", ["garbage\n", "A='1'\nA='2'\n"])
    def test_lines_no_writer_produces_fail_loudly(self, sf: SecretsFile, content: str) -> None:
        sf.path.write_text(content)
        with pytest.raises(SecretsFileError, match="line"):
            list_keys(sf)
        with pytest.raises(SecretsFileError):
            set_key(sf, "NEW", "x")
        assert sf.path.read_text() == content


class TestLegacyUnquotedFiles:
    """Files written before literal storage hold unquoted values."""

    def test_plain_unquoted_values_read_literally(self, sf: SecretsFile) -> None:
        sf.path.write_text("URL=postgres://u:p@h/db?a=1\nHASH=a#b\nEMPTY=\n")
        assert get_key(sf, "URL") == "postgres://u:p@h/db?a=1"
        assert get_key(sf, "HASH") == "a#b"
        assert get_key(sf, "EMPTY") == ""
        assert inventory(sf).legacy == []

    def test_plain_lines_are_reencoded_on_next_write(self, sf: SecretsFile) -> None:
        sf.path.write_text("OLD=plain\n")
        assert set_key(sf, "NEW", "x").migrated == ["OLD"]
        assert sf.path.read_text() == "NEW='x'\nOLD='plain'\n"

    @pytest.mark.parametrize("stored", [
        "pa${X}ss", "alpha # omega", '"abc"', "  padded  ", "trail ", "'unterminated",
    ])
    def test_ambiguous_lines_are_reported_not_guessed(self, sf: SecretsFile, stored: str) -> None:
        sf.path.write_text(f"KEY={stored}\n")
        assert inventory(sf).legacy == ["KEY"]
        with pytest.raises(LegacySecretError) as exc:
            get_key(sf, "KEY")
        assert exc.value.stored == stored

    def test_ambiguous_lines_survive_other_writes_byte_for_byte(self, sf: SecretsFile) -> None:
        """Containers keep receiving what they did until the key is re-set."""
        sf.path.write_text("KEY=pa${X}ss # note\n")
        set_key(sf, "OTHER", "o")
        assert sf.path.read_text() == "KEY=pa${X}ss # note\nOTHER='o'\n"

    def test_setting_an_ambiguous_key_resolves_it(self, sf: SecretsFile) -> None:
        sf.path.write_text("KEY=pa${X}ss\n")
        set_key(sf, "KEY", "pa${X}ss")
        assert get_key(sf, "KEY") == "pa${X}ss"
        assert inventory(sf).legacy == []

    def test_unsetting_an_ambiguous_key_removes_it(self, sf: SecretsFile) -> None:
        sf.path.write_text("KEY=pa${X}ss\nOTHER='o'\n")
        unset_key(sf, "KEY")
        assert sf.path.read_text() == "OTHER='o'\n"


class TestLineBreaksInsideValues:
    """Compose splits env files on "\\n" only; so must the reader."""

    @pytest.mark.parametrize("char", ["\u2028", "\u2029", "\u0085", "\u2028\u2029"])
    def test_unicode_separators_round_trip_and_keep_the_file_readable(
            self, sf: SecretsFile, char: str) -> None:
        set_key(sf, "FIRST", f"a{char}b")
        set_key(sf, "SECOND", "x")
        assert get_key(sf, "FIRST") == f"a{char}b"
        assert list_keys(sf) == ["FIRST", "SECOND"]

    def test_write_reports_inventory_without_rereading(self, sf: SecretsFile) -> None:
        inv = set_key(sf, "A", "x\u2028y")
        assert (inv.keys, inv.legacy, inv.misnamed, inv.migrated) == (["A"], [], [], [])


class TestMisnamedLegacyKeys:
    """Before v0.10.1 any key name was accepted, and Compose passes such
    names to containers, so their lines are kept rather than refused."""

    def test_kept_verbatim_listed_and_flagged(self, sf: SecretsFile) -> None:
        sf.path.write_text("MY-KEY=x\napp.key=y\n")
        set_key(sf, "GOOD", "g")
        assert sf.path.read_text() == "GOOD='g'\nMY-KEY=x\napp.key=y\n"
        inv = inventory(sf)
        assert inv.keys == ["GOOD", "MY-KEY", "app.key"]
        assert inv.misnamed == ["MY-KEY", "app.key"]
        assert inv.legacy == []
        with pytest.raises(LegacySecretError, match="not a valid secret key name"):
            get_key(sf, "MY-KEY")

    def test_unset_removes_one_by_exact_name(self, sf: SecretsFile) -> None:
        sf.path.write_text("MY-KEY=x\napp.key=y\n")
        unset_key(sf, "app.key")
        assert sf.path.read_text() == "MY-KEY=x\n"

    def test_set_still_refuses_such_names(self, sf: SecretsFile) -> None:
        with pytest.raises(ValueError, match="invalid secret key"):
            set_key(sf, "MY-KEY", "x")


class TestInternalKeys:
    """boxmunge's own keys keep the old reader's meaning for old lines."""

    @pytest.mark.parametrize("line,expected", [
        ("PW=Xk9$qL2#z", "Xk9$qL2#z"),
        ("PW=alpha # omega  ", "alpha # omega"),
        ('PW="quoted"', "quoted"),
        ("PW=  lead", "  lead"),
    ])
    def test_old_lines_read_as_the_old_reader_did(self, sf, line: str, expected: str) -> None:
        sf.path.write_text(line + "\n")
        assert get_internal_key(sf, "PW") == expected

    def test_new_lines_read_literally(self, sf: SecretsFile) -> None:
        set_key(sf, "PW", " 'x' ")
        assert get_internal_key(sf, "PW") == " 'x' "
        assert get_internal_key(sf, "NOPE") is None


class TestSetKeyRejectsInjection:
    """A-09: a key or value that would add or corrupt env-file lines is refused."""

    @pytest.mark.parametrize("key", [
        "", "1KEY", "MY-KEY", "KEY=X", "KEY NAME", "KEY\nEVIL", "KéY", " KEY",
    ])
    def test_rejects_bad_keys(self, sf: SecretsFile, key: str) -> None:
        with pytest.raises(ValueError, match="key"):
            set_key(sf, key, "v")
        assert not sf.path.exists()

    @pytest.mark.parametrize("value", [
        "line1\nINJECTED=1", "a\rb", "nul\x00byte", "esc\x1b[2J", "del\x7f",
    ])
    def test_rejects_control_characters_in_values(self, sf: SecretsFile, value: str) -> None:
        set_key(sf, "SAFE", "kept")
        with pytest.raises(ValueError, match="value"):
            set_key(sf, "KEY", value)
        assert list_keys(sf) == ["SAFE"]


class TestLocking:
    def test_paths_put_locks_outside_the_project_tree(self, tmp_path: Path) -> None:
        paths = BoxPaths(root=tmp_path)
        assert SecretsFile.project(paths, "myapp").lock_path.parent == paths.state / "secrets-locks"
        assert SecretsFile.host(paths).lock_path.parent == paths.state / "secrets-locks"

    @pytest.mark.parametrize("ops", [
        [("set", "ONE", "1"), ("set", "TWO", "2")],
        [("set", "TWO", "2"), ("unset", "ONE", None)],
    ])
    def test_concurrent_writers_do_not_lose_updates(self, sf: SecretsFile, ops) -> None:
        """Both writers read before either writes unless the lock serialises
        them. Under the lock the first reader's barrier wait times out (the
        second writer is blocked on the lock), so the barrier never deadlocks."""
        if ops[1][0] == "unset":
            set_key(sf, "ONE", "1")
        barrier = threading.Barrier(2, timeout=1)
        real_parse = secrets_mod._parse

        def parse_then_wait(path: Path):
            result = real_parse(path)
            try:
                barrier.wait()
            except threading.BrokenBarrierError:
                pass
            return result

        def run(op: str, key: str, value: str | None) -> None:
            set_key(sf, key, value) if op == "set" else unset_key(sf, key)

        with patch.object(secrets_mod, "_parse", parse_then_wait):
            threads = [threading.Thread(target=run, args=op) for op in ops]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        expected = sorted(k for op, k, _ in ops if op == "set")
        assert list_keys(sf) == expected
