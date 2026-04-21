# SPDX-License-Identifier: Apache-2.0
from pathlib import Path
from unittest.mock import patch
import pytest
from boxmunge.commands.stash_cmd import cmd_stash


class TestStashRestore:
    def test_restore_latest_calls_restore_stash(self, tmp_path):
        with patch("boxmunge.commands.stash_cmd.restore_stash") as mock_restore:
            mock_restore.return_value = tmp_path / "stash.tar.gz"
            with pytest.raises(SystemExit) as exc:
                cmd_stash(["restore", "--latest"])
            assert exc.value.code == 0
            mock_restore.assert_called_once()

    def test_restore_no_args_shows_error(self):
        with pytest.raises(SystemExit) as exc:
            cmd_stash(["restore"])
        assert exc.value.code != 0

    def test_no_subcommand_shows_usage(self):
        with pytest.raises(SystemExit) as exc:
            cmd_stash([])
        assert exc.value.code == 1

    def test_unknown_subcommand_exits(self):
        with pytest.raises(SystemExit) as exc:
            cmd_stash(["unknown"])
        assert exc.value.code == 1
