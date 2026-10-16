# SPDX-License-Identifier: Apache-2.0
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
        # Usage error: missing --latest -> exit 2
        assert exc.value.code == 2

    def test_no_subcommand_shows_usage(self):
        with pytest.raises(SystemExit) as exc:
            cmd_stash([])
        # No subcommand -> usage error -> exit 2
        assert exc.value.code == 2

    def test_unknown_subcommand_exits(self):
        with pytest.raises(SystemExit) as exc:
            cmd_stash(["unknown"])
        # Unknown subcommand -> usage error -> exit 2
        assert exc.value.code == 2


class TestStashErrors:
    """A refused stash prints one ERROR line and exits 1; the shim shows it."""

    def test_create_refusal_is_an_error_line(self, tmp_path, monkeypatch, capsys):
        from boxmunge.paths import BoxPaths
        paths = BoxPaths(root=tmp_path / "bm")
        for d in ["config", "projects", "state/deploy", "stashes", "logs"]:
            (paths.root / d).mkdir(parents=True)
        (tmp_path / "elsewhere.env").write_text("X=1\n")
        pdir = paths.project_dir("app")
        pdir.mkdir()
        (pdir / "secrets.env").symlink_to(tmp_path / "elsewhere.env")
        monkeypatch.setattr("boxmunge.commands.stash_cmd.BoxPaths", lambda: paths)
        with pytest.raises(SystemExit) as exc:
            cmd_stash(["create"])
        assert exc.value.code == 1
        err = capsys.readouterr().err
        assert err.startswith("ERROR: Cannot stash")
        assert str(pdir / "secrets.env") in err
        assert "Traceback" not in err

    def test_restore_refusal_is_an_error_line(self, capsys):
        from boxmunge.stash import StashError
        with patch("boxmunge.commands.stash_cmd.restore_stash",
                   side_effect=StashError("refusing to extract member 'x'")):
            with pytest.raises(SystemExit) as exc:
                cmd_stash(["restore", "--latest"])
        assert exc.value.code == 1
        assert capsys.readouterr().err == "ERROR: refusing to extract member 'x'\n"
