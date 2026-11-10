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


def _box(tmp_path, monkeypatch):
    from boxmunge.paths import BoxPaths
    from boxmunge.version import write_installed_version
    paths = BoxPaths(root=tmp_path / "bm")
    for d in ["config", "projects", "state/deploy", "stashes", "logs"]:
        (paths.root / d).mkdir(parents=True)
    paths.config_file.write_text("hostname: test\nadmin_email: t@t\n")
    write_installed_version(paths, "0.2.0", "abc1234")
    monkeypatch.setattr("boxmunge.commands.stash_cmd.BoxPaths", lambda: paths)
    return paths


def _create(capsys) -> list[str]:
    with pytest.raises(SystemExit) as exc:
        cmd_stash(["create"])
    assert exc.value.code == 0
    return capsys.readouterr().out.splitlines()


class TestStashCreateDigest:
    """`stash create` prints the size and sha256 of the archive it wrote, so
    the upgrade shim records them without re-reading the deploy-writable
    stashes/ name (#160/#166)."""

    def test_prints_the_digest_of_the_file_it_made(self, tmp_path, monkeypatch, capsys):
        import hashlib
        paths = _box(tmp_path, monkeypatch)
        created, digest = _create(capsys)
        name = created.removeprefix("Stash created: ")
        data = (paths.stashes / name).read_bytes()
        assert digest == f"Stash digest: {len(data)} {hashlib.sha256(data).hexdigest()}"

    def test_a_0_11_5_shim_still_reads_the_name(self, tmp_path, monkeypatch, capsys):
        """The 0.11.5 shim runs the new release's `stash create` on the upgrade
        to it. Its record_stash takes the last 'Stash created: ' line and
        requires the stash-name pattern of what follows; the digest line must
        not change what it reads. Its parse, verbatim:"""
        import re
        import subprocess
        paths = _box(tmp_path, monkeypatch)
        out = "\n".join(_create(capsys))
        parse_0_11_5 = "printf '%s\\n' \"$1\" | sed -n 's/^Stash created: //p' | tail -n 1"
        name = subprocess.run(["bash", "-c", parse_0_11_5, "-", out],
                              capture_output=True, text=True, check=True).stdout.rstrip("\n")
        assert re.fullmatch(r"boxmunge-stash-[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{6}\.tar\.gz", name)
        assert (paths.stashes / name).is_file()
