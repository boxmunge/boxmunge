"""add-git-project's URL reaches `git clone -- <url>` verbatim. git's own
default refuses the ext:: and fd:: transports (they run commands), but a
config git reads (/etc/gitconfig, deploy's ~/.gitconfig) can allow them:
boxmunge's git calls refuse them whatever the config says."""
from __future__ import annotations

import os
import pwd
from pathlib import Path

import pytest

from boxmunge import as_deploy
from boxmunge.git_slot import GitRefError, clone


@pytest.mark.parametrize("transport", ["ext", "fd"])
def test_a_config_allowing_a_command_transport_does_not_reopen_it(
        tmp_path: Path, monkeypatch, transport: str) -> None:
    home = tmp_path / "home"
    home.mkdir()
    (home / ".gitconfig").write_text('[protocol "ext"]\n\tallow = always\n'
                                     '[protocol "fd"]\n\tallow = always\n')
    me = pwd.getpwuid(os.getuid())
    monkeypatch.setattr(as_deploy.pwd, "getpwuid", lambda uid: pwd.struct_passwd(
        (me.pw_name, me.pw_passwd, me.pw_uid, me.pw_gid, me.pw_gecos, str(home),
         me.pw_shell)))
    marker = tmp_path / "ran"
    url = f"ext::touch {marker}" if transport == "ext" else "fd::0"
    with pytest.raises(GitRefError, match=f"transport '{transport}' not allowed"):
        clone(url, tmp_path / "projects" / "x" / "repo", None)
    assert not marker.exists()
