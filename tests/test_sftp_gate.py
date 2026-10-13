# SPDX-License-Identifier: Apache-2.0
"""boxmunge-sftp (sshd's SFTP subsystem): deploy is refused (A-04), other
users get the real sftp-server unchanged."""
from __future__ import annotations

import pwd
from unittest.mock import MagicMock, patch

import pytest

from boxmunge import sftp_receive


def _as_user(name: str):
    return patch("boxmunge.sftp_receive.pwd.getpwuid",
                 return_value=MagicMock(spec=pwd.struct_passwd, pw_name=name))


def test_deploy_is_refused(capsys: pytest.CaptureFixture[str]) -> None:
    with _as_user("deploy"), patch("boxmunge.sftp_receive.os.execv") as execv, \
         patch("boxmunge.sftp_receive.subprocess", create=True) as sub, \
         patch("sys.argv", ["boxmunge-sftp"]):
        with pytest.raises(SystemExit) as exc:
            sftp_receive.main()
    assert exc.value.code == 1
    execv.assert_not_called()
    sub.run.assert_not_called()
    err = capsys.readouterr().err
    assert "SFTP is disabled" in err and "scp -O" in err


def test_deploy_identity_comes_from_the_uid_not_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("USER", "supervisor")
    monkeypatch.setenv("LOGNAME", "supervisor")
    with _as_user("deploy"), patch("boxmunge.sftp_receive.os.execv") as execv, \
         patch("sys.argv", ["boxmunge-sftp"]):
        with pytest.raises(SystemExit):
            sftp_receive.main()
    execv.assert_not_called()


def test_other_users_get_the_real_sftp_server() -> None:
    with _as_user("supervisor"), patch("boxmunge.sftp_receive.os.execv") as execv, \
         patch("sys.argv", ["boxmunge-sftp", "-l", "INFO"]):
        sftp_receive.main()
    execv.assert_called_once_with(
        sftp_receive.REAL_SFTP_SERVER, [sftp_receive.REAL_SFTP_SERVER, "-l", "INFO"],
    )
