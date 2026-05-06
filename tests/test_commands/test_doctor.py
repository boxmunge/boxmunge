# SPDX-License-Identifier: Apache-2.0
"""Tests for boxmunge doctor command — host health diagnostic."""

import json

import pytest

from boxmunge.commands.doctor import cmd_doctor
from boxmunge.paths import BoxPaths


class TestDoctorJson:
    """Audit H-5: `--json` must suppress the banner so output stays parseable."""

    def test_json_output_is_parseable(
        self, paths: BoxPaths, capsys, monkeypatch,
    ) -> None:
        monkeypatch.setattr(
            "boxmunge.commands.doctor.BoxPaths", lambda: paths,
        )
        with pytest.raises(SystemExit):
            cmd_doctor(["--json"])
        out = capsys.readouterr().out
        # No banner pollution: the entire stdout must parse as JSON.
        payload = json.loads(out)
        assert isinstance(payload, list)
        # Each result has the documented shape
        for r in payload:
            assert {"name", "status", "detail"} <= r.keys()

    def test_text_output_includes_banner(
        self, paths: BoxPaths, capsys, monkeypatch,
    ) -> None:
        monkeypatch.setattr(
            "boxmunge.commands.doctor.BoxPaths", lambda: paths,
        )
        with pytest.raises(SystemExit):
            cmd_doctor([])
        out = capsys.readouterr().out
        assert "boxmunge doctor" in out


class TestDoctorUnknownArg:
    """Audit H-N1: cmd_doctor rejects unknown flags."""

    def test_unknown_flag_exits_2(self, capsys) -> None:
        with pytest.raises(SystemExit) as exc:
            cmd_doctor(["--not-a-flag"])
        assert exc.value.code == 2
        err = capsys.readouterr().err
        assert "ERROR" in err
        assert "--not-a-flag" in err
