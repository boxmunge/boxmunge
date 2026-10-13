"""Tests for the internal _discover-update CLI command."""
import json
from unittest.mock import patch

import pytest

from boxmunge.commands.discover_update_cmd import cmd_discover_update


def _run(args, tmp_root, config=None):
    if config is not None:
        (tmp_root / "config" / "boxmunge.yml").write_text(config)
    with patch("boxmunge.commands.discover_update_cmd.BoxPaths") as bp, \
         patch("boxmunge.commands.discover_update_cmd.discover_update") as m:
        from boxmunge.paths import BoxPaths
        bp.return_value = BoxPaths(root=tmp_root)
        m.return_value = {"action": "up_to_date", "current_version": "0.3.5"}
        with pytest.raises(SystemExit) as exc:
            cmd_discover_update(args)
    return exc.value.code, m


BASE = "hostname: t\nadmin_email: a@b\n"


class TestCmdDiscoverUpdate:
    def test_emits_json_to_stdout(self, capsys, tmp_root):
        code, m = _run(["--json"], tmp_root)
        assert code == 0
        assert json.loads(capsys.readouterr().out)["action"] == "up_to_date"
        assert m.call_args.kwargs["mode"] == "latest"

    def test_auto_uses_breakfix_by_default(self, tmp_root):
        _, m = _run(["--json", "--auto"], tmp_root, config=BASE)
        assert m.call_args.kwargs["mode"] == "breakfix"

    def test_auto_honours_breakfix_disabled(self, tmp_root):
        _, m = _run(["--json", "--auto"], tmp_root,
                    config=BASE + "auto_update:\n  breakfix: false\n")
        assert m.call_args.kwargs["mode"] == "security"

    def test_auto_with_bad_config_reports_error_json(self, capsys, tmp_root):
        code, m = _run(["--json", "--auto"], tmp_root,
                       config=BASE + "auto_update:\n  breakfix: maybe\n")
        assert code == 0
        out = json.loads(capsys.readouterr().out)
        assert out["action"] == "error"
        assert "auto_update.breakfix" in out["message"]
        m.assert_not_called()

    def test_requires_json_flag(self, tmp_root):
        code, _ = _run([], tmp_root)
        assert code == 2

    def test_rejects_unknown_flags(self, capsys, tmp_root):
        code, m = _run(["--json", "--security-only"], tmp_root)
        assert code == 2
        assert "--security-only" in capsys.readouterr().err
        m.assert_not_called()
