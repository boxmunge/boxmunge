"""mcp-serve without the `mcp` package, which every install includes, must
say how to repair the environment."""

import sys
from unittest.mock import patch

import pytest

from boxmunge.commands.mcp_serve_cmd import cmd_mcp_serve


def test_missing_mcp_package_gives_the_repair(capsys) -> None:
    # A None entry makes `import mcp` raise ModuleNotFoundError, exactly as in
    # an environment built without requirements-mcp.txt.
    with patch.dict(sys.modules, {"mcp": None}):
        with pytest.raises(SystemExit) as exc:
            cmd_mcp_serve([])
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "requires the 'mcp' package" in err
    assert "requirements-mcp.txt" in err
    assert "sudo bash boxmunge-install.sh" in err
    # Never an unpinned install into the live venv: the next upgrade drops it.
    assert "pip install" not in err
