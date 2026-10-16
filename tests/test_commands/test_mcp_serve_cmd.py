"""mcp-serve without the optional `mcp` package must say how to install it."""

import sys
from unittest.mock import patch

import pytest

from boxmunge.commands.mcp_serve_cmd import cmd_mcp_serve


def test_missing_mcp_package_gives_the_install_instruction(capsys) -> None:
    # A None entry makes `import mcp` raise ModuleNotFoundError, exactly as on
    # a box where the extra was never installed.
    with patch.dict(sys.modules, {"mcp": None}):
        with pytest.raises(SystemExit) as exc:
            cmd_mcp_serve([])
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "requires the 'mcp' package" in err
    assert "pip install" in err
