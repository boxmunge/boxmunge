# SPDX-License-Identifier: Apache-2.0
"""One corrupt quarantine record reads the same way everywhere: the CLI
views print an ERROR line naming the file and exit 1, the actions fail
naming it, and nothing ends in a traceback."""
from __future__ import annotations

import json

import pytest

from boxmunge.api.dev.fixture_host import FixtureHost
from boxmunge.api.principal import Principal, Tier
from boxmunge.api.result import ActionError, ErrorCode
from boxmunge.commands.security_cmd import cmd_security
from boxmunge.commands.status import run_status
from tests.api.fakes import make_invoker

WEBUI = Principal.plugin("webui", Tier.OBSERVE)


def _corrupt(path, kind: str) -> None:
    if kind == "not-json":
        path.write_text("{not json")
    else:
        record = json.loads(path.read_text())
        record["explanation"] = None
        path.write_text(json.dumps(record))


@pytest.fixture(params=["not-json", "null-field"])
def corrupt(request, fixture_paths, monkeypatch):
    path = fixture_paths.project_quarantine_state("billing")
    _corrupt(path, request.param)
    monkeypatch.setattr("boxmunge.commands.security_cmd._paths", lambda: fixture_paths)
    return fixture_paths, path


def test_status(corrupt, capsys) -> None:
    paths, path = corrupt
    assert run_status(paths, as_json=True) == 1
    err = capsys.readouterr().err
    assert "ERROR: status: billing:" in err and str(path) in err


@pytest.mark.parametrize("argv", [["--json"], [], ["billing"], ["billing", "--json"]])
def test_security_views(corrupt, capsys, argv) -> None:
    _, path = corrupt
    with pytest.raises(SystemExit) as exc:
        cmd_security(argv)
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "ERROR: " in err and str(path) in err and "Traceback" not in err


@pytest.mark.parametrize("action", ["project.get", "security.project"])
def test_actions(corrupt, action) -> None:
    paths, path = corrupt
    with pytest.raises(ActionError) as excinfo:
        make_invoker(paths, host=FixtureHost(paths)).invoke(
            action, {"project": "billing"}, WEBUI)
    assert excinfo.value.code is ErrorCode.FAILED
    assert str(path) in excinfo.value.message
