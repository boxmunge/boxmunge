"""Tests for the client/server compatibility handshake (fake ssh on PATH)."""

import json
from pathlib import Path

import pytest

from boxmunge_cli import handshake
from boxmunge_cli.cli import main
from boxmunge_cli.handshake import HandshakeError, MIN_SERVER_VERSION, check_server_compatibility
from boxmunge_cli.init_cmd import run_init
from boxmunge_cli.version import parse_version

CONFIG = {"server": "box.example.com", "port": 922, "user": "deploy", "project": "myapp"}


def _reply(fake_remote, **fields) -> None:
    data = {"server_version": "0.11.0", "min_client_version": "0.1.0", "schema_version": 3}
    data.update(fields)
    fake_remote.respond("ssh", "handshake", stdout=json.dumps(data))


def test_compatible(fake_remote) -> None:
    info = check_server_compatibility(CONFIG)
    assert info.schema_version == 3


def test_client_too_old(fake_remote) -> None:
    _reply(fake_remote, min_client_version="99.0.0")
    with pytest.raises(HandshakeError, match="pip install --upgrade boxmunge"):
        check_server_compatibility(CONFIG)


def test_server_too_old(fake_remote) -> None:
    _reply(fake_remote, server_version="0.9.4")
    with pytest.raises(HandshakeError, match=MIN_SERVER_VERSION):
        check_server_compatibility(CONFIG)


def test_server_line_is_not_compared_with_the_client_line(fake_remote, monkeypatch,
                                                          capsys) -> None:
    monkeypatch.setattr(handshake, "__version__", "0.11.0")
    _reply(fake_remote, server_version="0.10.0")
    check_server_compatibility(CONFIG)
    assert capsys.readouterr().err == ""


@pytest.mark.parametrize("client, minimum, ok", [
    ("0.2.0rc1", "0.2.0", False),
    ("0.2.0rc1", "0.1.0", True),
    ("0.2.0", "0.2.0rc1", True),
    ("0.2.0.dev3", "0.2.0a1", False),
])
def test_pre_release_clients(fake_remote, monkeypatch, client, minimum, ok) -> None:
    monkeypatch.setattr(handshake, "__version__", client)
    _reply(fake_remote, min_client_version=minimum)
    if ok:
        check_server_compatibility(CONFIG)
    else:
        with pytest.raises(HandshakeError, match="too old"):
            check_server_compatibility(CONFIG)


@pytest.mark.parametrize("server", ["0.11.0rc1", "0.10.1.dev3", "0.10.0+local.1"])
def test_pre_release_servers(fake_remote, server) -> None:
    _reply(fake_remote, server_version=server)
    check_server_compatibility(CONFIG)


@pytest.mark.parametrize("fields", [
    {"server_version": 10}, {"server_version": "ten"}, {"min_client_version": None},
    {"schema_version": True}, {"schema_version": "3"}, {"schema_version": 0},
])
def test_malformed_fields_are_errors_not_tracebacks(fake_remote, fields) -> None:
    _reply(fake_remote, **fields)
    with pytest.raises(HandshakeError, match="Invalid handshake response"):
        check_server_compatibility(CONFIG)


@pytest.mark.parametrize("stdout", ["not json", "[1, 2]", "{}"])
def test_malformed_responses(fake_remote, stdout) -> None:
    fake_remote.respond("ssh", "handshake", stdout=stdout)
    with pytest.raises(HandshakeError, match="[Mm]alformed|Invalid"):
        check_server_compatibility(CONFIG)


def test_ssh_error_is_shown(fake_remote) -> None:
    fake_remote.respond("ssh", "handshake", stderr="deploy@box.example.com: Permission "
                        "denied (publickey).\n", rc=255)
    with pytest.raises(HandshakeError, match=r"Permission denied \(publickey\)"):
        check_server_compatibility(CONFIG)


def test_newer_manifest_schema_is_refused(fake_remote) -> None:
    with pytest.raises(HandshakeError, match="schema_version 4"):
        check_server_compatibility(CONFIG, manifest_schema=4)


def test_version_ordering() -> None:
    ordered = ["0.1.0", "0.2.0.dev1", "0.2.0a1", "0.2.0b2", "0.2.0rc1", "0.2.0",
               "0.2.0.post1", "0.2.1", "0.10.0", "1.0"]
    keys = [parse_version(v) for v in ordered]
    assert keys == sorted(keys)
    assert parse_version("0.2") == parse_version("0.2.0")


@pytest.fixture
def project(tmp_path: Path, monkeypatch, fake_remote) -> Path:
    root = tmp_path / "myapp"
    assert run_init(root, server="box.example.com", host="myapp.example.com") == 0
    monkeypatch.chdir(root)
    return root


def _run(argv: list[str]) -> int:
    with pytest.raises(SystemExit) as exc:
        main(argv)
    return exc.value.code


@pytest.mark.parametrize("argv", [["promote"], ["status"], ["logs"], ["mcp-serve"]])
def test_every_server_command_handshakes_first(project, fake_remote, argv) -> None:
    assert _run(argv) == 0
    first = fake_remote.calls("ssh")[0]
    assert first[-1] == "handshake"


def test_incompatible_server_stops_before_upload(project, fake_remote, capsys) -> None:
    _reply(fake_remote, schema_version=2)
    assert _run(["prod-deploy"]) == 1
    assert fake_remote.calls("scp") == []
    assert "schema_version 3" in capsys.readouterr().err
