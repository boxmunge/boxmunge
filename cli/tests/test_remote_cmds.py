# SPDX-License-Identifier: Apache-2.0
"""stage / prod-deploy / promote / status / logs through the real entry point,
with fake ssh and scp on PATH recording what reaches the server."""

from pathlib import Path

import pytest

from boxmunge_cli.cli import main
from boxmunge_cli.init_cmd import run_init


def run_cli(argv: list[str]) -> int:
    with pytest.raises(SystemExit) as exc:
        main(argv)
    return exc.value.code


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_remote) -> Path:
    root = tmp_path / "myapp"
    assert run_init(root, server="box.example.com", host="myapp.example.com") == 0
    monkeypatch.chdir(root)
    return root


def _set_config_project(project: Path, name: str) -> None:
    cfg = project / ".boxmunge"
    cfg.write_text(cfg.read_text().replace("project: myapp", f"project: {name}"))


def _remote_commands(fake_remote) -> list[str]:
    """The command each ssh call runs: everything after the destination."""
    out = []
    for argv in fake_remote.calls("ssh"):
        dest = next(i for i, a in enumerate(argv) if a == "deploy@box.example.com")
        out.append(" ".join(argv[dest + 1:]))
    return out


@pytest.mark.parametrize("command", ["stage", "prod-deploy"])
def test_mismatched_project_is_refused_before_upload(project, fake_remote, command,
                                                     capsys) -> None:
    _set_config_project(project, "other-app")
    assert run_cli([command]) == 1
    assert fake_remote.calls() == []
    err = capsys.readouterr().err
    assert "other-app" in err and "myapp" in err


def test_standalone_bundle_also_checks_the_config(project, tmp_path) -> None:
    _set_config_project(project, "other-app")
    out = tmp_path / "out"
    out.mkdir()
    assert run_cli(["bundle", "--output", str(out)]) == 1
    assert not list(out.iterdir())


@pytest.mark.parametrize("command", ["stage", "prod-deploy"])
def test_ships_and_runs_the_configured_project(project, fake_remote, command) -> None:
    assert run_cli([command]) == 0
    scp = fake_remote.calls("scp")
    assert len(scp) == 1 and Path(scp[0][-2]).name.startswith("myapp-")
    assert scp[0][-1] == "deploy@box.example.com:"
    remote = _remote_commands(fake_remote)
    assert remote[0].endswith("handshake")
    assert remote[-1].endswith(f"{command} myapp")


def test_upload_destination_is_printed(project, fake_remote, capsys) -> None:
    assert run_cli(["prod-deploy"]) == 0
    assert "to deploy@box.example.com:922" in capsys.readouterr().err


def test_prod_deploy_forwards_its_flags(project, fake_remote) -> None:
    assert run_cli(["prod-deploy", "--dry-run", "--no-snapshot"]) == 0
    assert _remote_commands(fake_remote)[-1].endswith("prod-deploy myapp --dry-run --no-snapshot")


def test_prod_deploy_abandon_forwards_without_bundling(project, fake_remote) -> None:
    assert run_cli(["prod-deploy", "--abandon"]) == 0
    assert fake_remote.calls("scp") == []
    assert _remote_commands(fake_remote) == ["handshake", "prod-deploy myapp --abandon"]
    assert not list(project.glob("*.tar.gz"))


@pytest.mark.parametrize("flag", ["--dry-run", "--no-snapshot"])
def test_prod_deploy_abandon_takes_no_other_options(project, fake_remote, flag,
                                                    capsys) -> None:
    assert run_cli(["prod-deploy", "--abandon", flag]) == 2
    assert fake_remote.calls() == []
    assert "--abandon takes no other options" in capsys.readouterr().err


def test_server_failure_is_the_exit_code(project, fake_remote) -> None:
    fake_remote.respond("ssh", "prod-deploy", stderr="ERROR: boom\n", rc=1)
    assert run_cli(["prod-deploy"]) == 1


def test_promote_status_logs(project, fake_remote) -> None:
    assert run_cli(["promote"]) == 0
    assert run_cli(["status", "--json"]) == 0
    assert run_cli(["logs", "web", "--tail", "20", "--follow"]) == 0
    remote = [c for c in _remote_commands(fake_remote) if c != "handshake"]
    assert remote == ["promote myapp", "status --json", "logs myapp web --tail 20 --follow"]


def test_manifest_project_must_be_a_valid_name(project, capsys) -> None:
    manifest = project / "manifest.yml"
    manifest.write_text(manifest.read_text().replace("project: myapp", "project: ../../evil"))
    _set_config_project(project, "myapp")
    assert run_cli(["bundle", "--validate"]) == 1
    assert "project" in capsys.readouterr().err
