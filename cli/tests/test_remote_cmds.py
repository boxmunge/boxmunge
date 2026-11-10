# SPDX-License-Identifier: Apache-2.0
"""stage / prod-deploy / promote / status / logs through the real entry point,
with fake ssh and scp on PATH recording what reaches the server."""

import json
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


@pytest.mark.parametrize("command", ["stage", "prod-deploy", "promote"])
def test_no_pull_is_refused_before_upload_by_an_older_server(project, fake_remote, command,
                                                             capsys) -> None:
    """The fixture's server is 0.11.0."""
    assert run_cli([command, "--no-pull"]) == 3
    assert fake_remote.calls("scp") == []
    assert _remote_commands(fake_remote) == ["handshake"]
    assert "--no-pull needs boxmunge-server 0.11.4" in capsys.readouterr().err


@pytest.mark.parametrize("command", ["stage", "prod-deploy", "promote"])
def test_no_pull_is_forwarded(project, fake_remote, command) -> None:
    fake_remote.respond("ssh", "handshake", stdout=json.dumps({
        "server_version": "0.11.4", "min_client_version": "0.1.0", "schema_version": 3}))
    assert run_cli([command, "--no-pull"]) == 0
    assert _remote_commands(fake_remote)[-1].endswith(f"{command} myapp --no-pull")


@pytest.mark.parametrize("flag", ["--dry-run", "--no-snapshot", "--no-pull"])
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


def _server(fake_remote, version: str) -> None:
    fake_remote.respond("ssh", "handshake", stdout=json.dumps({
        "server_version": version, "min_client_version": "0.1.0", "schema_version": 3}))


def test_redeploy_forwards_without_bundling(project, fake_remote) -> None:
    _server(fake_remote, "0.11.4")
    assert run_cli(["prod-deploy", "--redeploy", "--no-snapshot", "--dry-run"]) == 0
    assert fake_remote.calls("scp") == []
    assert _remote_commands(fake_remote) == [
        "handshake", "prod-deploy myapp --redeploy --dry-run --no-snapshot"]
    assert not list(project.glob("*.tar.gz"))


def test_redeploy_is_refused_by_an_older_server_naming_its_redeploy(project, fake_remote,
                                                                    capsys) -> None:
    """The fixture's server is 0.11.0: a bare prod-deploy with no bundle
    waiting deploys the installed release again there."""
    assert run_cli(["prod-deploy", "--redeploy"]) == 3
    assert _remote_commands(fake_remote) == ["handshake"]
    err = capsys.readouterr().err
    assert "--redeploy needs boxmunge-server 0.11.4" in err
    assert "'boxmunge remote prod-deploy myapp'" in err


def test_ref_deploys_that_release_without_bundling(project, fake_remote) -> None:
    """--ref (any supported server) resumes an open install, or deploys a
    bundle already in the inbox, without uploading the working tree."""
    assert run_cli(["prod-deploy", "--ref", "myapp-20261110T120000Z", "--no-pull"]) == 3
    _server(fake_remote, "0.11.4")
    assert run_cli(["prod-deploy", "--ref", "myapp-20261110T120000Z"]) == 0
    assert fake_remote.calls("scp") == []
    assert _remote_commands(fake_remote)[-1] == "prod-deploy myapp --ref myapp-20261110T120000Z"


def test_accept_stale_kev_is_forwarded_with_the_upload(project, fake_remote) -> None:
    _server(fake_remote, "0.11.5")
    assert run_cli(["prod-deploy", "--accept-stale-kev"]) == 0
    assert len(fake_remote.calls("scp")) == 1
    assert _remote_commands(fake_remote)[-1] == "prod-deploy myapp --accept-stale-kev"


@pytest.mark.parametrize("mode", [["--redeploy"], ["--ref", "abc123"]])
def test_accept_stale_kev_goes_with_a_deploy_of_no_upload(project, fake_remote, mode) -> None:
    _server(fake_remote, "0.11.5")
    assert run_cli(["prod-deploy", *mode, "--accept-stale-kev"]) == 0
    assert fake_remote.calls("scp") == []
    assert _remote_commands(fake_remote)[-1] == " ".join(
        ["prod-deploy", "myapp", *mode, "--accept-stale-kev"])


def test_accept_stale_kev_is_refused_before_upload_by_an_older_server(project, fake_remote,
                                                                      capsys) -> None:
    _server(fake_remote, "0.11.4")
    assert run_cli(["prod-deploy", "--accept-stale-kev"]) == 3
    assert fake_remote.calls("scp") == []
    assert _remote_commands(fake_remote) == ["handshake"]
    err = capsys.readouterr().err
    assert "--accept-stale-kev needs boxmunge-server 0.11.5" in err
    assert "Nothing was sent" in err and "without --accept-stale-kev" not in err


@pytest.mark.parametrize("argv", [
    ["--redeploy", "--ref", "abc123"],
    ["--abandon", "--redeploy"],
    ["--abandon", "--ref", "abc123"],
    ["--abandon", "--accept-stale-kev"],
])
def test_prod_deploy_modes_exclude_each_other(project, fake_remote, argv) -> None:
    assert run_cli(["prod-deploy", *argv]) == 2
    assert fake_remote.calls() == []


def test_logs_staging_is_forwarded(project, fake_remote) -> None:
    _server(fake_remote, "0.11.4")
    assert run_cli(["logs", "web", "--staging", "--tail", "5"]) == 0
    assert _remote_commands(fake_remote)[-1] == "logs myapp web --tail 5 --staging"


def test_logs_staging_is_refused_by_an_older_server(project, fake_remote, capsys) -> None:
    assert run_cli(["logs", "--staging"]) == 3
    assert _remote_commands(fake_remote) == ["handshake"]
    assert "--staging needs boxmunge-server 0.11.4" in capsys.readouterr().err
