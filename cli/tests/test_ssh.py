"""Tests for SSH command building and execution."""

from boxmunge_cli.ssh import build_ssh_cmd, build_scp_cmd, run_ssh, run_scp


class TestBuildSshCmd:
    def test_basic_command(self) -> None:
        config = {"server": "box.example.com", "port": 922, "user": "deploy", "project": "myapp"}
        cmd = build_ssh_cmd(config, "stage", "myapp")
        assert cmd == ["ssh", "-p", "922", "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=15",
                       "deploy@box.example.com", "stage myapp"]

    def test_extra_args(self) -> None:
        config = {"server": "box.example.com", "port": 922, "user": "deploy", "project": "myapp"}
        cmd = build_ssh_cmd(config, "prod-deploy", "myapp", "--dry-run")
        assert cmd == ["ssh", "-p", "922", "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=15",
                       "deploy@box.example.com", "prod-deploy myapp --dry-run"]

    def test_custom_port_and_user(self) -> None:
        config = {"server": "10.0.0.1", "port": 2222, "user": "admin", "project": "myapp"}
        cmd = build_ssh_cmd(config, "status", "myapp")
        assert cmd == ["ssh", "-p", "2222", "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=15",
                       "admin@10.0.0.1", "status myapp"]

    def test_no_project_arg(self) -> None:
        config = {"server": "box.example.com", "port": 922, "user": "deploy", "project": "myapp"}
        cmd = build_ssh_cmd(config, "handshake")
        assert cmd == ["ssh", "-p", "922", "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=15",
                       "deploy@box.example.com", "handshake"]


    def test_arguments_are_quoted_for_the_remote_shell(self) -> None:
        config = {"server": "box.example.com", "port": 922, "user": "deploy", "project": "myapp"}
        cmd = build_ssh_cmd(config, "logs", "myapp", "a b", "$(id)")
        assert cmd[-1] == "logs myapp 'a b' '$(id)'"


class TestBuildScpCmd:
    def test_basic_upload(self) -> None:
        config = {"server": "box.example.com", "port": 922, "user": "deploy", "project": "myapp"}
        cmd = build_scp_cmd(config, "/tmp/myapp-2024.tar.gz")
        assert cmd == ["scp", "-O", "-P", "922", "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=15",
                       "/tmp/myapp-2024.tar.gz", "deploy@box.example.com:"]


    def test_ipv6_is_bracketed_for_scp(self) -> None:
        config = {"server": "2001:db8::1", "port": 922, "user": "deploy", "project": "myapp"}
        assert build_scp_cmd(config, "/tmp/b.tar.gz")[-1] == "deploy@[2001:db8::1]:"
        assert build_ssh_cmd(config, "status")[-2] == "deploy@2001:db8::1"


CONFIG = {"server": "box.example.com", "port": 922, "user": "deploy", "project": "myapp"}


class TestRunSsh:
    def test_runs_ssh_with_the_built_argv(self, fake_remote) -> None:
        assert run_ssh(CONFIG, "status", "myapp") == 0
        assert fake_remote.calls("ssh") == [build_ssh_cmd(CONFIG, "status", "myapp")[1:]]

    def test_returns_the_remote_exit_code(self, fake_remote) -> None:
        fake_remote.respond("ssh", "status", rc=2)
        assert run_ssh(CONFIG, "status") == 2

    def test_ssh_connection_failure_is_exit_4(self, fake_remote) -> None:
        fake_remote.respond("ssh", "status", rc=255)
        assert run_ssh(CONFIG, "status") == 4


class TestRunScp:
    def test_uploads_file(self, fake_remote) -> None:
        assert run_scp(CONFIG, "/tmp/bundle.tar.gz") == 0
        assert fake_remote.calls("scp") == [build_scp_cmd(CONFIG, "/tmp/bundle.tar.gz")[1:]]


class TestLegacyScpProtocol:
    def test_upload_uses_the_legacy_protocol(self) -> None:
        # The deploy user has no SFTP subsystem; OpenSSH 9's scp defaults to SFTP.
        assert build_scp_cmd(CONFIG, "/tmp/b.tar.gz")[:2] == ["scp", "-O"]

    def test_old_scp_without_O_fails_clearly(self, fake_remote, capsys) -> None:
        fake_remote.respond("scp", "-O", stderr="scp: unknown option -- O\nusage: scp ...\n",
                            rc=1)
        assert run_scp(CONFIG, "/tmp/b.tar.gz") == 1
        assert "OpenSSH to 8.7" in capsys.readouterr().err
