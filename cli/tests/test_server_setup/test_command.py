# SPDX-License-Identifier: Apache-2.0
"""Tests for the server-setup command orchestrator."""

import pytest
from unittest.mock import patch, MagicMock
from io import StringIO

from boxmunge_cli.server_setup.command import parse_args, ServerSetupArgs


class TestParseArgs:
    def test_minimal(self) -> None:
        args = parse_args(["myserver.example.com", "--email", "a@b.com"])
        assert args.user == "root"
        assert args.host == "myserver.example.com"
        assert args.port == 22
        assert args.email == "a@b.com"

    def test_user_at_host(self) -> None:
        args = parse_args(["admin@myserver.example.com", "--email", "a@b.com"])
        assert args.user == "admin"
        assert args.host == "myserver.example.com"

    def test_custom_port(self) -> None:
        args = parse_args(["myserver.example.com", "-p", "322", "--email", "a@b.com"])
        assert args.port == 322

    def test_all_flags(self) -> None:
        args = parse_args([
            "myserver.example.com", "--email", "a@b.com",
            "--ssh-key", "/tmp/key.pub",
            "--hostname", "custom.example.com",
            "--boxmunge-ssh-port", "2222",
            "--no-aide", "--no-crowdsec", "--no-auto-updates",
            "--reboot-window", "05:00",
        ])
        assert args.ssh_key_arg == "/tmp/key.pub"
        assert args.hostname == "custom.example.com"
        assert args.boxmunge_ssh_port == 2222
        assert args.no_aide is True
        assert args.no_crowdsec is True
        assert args.no_auto_updates is True
        assert args.reboot_window == "05:00"

    def test_missing_email_raises(self) -> None:
        with pytest.raises(SystemExit):
            parse_args(["myserver.example.com"])

    def test_missing_target_raises(self) -> None:
        with pytest.raises(SystemExit):
            parse_args(["--email", "a@b.com"])

    def test_hostname_defaults_from_target(self) -> None:
        args = parse_args(["myserver.example.com", "--email", "a@b.com"])
        assert args.hostname == "myserver.example.com"

    def test_hostname_from_ip_is_none(self) -> None:
        args = parse_args(["203.0.113.50", "--email", "a@b.com"])
        assert args.hostname is None
