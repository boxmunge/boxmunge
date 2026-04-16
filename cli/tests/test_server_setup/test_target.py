"""Tests for server-setup target parsing."""

import pytest

from boxmunge_cli.server_setup.target import parse_target, is_ip_address


class TestParseTarget:
    def test_hostname_only(self) -> None:
        user, host = parse_target("myserver.example.com")
        assert user == "root"
        assert host == "myserver.example.com"

    def test_user_at_hostname(self) -> None:
        user, host = parse_target("admin@myserver.example.com")
        assert user == "admin"
        assert host == "myserver.example.com"

    def test_root_at_hostname(self) -> None:
        user, host = parse_target("root@myserver.example.com")
        assert user == "root"
        assert host == "myserver.example.com"

    def test_ip_address(self) -> None:
        user, host = parse_target("203.0.113.50")
        assert user == "root"
        assert host == "203.0.113.50"

    def test_user_at_ip(self) -> None:
        user, host = parse_target("admin@203.0.113.50")
        assert user == "admin"
        assert host == "203.0.113.50"


class TestIsIpAddress:
    def test_ipv4(self) -> None:
        assert is_ip_address("203.0.113.50") is True

    def test_ipv6_loopback(self) -> None:
        assert is_ip_address("::1") is True

    def test_ipv6_full(self) -> None:
        assert is_ip_address("2001:db8::1") is True

    def test_hostname(self) -> None:
        assert is_ip_address("myserver.example.com") is False

    def test_short_hostname(self) -> None:
        assert is_ip_address("myserver") is False
