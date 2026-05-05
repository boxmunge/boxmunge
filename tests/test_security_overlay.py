"""Tests for boxmunge.security_overlay — resolver + renderer."""
import pytest
from boxmunge.security_overlay import (
    PROFILE_DEFAULT, PROFILE_OFF, KNOWN_PROFILES, RESERVED_PROFILES,
    DEFAULT_CAP_DROP, DEFAULT_PIDS_LIMIT,
)
from boxmunge.security_overlay import resolve_security


class TestDefaultProfile:
    def test_absent_security_block_yields_default_payload(self) -> None:
        # No project-level security, no service-level security.
        result = resolve_security(project_security=None, service_security=None)
        assert result["security_opt"] == ["no-new-privileges:true"]
        assert result["init"] is True
        assert result["pids_limit"] == 512
        assert "NET_ADMIN" in result["cap_drop"]
        assert "NET_RAW" in result["cap_drop"]
        assert result["cap_add"] == []

    def test_explicit_default_profile_yields_same_payload(self) -> None:
        result = resolve_security(
            project_security={"profile": "default"},
            service_security=None,
        )
        assert result["security_opt"] == ["no-new-privileges:true"]
        assert result["pids_limit"] == 512


class TestConstants:
    def test_profile_names_match_spec(self) -> None:
        assert PROFILE_DEFAULT == "default"
        assert PROFILE_OFF == "off"
        assert KNOWN_PROFILES == {"default", "off"}
        assert "strict" in RESERVED_PROFILES
        assert "paranoid" in RESERVED_PROFILES

    def test_default_cap_drop_includes_required_caps(self) -> None:
        for cap in (
            "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "SYS_RAWIO",
            "SYS_TIME", "SYS_BOOT", "MAC_ADMIN", "MAC_OVERRIDE",
            "MKNOD", "AUDIT_WRITE", "WAKE_ALARM", "BLOCK_SUSPEND",
            "LEASE", "NET_RAW",
        ):
            assert cap in DEFAULT_CAP_DROP, f"{cap} missing from DEFAULT_CAP_DROP"

    def test_default_pids_limit(self) -> None:
        assert DEFAULT_PIDS_LIMIT == 512


class TestOffProfile:
    def test_off_profile_yields_empty_payload(self) -> None:
        result = resolve_security(
            project_security={"profile": "off", "reason": "needed"},
            service_security=None,
        )
        assert result == {}

    def test_service_off_overrides_project_default(self) -> None:
        result = resolve_security(
            project_security={"profile": "default"},
            service_security={"profile": "off", "reason": "deliberate"},
        )
        assert result == {}
