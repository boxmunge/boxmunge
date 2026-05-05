"""Tests for boxmunge.security_overlay — resolver + renderer."""
import pytest
from boxmunge.security_overlay import (
    PROFILE_DEFAULT, PROFILE_OFF, KNOWN_PROFILES, RESERVED_PROFILES,
    DEFAULT_CAP_DROP, DEFAULT_PIDS_LIMIT,
)


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
