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


class TestProjectFieldOverrides:
    def test_pids_limit_override(self) -> None:
        result = resolve_security(
            project_security={"profile": "default", "pids_limit": 2048},
            service_security=None,
        )
        assert result["pids_limit"] == 2048

    def test_no_new_privileges_explicit_false_disables(self) -> None:
        result = resolve_security(
            project_security={"profile": "default", "no_new_privileges": False},
            service_security=None,
        )
        assert "no-new-privileges:true" not in result.get("security_opt", [])

    def test_init_explicit_false_disables(self) -> None:
        result = resolve_security(
            project_security={"profile": "default", "init": False},
            service_security=None,
        )
        assert result.get("init") is False or "init" not in result

    def test_cap_drop_replaces_default_list(self) -> None:
        result = resolve_security(
            project_security={"profile": "default", "cap_drop": ["NET_ADMIN"]},
            service_security=None,
        )
        assert result["cap_drop"] == ["NET_ADMIN"]
        assert "NET_RAW" not in result["cap_drop"]

    def test_omitted_field_inherits_profile_value(self) -> None:
        # Override only pids_limit. cap_drop must remain the default list.
        result = resolve_security(
            project_security={"profile": "default", "pids_limit": 1024},
            service_security=None,
        )
        assert "NET_ADMIN" in result["cap_drop"]
        assert result["pids_limit"] == 1024


class TestCapAddSubtractsFromDrop:
    def test_cap_add_removes_matching_drop(self) -> None:
        result = resolve_security(
            project_security={"profile": "default"},
            service_security={"cap_add": ["NET_RAW"]},
        )
        assert "NET_RAW" not in result["cap_drop"]
        # Other drops untouched
        assert "SYS_PTRACE" in result["cap_drop"]
        assert "NET_RAW" in result["cap_add"]

    def test_cap_add_with_cap_drop_override(self) -> None:
        result = resolve_security(
            project_security={
                "profile": "default",
                "cap_drop": ["NET_ADMIN", "NET_RAW"],
            },
            service_security={"cap_add": ["NET_RAW"]},
        )
        assert result["cap_drop"] == ["NET_ADMIN"]
        assert result["cap_add"] == ["NET_RAW"]


class TestServiceFieldOverrides:
    def test_service_pids_overrides_project_pids(self) -> None:
        result = resolve_security(
            project_security={"profile": "default", "pids_limit": 1024},
            service_security={"pids_limit": 4096},
        )
        assert result["pids_limit"] == 4096

    def test_service_inherits_when_block_absent(self) -> None:
        result = resolve_security(
            project_security={"profile": "default", "pids_limit": 1024},
            service_security=None,
        )
        assert result["pids_limit"] == 1024


from boxmunge.security_overlay import (
    validate_security_block, SecurityValidationError,
)


class TestValidation:
    def test_default_profile_no_block_passes(self) -> None:
        validate_security_block(None, context="project")

    def test_unknown_profile_rejected(self) -> None:
        with pytest.raises(SecurityValidationError, match="Unknown profile"):
            validate_security_block({"profile": "custom"}, context="project")

    def test_reserved_profile_rejected_in_v05(self) -> None:
        with pytest.raises(SecurityValidationError, match="reserved"):
            validate_security_block({"profile": "strict"}, context="project")

    def test_invalid_cap_name_in_drop_rejected(self) -> None:
        with pytest.raises(SecurityValidationError, match="Unknown capability"):
            validate_security_block(
                {"cap_drop": ["NET_ADMIN", "SYS_NUKE"]}, context="project"
            )

    def test_invalid_cap_name_in_add_rejected(self) -> None:
        with pytest.raises(SecurityValidationError, match="Unknown capability"):
            validate_security_block(
                {"cap_add": ["FOO_BAR"]}, context="project"
            )

    def test_negative_pids_limit_rejected(self) -> None:
        with pytest.raises(SecurityValidationError, match="pids_limit"):
            validate_security_block({"pids_limit": -1}, context="project")

    def test_pids_limit_zero_accepted_as_disable(self) -> None:
        # 0 is the explicit-disable sentinel.
        validate_security_block({"pids_limit": 0}, context="project")

    def test_pids_limit_string_rejected(self) -> None:
        with pytest.raises(SecurityValidationError, match="pids_limit"):
            validate_security_block({"pids_limit": "many"}, context="project")
