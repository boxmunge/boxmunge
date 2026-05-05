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


class TestYamlBooleanTrap:
    """Audit Finding 4: PyYAML parses unquoted `off` as YAML 1.1 boolean False.

    Without the targeted check, the operator sees a confusing
    ``Unknown profile False`` message and may not realise the fix is to
    quote the literal string in their manifest.
    """

    def test_profile_false_yields_targeted_error(self) -> None:
        with pytest.raises(SecurityValidationError) as exc:
            validate_security_block({"profile": False}, context="project")
        msg = str(exc.value)
        assert "boolean" in msg.lower()
        assert 'profile: "off"' in msg
        # Must NOT degrade to the cryptic generic "Unknown profile False"
        assert "Unknown profile False" not in msg

    def test_profile_true_also_caught(self) -> None:
        # `on` -> True is the symmetric trap; same fix applies.
        with pytest.raises(SecurityValidationError) as exc:
            validate_security_block({"profile": True}, context="project")
        assert "boolean" in str(exc.value).lower()


class TestReasonRequired:
    def test_off_without_reason_rejected(self) -> None:
        with pytest.raises(SecurityValidationError, match="reason"):
            validate_security_block({"profile": "off"}, context="project")

    def test_off_with_empty_reason_rejected(self) -> None:
        with pytest.raises(SecurityValidationError, match="reason"):
            validate_security_block(
                {"profile": "off", "reason": ""}, context="project"
            )

    def test_off_with_whitespace_reason_rejected(self) -> None:
        with pytest.raises(SecurityValidationError, match="reason"):
            validate_security_block(
                {"profile": "off", "reason": "   \t\n"}, context="project"
            )

    def test_off_with_real_reason_passes(self) -> None:
        validate_security_block(
            {"profile": "off", "reason": "deliberate honeypot, see #42"},
            context="project",
        )

    def test_default_profile_doesnt_require_reason(self) -> None:
        validate_security_block({"profile": "default"}, context="project")
        validate_security_block(
            {"profile": "default", "pids_limit": 2048}, context="project"
        )


from boxmunge.security_overlay import services_with_off_profile


class TestEnumerationShapeGuards:
    """Audit Finding 11: services_with_off_profile / services_with_overrides
    must not AttributeError on a malformed services section. Validation
    catches the problem upstream, but these helpers are also called from
    health and check paths after potentially partial validation."""

    def test_off_profile_services_as_list_returns_empty(self) -> None:
        manifest = {"project": "demo", "services": ["a", "b"]}
        assert services_with_off_profile(manifest) == []

    def test_off_profile_services_as_string_returns_empty(self) -> None:
        manifest = {"project": "demo", "services": "web"}
        assert services_with_off_profile(manifest) == []

    def test_off_profile_services_missing_returns_empty(self) -> None:
        manifest = {"project": "demo"}
        assert services_with_off_profile(manifest) == []

    def test_overrides_services_as_list_returns_empty(self) -> None:
        from boxmunge.security_overlay import services_with_overrides
        manifest = {"project": "demo", "services": ["a", "b"]}
        assert services_with_overrides(manifest) == []


class TestOffProfileEnumeration:
    def test_no_security_block_returns_empty(self) -> None:
        manifest = {
            "project": "demo",
            "services": {"web": {"port": 3000}},
        }
        assert services_with_off_profile(manifest) == []

    def test_project_off_lists_all_services(self) -> None:
        manifest = {
            "project": "demo",
            "security": {"profile": "off", "reason": "test"},
            "services": {
                "web": {"port": 3000},
                "worker": {"port": 4000},
            },
        }
        result = services_with_off_profile(manifest)
        assert sorted(s for s, _ in result) == ["web", "worker"]
        assert all(reason == "test" for _, reason in result)

    def test_service_off_overrides_project_default(self) -> None:
        manifest = {
            "project": "demo",
            "security": {"profile": "default"},
            "services": {
                "web": {
                    "port": 3000,
                    "security": {"profile": "off", "reason": "honeypot"},
                },
                "worker": {"port": 4000},
            },
        }
        result = services_with_off_profile(manifest)
        assert result == [("web", "honeypot")]

    def test_service_default_overrides_project_off(self) -> None:
        manifest = {
            "project": "demo",
            "security": {"profile": "off", "reason": "lifted by services"},
            "services": {
                "web": {
                    "port": 3000,
                    "security": {"profile": "default"},
                },
            },
        }
        assert services_with_off_profile(manifest) == []


from boxmunge.security_overlay import services_with_overrides


class TestServicesWithOverrides:
    """F4: surface per-flag overrides for info-level visibility."""

    def test_default_profile_no_overrides_returns_empty(self) -> None:
        manifest = {
            "project": "demo",
            "services": {"web": {"port": 3000}},
        }
        assert services_with_overrides(manifest) == []

    def test_explicit_default_no_overrides_returns_empty(self) -> None:
        manifest = {
            "project": "demo",
            "security": {"profile": "default"},
            "services": {"web": {"port": 3000}},
        }
        assert services_with_overrides(manifest) == []

    def test_off_services_excluded(self) -> None:
        # off is handled by services_with_off_profile at warn level.
        manifest = {
            "project": "demo",
            "services": {
                "web": {
                    "port": 3000,
                    "security": {"profile": "off", "reason": "x"},
                },
            },
        }
        assert services_with_overrides(manifest) == []

    def test_cap_add_surfaced(self) -> None:
        manifest = {
            "project": "demo",
            "services": {
                "web": {
                    "port": 3000,
                    "security": {"cap_add": ["NET_RAW"]},
                },
            },
        }
        result = services_with_overrides(manifest)
        assert len(result) == 1
        svc_name, diffs = result[0]
        assert svc_name == "web"
        # cap_add and the resulting cap_drop change should both appear.
        assert any("cap_add" in d and "NET_RAW" in d for d in diffs)

    def test_pids_limit_override_surfaced(self) -> None:
        manifest = {
            "project": "demo",
            "services": {
                "web": {
                    "port": 3000,
                    "security": {"pids_limit": 4096},
                },
            },
        }
        result = services_with_overrides(manifest)
        assert result == [("web", ["pids_limit=4096"])]

    def test_no_new_privileges_disable_surfaced(self) -> None:
        manifest = {
            "project": "demo",
            "services": {
                "web": {
                    "port": 3000,
                    "security": {"no_new_privileges": False},
                },
            },
        }
        result = services_with_overrides(manifest)
        assert len(result) == 1
        assert any("no_new_privileges" in d for d in result[0][1])

    def test_project_level_override_applies_to_all_services(self) -> None:
        manifest = {
            "project": "demo",
            "security": {"pids_limit": 2048},
            "services": {
                "web": {"port": 3000},
                "worker": {"port": 4000},
            },
        }
        result = services_with_overrides(manifest)
        names = sorted(s for s, _ in result)
        assert names == ["web", "worker"]


from boxmunge.security_overlay import render_compose_security_fragment


class TestComposeFragment:
    def test_default_renders_all_keys(self) -> None:
        fragment = render_compose_security_fragment({
            "security_opt": ["no-new-privileges:true"],
            "init": True,
            "pids_limit": 512,
            "cap_drop": ["NET_RAW"],
            "cap_add": [],
        })
        assert fragment["security_opt"] == ["no-new-privileges:true"]
        assert fragment["init"] is True
        assert fragment["pids_limit"] == 512
        assert fragment["cap_drop"] == ["NET_RAW"]
        assert "cap_add" not in fragment

    def test_off_yields_empty_fragment(self) -> None:
        fragment = render_compose_security_fragment({})
        assert fragment == {}

    def test_empty_cap_drop_omitted(self) -> None:
        fragment = render_compose_security_fragment({"cap_drop": []})
        assert "cap_drop" not in fragment


from boxmunge.security_overlay import format_off_warning


class TestOffWarningFormat:
    def test_no_off_services_yields_empty(self) -> None:
        msg = format_off_warning(project="demo", off_services=[])
        assert msg == ""

    def test_single_off_service_includes_reason_and_keyword(self) -> None:
        msg = format_off_warning(
            project="demo",
            off_services=[("worker", "deliberate honeypot, see #42")],
        )
        assert "SECURITY OFF" in msg
        assert "demo/worker" in msg
        assert "deliberate honeypot, see #42" in msg

    def test_multiple_services_listed(self) -> None:
        msg = format_off_warning(
            project="demo",
            off_services=[("web", "r1"), ("worker", "r2")],
        )
        assert "demo/web" in msg
        assert "demo/worker" in msg
        assert "r1" in msg
        assert "r2" in msg
