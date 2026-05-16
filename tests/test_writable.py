"""Tests for boxmunge.writable — validation, translation, state classification."""
import re

import pytest

from boxmunge.writable import (
    NAME_PATTERN,
    RESERVED_ROOTS,
    WritableState,
    WritableValidationError,
    classify_state,
    validate_writable_block,
)


class TestConstants:
    def test_writable_state_values(self) -> None:
        assert WritableState.DEFAULT.value == "default"
        assert WritableState.MANAGED.value == "manifest-managed"
        assert WritableState.EXTERNAL.value == "externally-managed"

    def test_reserved_roots(self) -> None:
        for r in (
            "/", "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64",
            "/boot", "/proc", "/sys", "/dev",
        ):
            assert r in RESERVED_ROOTS

    def test_name_pattern_accepts_normal(self) -> None:
        assert re.match(NAME_PATTERN, "dbdata")
        assert re.match(NAME_PATTERN, "uploads-2025")
        assert re.match(NAME_PATTERN, "0abc")

    def test_name_pattern_rejects(self) -> None:
        for bad in (
            "", "-leading", "UPPER", "with spaces",
            "a" * 32, "with_underscore",
        ):
            assert not re.match(NAME_PATTERN, bad), f"{bad!r} should be rejected"


class TestPathValidation:
    def test_absolute_path_required(self) -> None:
        with pytest.raises(WritableValidationError, match="absolute"):
            validate_writable_block({"ephemeral": ["relative/path"]}, "web")

    def test_no_dotdot(self) -> None:
        with pytest.raises(WritableValidationError, match=r"\.\."):
            validate_writable_block({"ephemeral": ["/var/../etc"]}, "web")

    def test_persistent_no_trailing_slash(self) -> None:
        block = {"persistent": [{"name": "data", "mount": "/app/data/"}]}
        with pytest.raises(WritableValidationError, match="trailing slash"):
            validate_writable_block(block, "web")

    def test_persistent_reserved_root_rejected(self) -> None:
        block = {"persistent": [{"name": "etc", "mount": "/etc"}]}
        with pytest.raises(WritableValidationError, match="reserved"):
            validate_writable_block(block, "web")

    def test_persistent_tmp_path_rejected(self) -> None:
        block = {"persistent": [{"name": "t", "mount": "/tmp"}]}
        with pytest.raises(WritableValidationError, match="ephemeral"):
            validate_writable_block(block, "web")

    def test_persistent_var_run_rejected(self) -> None:
        block = {"persistent": [{"name": "r", "mount": "/var/run"}]}
        with pytest.raises(WritableValidationError, match="ephemeral"):
            validate_writable_block(block, "web")

    def test_path_too_long_rejected(self) -> None:
        block = {"ephemeral": ["/" + "a" * 300]}
        with pytest.raises(WritableValidationError, match="too long"):
            validate_writable_block(block, "web")

    def test_ephemeral_must_be_list(self) -> None:
        with pytest.raises(WritableValidationError, match="list"):
            validate_writable_block({"ephemeral": "/tmp"}, "web")

    def test_persistent_must_be_list(self) -> None:
        with pytest.raises(WritableValidationError, match="list"):
            validate_writable_block({"persistent": {"name": "d", "mount": "/x"}}, "web")

    def test_persistent_entry_must_be_mapping(self) -> None:
        with pytest.raises(WritableValidationError, match="mapping"):
            validate_writable_block({"persistent": ["dbdata:/data"]}, "web")

    def test_persistent_entry_requires_name(self) -> None:
        with pytest.raises(WritableValidationError, match="name"):
            validate_writable_block({"persistent": [{"mount": "/x"}]}, "web")

    def test_persistent_entry_requires_mount(self) -> None:
        with pytest.raises(WritableValidationError, match="mount"):
            validate_writable_block({"persistent": [{"name": "d"}]}, "web")

    def test_ephemeral_duplicates_rejected(self) -> None:
        with pytest.raises(WritableValidationError, match="duplicate"):
            validate_writable_block({"ephemeral": ["/a", "/a"]}, "web")


class TestCrossBlockValidation:
    def test_ephemeral_persistent_overlap_rejected(self) -> None:
        block = {
            "ephemeral": ["/data"],
            "persistent": [{"name": "d", "mount": "/data"}],
        }
        with pytest.raises(
            WritableValidationError,
            match="both ephemeral and persistent",
        ):
            validate_writable_block(block, "web")

    def test_persistent_nested_under_ephemeral_rejected(self) -> None:
        block = {
            "ephemeral": ["/var/cache"],
            "persistent": [{"name": "c", "mount": "/var/cache/data"}],
        }
        with pytest.raises(WritableValidationError, match="nested"):
            validate_writable_block(block, "web")

    def test_external_with_ephemeral_rejected(self) -> None:
        block = {"external": True, "ephemeral": ["/x"]}
        with pytest.raises(WritableValidationError, match="mutually exclusive"):
            validate_writable_block(block, "web")

    def test_external_with_persistent_rejected(self) -> None:
        block = {"external": True, "persistent": [{"name": "n", "mount": "/x"}]}
        with pytest.raises(WritableValidationError, match="mutually exclusive"):
            validate_writable_block(block, "web")

    def test_external_false_rejected(self) -> None:
        with pytest.raises(WritableValidationError, match="omit"):
            validate_writable_block({"external": False}, "web")

    def test_external_non_bool_rejected(self) -> None:
        with pytest.raises(WritableValidationError, match="boolean"):
            validate_writable_block({"external": "yes"}, "web")

    def test_persistent_name_format(self) -> None:
        block = {"persistent": [{"name": "Bad-NAME", "mount": "/x"}]}
        with pytest.raises(WritableValidationError, match="name"):
            validate_writable_block(block, "web")

    def test_persistent_name_uniqueness(self) -> None:
        block = {"persistent": [
            {"name": "d", "mount": "/a"},
            {"name": "d", "mount": "/b"},
        ]}
        with pytest.raises(WritableValidationError, match="unique"):
            validate_writable_block(block, "web")

    def test_persistent_mount_uniqueness(self) -> None:
        block = {"persistent": [
            {"name": "a", "mount": "/x"},
            {"name": "b", "mount": "/x"},
        ]}
        with pytest.raises(WritableValidationError, match="mount"):
            validate_writable_block(block, "web")

    def test_unknown_keys_rejected(self) -> None:
        with pytest.raises(WritableValidationError, match="unknown"):
            validate_writable_block({"bogus": True}, "web")

    def test_block_must_be_mapping(self) -> None:
        with pytest.raises(WritableValidationError, match="mapping"):
            validate_writable_block(["ephemeral"], "web")

    def test_valid_blocks_accepted(self) -> None:
        # Each of these is a happy-path case that must not raise.
        validate_writable_block({"ephemeral": ["/var/cache", "/var/run"]}, "web")
        validate_writable_block(
            {"persistent": [{"name": "data", "mount": "/app/data"}]},
            "web",
        )
        validate_writable_block(
            {
                "ephemeral": ["/var/run"],
                "persistent": [{"name": "data", "mount": "/app/data"}],
            },
            "web",
        )
        validate_writable_block({"external": True}, "web")
        validate_writable_block(None, "web")  # absent block is fine
        validate_writable_block({}, "web")  # empty mapping is fine


class TestClassifyState:
    def test_default_when_no_block(self) -> None:
        assert classify_state({}) is WritableState.DEFAULT
        assert classify_state({"writable": None}) is WritableState.DEFAULT

    def test_default_when_empty_block(self) -> None:
        # Empty mapping is valid but classifies as DEFAULT — no declarations.
        assert classify_state({"writable": {}}) is WritableState.DEFAULT

    def test_managed_when_ephemeral_only(self) -> None:
        svc = {"writable": {"ephemeral": ["/x"]}}
        assert classify_state(svc) is WritableState.MANAGED

    def test_managed_when_persistent_only(self) -> None:
        svc = {"writable": {"persistent": [{"name": "n", "mount": "/m"}]}}
        assert classify_state(svc) is WritableState.MANAGED

    def test_managed_when_both(self) -> None:
        svc = {"writable": {
            "ephemeral": ["/x"],
            "persistent": [{"name": "n", "mount": "/m"}],
        }}
        assert classify_state(svc) is WritableState.MANAGED

    def test_external_state(self) -> None:
        svc = {"writable": {"external": True}}
        assert classify_state(svc) is WritableState.EXTERNAL
