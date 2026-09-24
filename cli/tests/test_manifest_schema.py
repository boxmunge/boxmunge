"""Schema-version gating in the client manifest validator.

Regression: the client hardcoded CURRENT_SCHEMA_VERSION = 1 while the server
advanced to 3 (schema 2 added the `security:` block, schema 3 the `writable:`
block). Because the client's validator only checks schema-independent basics
and never inspects those blocks, that cap rejected perfectly valid manifests
and made `boxmunge bundle` unusable against any current project.
"""

import pytest

from boxmunge_cli.manifest import CURRENT_SCHEMA_VERSION, validate_manifest


def _manifest(schema_version: int) -> dict:
    """A minimal manifest that is valid apart from its schema_version."""
    return {
        "schema_version": schema_version,
        "id": "01TESTULID0000000000000000",
        "project": "testapp",
        "source": "bundle",
        "hosts": ["testapp.example.com"],
        "services": {
            "web": {"port": 8080, "routes": [{"path": "/"}], "smoke": "s.sh"},
        },
        "backup": {"type": "none"},
    }


class TestSupportedSchemaVersions:
    @pytest.mark.parametrize("version", [1, 2, 3])
    def test_current_schemas_validate(self, version: int) -> None:
        """Schemas the server actually emits must not be rejected."""
        errors, _ = validate_manifest(_manifest(version), "testapp")
        assert errors == []

    def test_client_knows_about_schema_3(self) -> None:
        """The server is at schema 3; the client must not lag behind it."""
        assert CURRENT_SCHEMA_VERSION >= 3

    def test_schema_3_writable_block_is_accepted(self) -> None:
        """A real schema-3 feature the client does not interpret."""
        manifest = _manifest(3)
        manifest["services"]["web"]["writable"] = {
            "persistent": [{"name": "dbdata"}],
        }
        errors, _ = validate_manifest(manifest, "testapp")
        assert errors == []

    def test_schema_2_security_block_is_accepted(self) -> None:
        """A real schema-2 feature the client does not interpret."""
        manifest = _manifest(2)
        manifest["security"] = {"posture": "balanced"}
        errors, _ = validate_manifest(manifest, "testapp")
        assert errors == []


class TestNewerSchemaIsWarnedNotRejected:
    def test_newer_schema_is_not_an_error(self) -> None:
        """A newer schema must not hard-fail.

        The client cannot assess schema-specific validity at all, so a local
        error would be a false claim of competence. The server re-validates
        and is the authority.
        """
        errors, _ = validate_manifest(_manifest(CURRENT_SCHEMA_VERSION + 1), "testapp")
        assert errors == []

    def test_newer_schema_warns(self) -> None:
        errors, warnings = validate_manifest(
            _manifest(CURRENT_SCHEMA_VERSION + 1), "testapp",
        )
        assert any("schema_version" in w for w in warnings), warnings

    def test_newer_schema_warning_names_the_authority(self) -> None:
        """The warning must tell the operator who actually decides."""
        _, warnings = validate_manifest(
            _manifest(CURRENT_SCHEMA_VERSION + 1), "testapp",
        )
        text = " ".join(warnings).lower()
        assert "server" in text

    def test_newer_schema_still_validates_the_basics(self) -> None:
        """Warning must not short-circuit the rest of validation.

        The old code returned early on a bad schema_version, so genuine
        errors were masked. A missing project must still be reported.
        """
        manifest = _manifest(CURRENT_SCHEMA_VERSION + 1)
        del manifest["project"]
        errors, _ = validate_manifest(manifest, "testapp")
        assert any("project" in e for e in errors), errors


class TestInvalidSchemaVersionsStillFail:
    @pytest.mark.parametrize("version", [0, -1])
    def test_below_one_is_an_error(self, version: int) -> None:
        """Not 'newer than I know' — genuinely invalid."""
        errors, _ = validate_manifest(_manifest(version), "testapp")
        assert any("schema_version" in e for e in errors), errors

    @pytest.mark.parametrize("version", ["3", 3.0, None, [3]])
    def test_non_integer_is_an_error(self, version) -> None:
        errors, _ = validate_manifest(_manifest(version), "testapp")
        assert any("schema_version" in e for e in errors), errors


class TestYamlBooleanTrap:
    """`schema_version: yes` parses to True, and isinstance(True, int) is True.

    Without an explicit bool guard, True slips through as schema_version 1
    and the manifest silently validates against the wrong schema. The repo
    already documents this YAML 1.1 trap for `profile: off`.
    """

    @pytest.mark.parametrize("version", [True, False])
    def test_boolean_schema_version_is_an_error(self, version: bool) -> None:
        errors, _ = validate_manifest(_manifest(version), "testapp")
        assert any("schema_version" in e for e in errors), errors
