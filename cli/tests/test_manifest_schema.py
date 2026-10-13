"""Client manifest checks: shape only, never a traceback, never stricter than
the server. Policy (hosts syntax, routes, backup, security:, writable:,
schema support) belongs to the server, which validates every bundle on
stage and prod-deploy; the handshake compares schema_version before upload.
"""

import copy
from pathlib import Path

import pytest

from boxmunge_cli.manifest import ManifestError, load_manifest, validate_manifest

BASE = {
    "schema_version": 3,
    "id": "01TESTULID0000000000000000",
    "project": "app",
    "source": "bundle",
    "hosts": ["app.example.com"],
    "services": {"web": {"port": 80, "routes": [{"path": "/"}],
                         "limits": {"memory": "1g"}, "smoke": "boxmunge-scripts/smoke.sh"}},
    "backup": {"type": "none"},
}


def _with(**changes) -> dict:
    m = copy.deepcopy(BASE)
    for key, value in changes.items():
        if value is None:
            m.pop(key, None)
        else:
            m[key] = value
    return m


@pytest.mark.parametrize("version", [1, 2, 3, 4, 99])
def test_any_positive_schema_passes_offline(version: int) -> None:
    # The client cannot know the server's schema offline; the handshake checks it.
    assert validate_manifest(_with(schema_version=version)) == ([], [])


@pytest.mark.parametrize("version", [0, -1, "3", 3.0, [3], True, False])
def test_bad_schema_versions(version) -> None:
    errors, _ = validate_manifest(_with(schema_version=version))
    assert any("schema_version" in e for e in errors), errors


def test_schema_gated_blocks_are_left_to_the_server() -> None:
    m = _with(security={"profile": "default"})
    m["services"]["web"]["writable"] = {"ephemeral": ["/var/run"]}
    assert validate_manifest(m) == ([], [])


# Malformed shapes: each must be an error, never an exception.
MALFORMED = {
    "top level is a list": ["web"],
    "top level is a string": "app",
    "services is a list": _with(services=["web"]),
    "service is a string": _with(services={"web": "x"}),
    "services missing": _with(services=None),
    "hosts is a string": _with(hosts="app.example.com"),
    "hosts is empty": _with(hosts=[]),
    "host is a number": _with(hosts=[42]),
    "project is a list": _with(project=["app"]),
    "project escapes": _with(project="../../app"),
    "project missing": _with(project=None),
    "source missing": _with(source=None),
}


@pytest.mark.parametrize("name", MALFORMED)
def test_malformed_shapes_are_errors(name: str) -> None:
    errors, _ = validate_manifest(MALFORMED[name])
    assert errors


def test_missing_id_is_allowed_when_bundle_will_add_it() -> None:
    assert validate_manifest(_with(id=None), require_id=False) == ([], [])
    assert validate_manifest(_with(id=None))[0]


def test_yaml_syntax_error_is_a_manifest_error(tmp_path: Path) -> None:
    path = tmp_path / "manifest.yml"
    path.write_text("project: [unclosed\n")
    with pytest.raises(ManifestError, match="not valid YAML"):
        load_manifest(path)
