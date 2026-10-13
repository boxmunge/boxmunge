# SPDX-License-Identifier: Apache-2.0
"""Parity with the server's validator, when the server source tree is present.

The client checks shape only, so it accepts manifests the server rejects
(the server is the authority and rejects them before deploying). The
property that must hold is the other direction: the client never refuses a
manifest the server accepts, and never crashes.
"""

import copy
import sys
from pathlib import Path

import pytest

from boxmunge_cli.manifest import validate_manifest as client_validate
from test_manifest_schema import BASE, MALFORMED

REPO_SRC = Path(__file__).resolve().parents[2] / "src"


@pytest.fixture(scope="module")
def server_validate():
    if not (REPO_SRC / "boxmunge" / "manifest.py").is_file():
        pytest.skip("server source tree not present (sdist)")
    sys.path.insert(0, str(REPO_SRC))
    try:
        from boxmunge.manifest import validate_manifest
    finally:
        sys.path.remove(str(REPO_SRC))
    return validate_manifest


def _mut(fn):
    m = copy.deepcopy(BASE)
    fn(m)
    return m


# The reviewer's parity corpus (policy cases) plus the malformed shapes.
CORPUS = {
    "valid": copy.deepcopy(BASE),
    "uppercase host": _mut(lambda m: m.update(hosts=["App.example.com"])),
    "wildcard host without opt-in": _mut(lambda m: m.update(hosts=["*.example.com"])),
    "wildcard host with opt-in": _mut(lambda m: m.update(hosts=["*.example.com"],
                                                         allow_wildcard_hosts=True)),
    "multi-service backup without service": _mut(lambda m: (
        m["services"].update(db={"port": 5432, "routes": [{"path": "/db"}]}),
        m.update(backup={"type": "postgres", "dump_command": "d", "restore_command": "r"}))),
    "writable without schema 3": _mut(lambda m: (
        m.update(schema_version=1),
        m["services"]["web"].update(writable={"ephemeral": ["/var/run"]}))),
    "security bad profile": _mut(lambda m: m.update(security={"profile": "bogus"})),
    "schema_version 4": _mut(lambda m: m.update(schema_version=4)),
    "staging.copy_data string": _mut(lambda m: m.update(staging={"copy_data": "yes"})),
    "service without routes": _mut(lambda m: m["services"]["web"].pop("routes")),
    **{f"malformed: {k}": v for k, v in MALFORMED.items()},
}


@pytest.mark.parametrize("name", CORPUS)
def test_client_is_never_stricter_than_the_server(server_validate, name: str) -> None:
    manifest = copy.deepcopy(CORPUS[name])
    client_errors, _ = client_validate(manifest)  # must not raise
    try:
        server_errors, _ = server_validate(copy.deepcopy(manifest), "app")
        server_accepts = not server_errors
    except Exception:  # a server crash is a rejection (and a server bug)
        server_accepts = False
    if server_accepts:
        assert client_errors == [], f"client refuses what the server accepts: {client_errors}"
