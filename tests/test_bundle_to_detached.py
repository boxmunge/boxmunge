# SPDX-License-Identifier: Apache-2.0
"""scripts/bundle-to-detached.py: the legacy .sig/.cert pair derived from a
cosign v3 Sigstore bundle, and its refusal of any bundle cosign 2.4.1 could
not verify in the detached form.

The fixture is a real public-good bundle: upstream's own signature over
cosign v3.1.4's cosign_checksums.txt (one hashedrekord entry in Rekor v1).
The CI rehearsal (.github/workflows/cosign-rehearsal.yml) runs real cosign
2.4.1 and 3.1.4 against the files this script derives."""
from __future__ import annotations

import ast
import base64
import copy
import json
import ssl
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "bundle-to-detached.py"
FIXTURE = REPO / "tests" / "fixtures" / "sigstore" / "cosign-v3.1.4-checksums.sigstore.json"
# Any log but Rekor v1: a Rekor v2 shard, say, which cosign 2.4.1 cannot search.
OTHER_LOG_ID = base64.b64encode(bytes(range(32))).decode()


def _bundle() -> dict:
    return json.loads(FIXTURE.read_text())


def _derive(tmp_path: Path, bundle: dict) -> tuple[subprocess.CompletedProcess, Path, Path]:
    src, sig, cert = tmp_path / "b.sigstore.json", tmp_path / "x.sig", tmp_path / "x.cert"
    src.write_text(json.dumps(bundle))
    proc = subprocess.run([sys.executable, "-I", str(SCRIPT), str(src), "--signature", str(sig),
                           "--certificate", str(cert)], capture_output=True, text=True)
    return proc, sig, cert


def test_derives_the_pair_cosign_2_wrote(tmp_path: Path) -> None:
    bundle = _bundle()
    proc, sig, cert = _derive(tmp_path, bundle)
    assert proc.returncode == 0, proc.stderr
    # .sig: the base64 DER signature, no newline (as cosign 2.x wrote it).
    assert sig.read_bytes() == bundle["messageSignature"]["signature"].encode()
    # .cert: base64 of the PEM of the bundle's leaf certificate, no newline.
    pem = base64.b64decode(cert.read_bytes(), validate=True).decode()
    assert pem.startswith("-----BEGIN CERTIFICATE-----\n") and pem.endswith("-----END CERTIFICATE-----\n")
    assert all(len(line) <= 64 for line in pem.splitlines())
    raw = base64.b64decode(bundle["verificationMaterial"]["certificate"]["rawBytes"])
    assert ssl.PEM_cert_to_DER_cert(pem) == raw


def _entry(bundle: dict) -> dict:
    return bundle["verificationMaterial"]["tlogEntries"][0]


def _mutations() -> dict[str, tuple]:
    def set_(path: list, value):
        def apply(b: dict) -> None:
            node = b
            for key in path[:-1]:
                node = node[key]
            if value is _DELETE:
                del node[path[-1]]
            else:
                node[path[-1]] = value
        return apply
    entry = ["verificationMaterial", "tlogEntries", 0]
    return {
        "rekor_v2": (set_([*entry, "logId", "keyId"], OTHER_LOG_ID), "not Rekor v1"),
        "two_entries": (lambda b: b["verificationMaterial"]["tlogEntries"].append(
            copy.deepcopy(_entry(b))), "exactly one transparency log entry, found 2"),
        "no_entries": (set_(["verificationMaterial", "tlogEntries"], []), "found 0"),
        "dsse_kind": (set_([*entry, "kindVersion"], {"kind": "dsse", "version": "0.0.1"}), "not {'kind'"),
        "no_promise": (set_([*entry, "inclusionPromise"], _DELETE), "inclusionPromise"),
        "no_time": (set_([*entry, "integratedTime"], _DELETE), "no integrated time"),
        "old_media": (set_(["mediaType"], "application/vnd.dev.sigstore.bundle+json;version=0.2"),
                      "media type"),
        "chain": (set_(["verificationMaterial", "x509CertificateChain"], {"certificates": []}),
                  "not one leaf certificate"),
        "sha512": (set_(["messageSignature", "messageDigest", "algorithm"], "SHA2_512"), "not SHA2_256"),
        "ed25519": (set_(["messageSignature", "signature"], base64.b64encode(bytes(64)).decode()),
                    "not an ECDSA"),
        "bad_b64": (set_(["messageSignature", "signature"], "not base64!"), "not base64"),
        "dsse": (set_(["messageSignature"], _DELETE), "messageSignature (a DSSE envelope"),
        "no_cert": (set_(["verificationMaterial", "certificate"], _DELETE), "leaf certificate is missing"),
        # Fields of the wrong JSON type refuse, never crash.
        "log_id_list": (set_([*entry, "logId"], ["x"]), "logId is missing or not an object"),
        "promise_string": (set_([*entry, "inclusionPromise"], "x"), "inclusionPromise is missing or not an object"),
        "entry_string": (set_(["verificationMaterial", "tlogEntries", 0], "x"), "log entry is missing or not an object"),
        "digest_list": (set_(["messageSignature", "messageDigest"], []), "message digest is missing or not an object"),
        "cert_string": (set_(["verificationMaterial", "certificate"], "x"), "leaf certificate is missing or not an object"),
        "material_list": (set_(["verificationMaterial"], []), "verificationMaterial is missing or not an object"),
    }


_DELETE = object()


@pytest.mark.parametrize("name", sorted(_mutations()))
def test_refuses_a_bundle_old_verifiers_cannot_use(name: str, tmp_path: Path) -> None:
    mutate, message = _mutations()[name]
    bundle = _bundle()
    mutate(bundle)
    proc, sig, cert = _derive(tmp_path, bundle)
    assert proc.returncode == 1, proc.stderr
    assert "Traceback" not in proc.stderr
    assert message in proc.stderr
    assert not sig.exists() and not cert.exists()


def test_refuses_what_is_not_json(tmp_path: Path) -> None:
    src = tmp_path / "b.sigstore.json"
    src.write_text("[not json")
    proc = subprocess.run([sys.executable, "-I", str(SCRIPT), str(src), "--signature", str(tmp_path / "s"),
                           "--certificate", str(tmp_path / "c")], capture_output=True, text=True)
    assert proc.returncode == 1 and "refusing" in proc.stderr


def test_imports_only_the_stdlib() -> None:
    """The signing job holds an OIDC token and runs no third-party Python."""
    tree = ast.parse(SCRIPT.read_text())
    names = {alias.name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import)
             for alias in node.names}
    names |= {node.module.split(".")[0] for node in ast.walk(tree)
              if isinstance(node, ast.ImportFrom) and node.module}
    assert names <= set(sys.stdlib_module_names) | {"__future__"}, names
