# SPDX-License-Identifier: Apache-2.0
"""Release download and verification for server-setup."""

import hashlib
import json
import os
import re
from pathlib import Path

import pytest

from boxmunge_cli.server_setup import release
from boxmunge_cli.server_setup.release import (
    COSIGN_CERT_IDENTITY_REGEXP,
    COSIGN_OIDC_ISSUER,
    ReleaseError,
    fetch_verified_installer,
)

TAG = "v0.11.0"
INSTALLER_BYTES = b"#!/usr/bin/env bash\necho installer\n__PAYLOAD__\n"
BASE = f"https://github.com/boxmunge/boxmunge/releases/download/{TAG}"


def _assets(sums: str | None = None) -> dict[str, bytes]:
    digest = hashlib.sha256(INSTALLER_BYTES).hexdigest()
    sums = sums if sums is not None else (
        f"{digest}  boxmunge-install.sh\n{'0' * 64}  boxmunge-{TAG[1:]}.tar.gz\n")
    return {
        f"{BASE}/boxmunge-install.sh": INSTALLER_BYTES,
        f"{BASE}/SHA256SUMS": sums.encode(),
        f"{BASE}/SHA256SUMS.sig": b"sig",
        f"{BASE}/SHA256SUMS.cert": b"cert",
        "https://api.github.com/repos/boxmunge/boxmunge/releases/latest":
            json.dumps({"tag_name": TAG}).encode(),
    }


def _fetcher(assets: dict[str, bytes]):
    def fetch(url: str) -> bytes:
        return assets[url]
    return fetch


def test_verifies_signature_then_checksum(tmp_path: Path, fake_remote) -> None:
    verified = fetch_verified_installer(None, tmp_path, fetch=_fetcher(_assets()))

    assert verified.tag == TAG
    assert verified.sha256 == hashlib.sha256(INSTALLER_BYTES).hexdigest()
    [argv] = fake_remote.calls("cosign")
    assert argv[0] == "verify-blob"
    opts = dict(zip(argv[1:-1:2], argv[2:-1:2]))
    identity = ("https://github.com/boxmunge/boxmunge/.github/workflows/release.yml"
                f"@refs/tags/{TAG}")
    assert opts["--certificate-identity"] == identity
    assert opts["--certificate-oidc-issuer"] == COSIGN_OIDC_ISSUER
    assert opts["--signature"].endswith("SHA256SUMS.sig")
    assert opts["--certificate"].endswith("SHA256SUMS.cert")
    assert argv[-1].endswith("SHA256SUMS")


def test_bad_signature_refuses(tmp_path: Path, fake_remote) -> None:
    fake_remote.respond("cosign", "verify-blob", stderr="Error: none of the expected identities matched", rc=1)
    with pytest.raises(ReleaseError, match="expected identities matched"):
        fetch_verified_installer(TAG, tmp_path, fetch=_fetcher(_assets()))


def test_missing_cosign_fails_loudly_before_downloading(tmp_path: Path,
                                                        monkeypatch) -> None:
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))

    def fetch(url: str) -> bytes:
        raise AssertionError("must not download without cosign")
    with pytest.raises(ReleaseError, match="cosign is not installed"):
        fetch_verified_installer(TAG, tmp_path, fetch=fetch)


def test_checksum_mismatch_refuses(tmp_path: Path, fake_remote) -> None:
    sums = f"{'a' * 64}  boxmunge-install.sh\n"
    with pytest.raises(ReleaseError, match="Checksum mismatch"):
        fetch_verified_installer(TAG, tmp_path, fetch=_fetcher(_assets(sums)))


@pytest.mark.parametrize("sums", ["", f"{'a' * 64}  other.tar.gz\n",
                                  f"{'a' * 64}  boxmunge-install.sh\n" * 2])
def test_sums_must_list_installer_exactly_once(tmp_path: Path, fake_remote, sums) -> None:
    with pytest.raises(ReleaseError, match="exactly once"):
        fetch_verified_installer(TAG, tmp_path, fetch=_fetcher(_assets(sums)))


@pytest.mark.parametrize("tag", ["v1.2", "latest", "v1.2.3; rm -rf /", "1.2.3", "v1.2.3rc1"])
def test_bad_tags_are_refused(tmp_path: Path, fake_remote, tag: str) -> None:
    with pytest.raises(ReleaseError, match="Invalid release tag"):
        fetch_verified_installer(tag, tmp_path, fetch=_fetcher(_assets()))


def test_pins_match_the_server_upgrade_shim() -> None:
    scripts = Path(__file__).resolve().parents[3] / "scripts"
    shim = scripts / "boxmunge-upgrade"
    if not shim.is_file():
        pytest.skip("server source tree not present (sdist)")
    # The shim's source is split into libraries the bundle build inlines.
    parts = [shim, *sorted((scripts / "boxmunge-upgrade.d").glob("*.sh"))]
    text = "\n".join(p.read_text() for p in parts)
    regexp = re.search(r"^COSIGN_CERT_IDENTITY_REGEXP='([^']+)'", text, re.M).group(1)
    issuer = re.search(r"^COSIGN_OIDC_ISSUER='([^']+)'", text, re.M).group(1)
    assert regexp == COSIGN_CERT_IDENTITY_REGEXP
    assert issuer == COSIGN_OIDC_ISSUER


def test_fetch_refuses_plain_http() -> None:
    with pytest.raises(ReleaseError, match="non-HTTPS"):
        release._fetch("http://example.com/x")


def test_fake_cosign_is_what_ran(fake_remote) -> None:
    # Guard for the tests above: the cosign on PATH is the recording fake.
    assert os.path.dirname(release.shutil.which("cosign")) == str(fake_remote.bin)
