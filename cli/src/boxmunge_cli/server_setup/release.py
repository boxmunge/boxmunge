# SPDX-License-Identifier: Apache-2.0
"""Download and verify a signed boxmunge server release, locally.

Verification mirrors scripts/boxmunge-upgrade on the server:
  1. cosign verifies the keyless signature on SHA256SUMS against the release
     workflow's certificate identity and GitHub's OIDC issuer;
  2. SHA256SUMS must list the installer exactly once, and the installer's
     SHA-256 must match that line.
The identity is pinned to the exact tag being installed, which is one of the
identities the shim's pattern accepts, so a signature from another workflow,
repository or release is refused. cosign is required: without it nothing is
installed.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import shutil
import subprocess
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from boxmunge_cli import __version__

REPO = "boxmunge/boxmunge"
# Must stay identical to the pins in scripts/boxmunge-upgrade (a test checks).
COSIGN_CERT_IDENTITY_REGEXP = (
    r"^https://github\.com/boxmunge/boxmunge/\.github/workflows/release\.yml"
    r"@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$"
)
COSIGN_OIDC_ISSUER = "https://token.actions.githubusercontent.com"

INSTALLER = "boxmunge-install.sh"
SUMS = "SHA256SUMS"
ASSETS = (INSTALLER, SUMS, f"{SUMS}.sig", f"{SUMS}.cert")

_TAG = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+")
_MAX_ASSET_BYTES = 256 * 1024 * 1024
_COSIGN_INSTALL_HINT = (
    "Install cosign (https://docs.sigstore.dev/cosign/system_config/installation/) "
    "and re-run. boxmunge never installs a server release it cannot verify."
)

Fetch = Callable[[str], bytes]


class ReleaseError(Exception):
    """Raised when a release cannot be downloaded or fails verification."""


@dataclass(frozen=True)
class VerifiedInstaller:
    tag: str
    path: Path
    sha256: str


def _fetch(url: str) -> bytes:
    if not url.startswith("https://"):
        raise ReleaseError(f"Refusing non-HTTPS URL: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": f"boxmunge-cli/{__version__}"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = resp.read(_MAX_ASSET_BYTES + 1)
    except OSError as e:
        raise ReleaseError(f"Download failed: {url}: {e}") from e
    if len(data) > _MAX_ASSET_BYTES:
        raise ReleaseError(f"Download too large: {url}")
    return data


def validate_tag(tag: str) -> str:
    if not _TAG.fullmatch(tag):
        raise ReleaseError(f"Invalid release tag {tag!r}: expected vMAJOR.MINOR.PATCH.")
    return tag


def latest_release_tag(fetch: Fetch = _fetch) -> str:
    raw = fetch(f"https://api.github.com/repos/{REPO}/releases/latest")
    try:
        tag = json.loads(raw)["tag_name"]
    except (ValueError, KeyError, TypeError) as e:
        raise ReleaseError(f"Unexpected response from the GitHub releases API: {e}") from e
    if not isinstance(tag, str):
        raise ReleaseError("Unexpected response from the GitHub releases API: no tag_name.")
    return validate_tag(tag)


def download_release(tag: str, dest: Path, fetch: Fetch = _fetch) -> None:
    base = f"https://github.com/{REPO}/releases/download/{validate_tag(tag)}"
    for name in ASSETS:
        (dest / name).write_bytes(fetch(f"{base}/{name}"))


def certificate_identity(tag: str) -> str:
    identity = f"https://github.com/{REPO}/.github/workflows/release.yml@refs/tags/{tag}"
    if not re.fullmatch(COSIGN_CERT_IDENTITY_REGEXP, identity):
        raise ReleaseError(f"Release tag {tag!r} is outside the pinned signing identity.")
    return identity


def _verify_signature(release_dir: Path, tag: str) -> None:
    cosign = shutil.which("cosign")
    if cosign is None:
        raise ReleaseError("cosign is not installed. " + _COSIGN_INSTALL_HINT)
    result = subprocess.run(
        [cosign, "verify-blob",
         "--certificate-identity", certificate_identity(tag),
         "--certificate-oidc-issuer", COSIGN_OIDC_ISSUER,
         "--signature", str(release_dir / f"{SUMS}.sig"),
         "--certificate", str(release_dir / f"{SUMS}.cert"),
         str(release_dir / SUMS)],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise ReleaseError(
            f"cosign could not verify the signature on {SUMS} for {tag}; "
            f"refusing to install. cosign said: {detail}"
        )


def _expected_digest(sums_text: str) -> str:
    digests = []
    for line in sums_text.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].lstrip("*") == INSTALLER:
            digests.append(parts[0].lower())
    if len(digests) != 1:
        raise ReleaseError(f"{SUMS} must list {INSTALLER} exactly once; found {len(digests)}.")
    if not re.fullmatch(r"[0-9a-f]{64}", digests[0]):
        raise ReleaseError(f"{SUMS} has a malformed digest for {INSTALLER}.")
    return digests[0]


def verify_release(release_dir: Path, tag: str) -> VerifiedInstaller:
    _verify_signature(release_dir, tag)
    expected = _expected_digest((release_dir / SUMS).read_text(encoding="utf-8"))
    installer = release_dir / INSTALLER
    actual = hashlib.sha256(installer.read_bytes()).hexdigest()
    if not hmac.compare_digest(actual, expected):
        raise ReleaseError(
            f"Checksum mismatch for {INSTALLER}: {SUMS} says {expected}, "
            f"download is {actual}. Refusing to install."
        )
    return VerifiedInstaller(tag=tag, path=installer, sha256=actual)


def fetch_verified_installer(tag: str | None, workdir: Path,
                             fetch: Fetch = _fetch) -> VerifiedInstaller:
    """Download the release for tag (default: latest) into workdir and verify it."""
    if shutil.which("cosign") is None:
        raise ReleaseError("cosign is not installed. " + _COSIGN_INSTALL_HINT)
    resolved = validate_tag(tag) if tag else latest_release_tag(fetch)
    download_release(resolved, workdir, fetch)
    return verify_release(workdir, resolved)
