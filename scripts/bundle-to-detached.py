#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Derive the legacy detached signature and certificate from a Sigstore bundle.

cosign v3 signs into a protobuf bundle (`sign-blob --bundle`). Every shim in
the field verifies with cosign 2.4.1 and the detached form instead:
`verify-blob --signature <.sig> --certificate <.cert>`, which looks the
signature up in Rekor v1. So the release publishes the bundle and, derived
from it, the same signature and certificate as the files cosign 2.x wrote:

  <.sig>   the bundle's base64 DER signature, as is
  <.cert>  the bundle's leaf certificate as PEM, base64 encoded

Both are backed by the bundle's one Rekor v1 entry. The script refuses a
bundle the old verifiers could not use, so a release fails before it
publishes files every old box would refuse: anything but one hashedrekord
0.0.1 entry in Rekor v1 (a Rekor v2 entry cannot be searched for), with its
signed entry timestamp, over a SHA-256 digest, signed by one leaf certificate
with an ECDSA (DER) signature.

Stdlib only: the job that signs runs no third-party Python.

Usage: bundle-to-detached.py <bundle> --signature <.sig> --certificate <.cert>
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import ssl
import sys
from pathlib import Path

MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"
# The public-good Rekor v1 log (rekor.sigstore.dev): the log ID in
# trusted_root.json, the SHA-256 of the log's public key.
REKOR_V1_LOG_ID = "wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0="
KIND_VERSION = {"kind": "hashedrekord", "version": "0.0.1"}


class BundleRefused(Exception):
    """The bundle cannot be turned into a detached pair the old verifiers accept."""


def _obj(value: object, what: str) -> dict:
    """value as a JSON object; anything else (missing, a list, a string) refuses."""
    if not isinstance(value, dict):
        raise BundleRefused(f"{what} is missing or not an object")
    return value


def _b64(value: object, what: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise BundleRefused(f"{what} is missing")
    try:
        return base64.b64decode(value, validate=True)
    except binascii.Error as e:
        raise BundleRefused(f"{what} is not base64: {e}") from None


def _ecdsa_der(sig: bytes) -> bool:
    """True when sig is a DER SEQUENCE of two INTEGERs (r, s), as ECDSA signs.
    An Ed25519 signature (64 raw bytes) is not."""
    def element(data: bytes, at: int, tag: int) -> int:
        if at + 2 > len(data) or data[at] != tag or data[at + 1] >= 0x80:
            return -1
        return at + 2 + data[at + 1]
    if len(sig) < 8 or element(sig, 0, 0x30) != len(sig):
        return False
    s_at = element(sig, 2, 0x02)
    return s_at > 0 and element(sig, s_at, 0x02) == len(sig)


def _entry(material: dict) -> dict:
    entries = material.get("tlogEntries")
    if not isinstance(entries, list) or len(entries) != 1:
        raise BundleRefused(f"expected exactly one transparency log entry, found "
                            f"{len(entries) if isinstance(entries, list) else 'none'}")
    entry = _obj(entries[0], "the log entry")
    if entry.get("kindVersion") != KIND_VERSION:
        raise BundleRefused(f"the log entry is {entry.get('kindVersion')}, not {KIND_VERSION}")
    log_id = _obj(entry.get("logId"), "the log entry's logId").get("keyId")
    if log_id != REKOR_V1_LOG_ID:
        raise BundleRefused(
            f"the log entry is in log {log_id}, not Rekor v1 ({REKOR_V1_LOG_ID}). cosign 2.4.1 "
            "verifies a detached signature by searching Rekor v1, so every old box would refuse "
            "this release. Sign with a Rekor v1 signing config (cosign sign-blob "
            "--signing-config), or stop publishing the detached pair")
    promise = _obj(entry.get("inclusionPromise"), "the log entry's inclusionPromise")
    _b64(promise.get("signedEntryTimestamp"), "the log entry's signed entry timestamp (inclusionPromise)")
    if not str(entry.get("integratedTime", "")).isdigit() or int(entry["integratedTime"]) <= 0:
        raise BundleRefused("the log entry has no integrated time")
    return entry


def derive(bundle: dict) -> tuple[bytes, bytes]:
    """Return the (.sig, .cert) file contents for a bundle, or raise BundleRefused."""
    if bundle.get("mediaType") != MEDIA_TYPE:
        raise BundleRefused(f"media type is {bundle.get('mediaType')!r}, not {MEDIA_TYPE!r}")
    material = _obj(bundle.get("verificationMaterial"), "the bundle's verificationMaterial")
    if set(material) & {"x509CertificateChain", "publicKey"}:
        raise BundleRefused("the bundle carries a certificate chain or a public key, "
                            "not one leaf certificate")
    cert = _b64(_obj(material.get("certificate"), "the leaf certificate").get("rawBytes"),
                "the leaf certificate's rawBytes")
    _entry(material)
    message = _obj(bundle.get("messageSignature"),
                   "the bundle's messageSignature (a DSSE envelope is not a blob signature)")
    algorithm = _obj(message.get("messageDigest"), "the message digest").get("algorithm")
    if algorithm != "SHA2_256":
        raise BundleRefused(f"the message digest is {algorithm}, not SHA2_256")
    signature = message.get("signature")
    if not _ecdsa_der(_b64(signature, "the signature")):
        raise BundleRefused("the signature is not an ECDSA (DER) signature")
    pem = ssl.DER_cert_to_PEM_cert(cert).encode("ascii")
    return signature.encode("ascii"), base64.b64encode(pem)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--certificate", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        bundle = json.loads(args.bundle.read_text())
        if not isinstance(bundle, dict):
            raise BundleRefused("the bundle is not a JSON object")
        sig, cert = derive(bundle)
    except (OSError, ValueError, BundleRefused) as e:
        print(f"bundle-to-detached: refusing {args.bundle}: {e}", file=sys.stderr)
        return 1
    args.signature.write_bytes(sig)
    args.certificate.write_bytes(cert)
    print(f"bundle-to-detached: {args.signature} and {args.certificate} derived from {args.bundle}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
