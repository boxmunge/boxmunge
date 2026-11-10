"""A software WebAuthn authenticator for the passkey tests.

Builds clientDataJSON, authenticatorData, a `none` attestation and signed
assertions by hand from an EC key, so the tests exercise the server's real
verification with no browser. Every field a test may want to falsify
(origin, RP ID, user verification, sign count) is a keyword argument.
"""

import base64
import hashlib
import json
import os

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

FLAG_UP, FLAG_UV, FLAG_AT = 0x01, 0x04, 0x40
AAGUID = bytes(16)
# COSE: alg ids, and the EC2 curve ids that go with them.
CURVES = {-7: (ec.SECP256R1(), 1, hashes.SHA256()), -35: (ec.SECP384R1(), 2, hashes.SHA384())}


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class SoftAuthenticator:
    def __init__(self, rp_id: str, origin: str, alg: int = -7) -> None:
        self.rp_id, self.origin, self.alg = rp_id, origin, alg
        curve, self._crv, self._hash = CURVES[alg]
        self.key = ec.generate_private_key(curve)
        self.credential_id = os.urandom(32)
        self.sign_count = 0

    def _cose_key(self) -> bytes:
        numbers = self.key.public_key().public_numbers()
        size = (self.key.curve.key_size + 7) // 8
        return cbor2.dumps({1: 2, 3: self.alg, -1: self._crv,
                            -2: numbers.x.to_bytes(size, "big"),
                            -3: numbers.y.to_bytes(size, "big")})

    def _client_data(self, kind: str, options: dict, origin: str | None) -> bytes:
        return json.dumps({"type": kind, "challenge": options["challenge"],
                           "origin": origin or self.origin, "crossOrigin": False}).encode()

    def _auth_data(self, flags: int, rp_id: str | None, tail: bytes = b"") -> bytes:
        rp_hash = hashlib.sha256((rp_id or self.rp_id).encode()).digest()
        return rp_hash + bytes([flags]) + self.sign_count.to_bytes(4, "big") + tail

    def create(self, options: dict, *, origin: str | None = None, rp_id: str | None = None,
               uv: bool = True) -> dict:
        """navigator.credentials.create(), as the JSON the page posts."""
        attested = (AAGUID + len(self.credential_id).to_bytes(2, "big")
                    + self.credential_id + self._cose_key())
        flags = FLAG_UP | FLAG_AT | (FLAG_UV if uv else 0)
        attestation = cbor2.dumps({"fmt": "none", "attStmt": {},
                                   "authData": self._auth_data(flags, rp_id, attested)})
        return {"id": b64url(self.credential_id), "rawId": b64url(self.credential_id),
                "type": "public-key",
                "response": {"clientDataJSON": b64url(self._client_data(
                                 "webauthn.create", options, origin)),
                             "attestationObject": b64url(attestation)}}

    def get(self, options: dict, *, origin: str | None = None, rp_id: str | None = None,
            sign_count: int | None = None) -> dict:
        """navigator.credentials.get(), as the JSON the page posts.

        The counter advances by one unless `sign_count` sets it.
        """
        self.sign_count = self.sign_count + 1 if sign_count is None else sign_count
        auth_data = self._auth_data(FLAG_UP | FLAG_UV, rp_id)
        client_data = self._client_data("webauthn.get", options, origin)
        signature = self.key.sign(auth_data + hashlib.sha256(client_data).digest(),
                                  ec.ECDSA(self._hash))
        return {"id": b64url(self.credential_id), "rawId": b64url(self.credential_id),
                "type": "public-key",
                "response": {"clientDataJSON": b64url(client_data),
                             "authenticatorData": b64url(auth_data),
                             "signature": b64url(signature)}}


# Ceremonies against the Flask test client, as the page's script runs them.

def register(client, authenticator: SoftAuthenticator, code: str, **create_kw):
    """The verify response; the options request must succeed."""
    options = client.post("/v1/admin/register/options", json={"code": code})
    assert options.status_code == 200, options.get_json()
    credential = authenticator.create(options.get_json(), **create_kw)
    return client.post("/v1/admin/register/verify", json={"code": code, "credential": credential})


def login(client, authenticator: SoftAuthenticator, **get_kw):
    """The verify response; the options request must succeed."""
    options = client.post("/v1/admin/login/options", json={})
    assert options.status_code == 200, options.get_json()
    return client.post("/v1/admin/login/verify",
                       json={"credential": authenticator.get(options.get_json(), **get_kw)})


def session_header(response) -> dict[str, str]:
    """The Cookie header a browser would send back after this sign-in response."""
    return {"Cookie": response.headers["Set-Cookie"].split(";")[0]}
