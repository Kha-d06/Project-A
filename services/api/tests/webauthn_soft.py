"""A software authenticator for tests: real P-256 keys and real WebAuthn
data (CBOR attestation object, COSE key, flags, signatures), so the server's
py_webauthn verification runs for real."""

import base64
import hashlib
import json
import secrets
import struct
from dataclasses import dataclass, field
from typing import Any

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

UP, UV, AT, BE, BS = 0x01, 0x04, 0x40, 0x08, 0x10


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


@dataclass
class SoftAuthenticator:
    rp_id: str = "localhost"
    origin: str = "http://localhost:8080"
    key: ec.EllipticCurvePrivateKey = field(
        default_factory=lambda: ec.generate_private_key(ec.SECP256R1())
    )
    credential_id: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    sign_count: int = 0
    user_handle: bytes | None = None

    def _cose_key(self) -> bytes:
        numbers = self.key.public_key().public_numbers()
        return cbor2.dumps(
            {
                1: 2,
                3: -7,
                -1: 1,
                -2: numbers.x.to_bytes(32, "big"),
                -3: numbers.y.to_bytes(32, "big"),
            }
        )

    def _auth_data(self, flags: int, attested: bool) -> bytes:
        data = (
            hashlib.sha256(self.rp_id.encode()).digest()
            + bytes([flags])
            + struct.pack(">I", self.sign_count)
        )
        if attested:
            data += (
                b"\0" * 16
                + struct.pack(">H", len(self.credential_id))
                + self.credential_id
                + self._cose_key()
            )
        return data

    def _client_data(self, kind: str, challenge: str, origin: str | None) -> bytes:
        return json.dumps(
            {
                "type": kind,
                "challenge": challenge,
                "origin": origin or self.origin,
                "crossOrigin": False,
            }
        ).encode()

    def register(
        self, options: dict[str, Any], *, uv: bool = True, origin: str | None = None
    ) -> dict[str, Any]:
        self.user_handle = unb64url(options["user"]["id"])
        flags = UP | AT | (UV if uv else 0) | BE | BS
        attestation = cbor2.dumps(
            {"fmt": "none", "attStmt": {}, "authData": self._auth_data(flags, True)}
        )
        client = self._client_data("webauthn.create", options["challenge"], origin)
        return {
            "id": b64url(self.credential_id),
            "rawId": b64url(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64url(client),
                "attestationObject": b64url(attestation),
                "transports": ["internal", "hybrid"],
            },
            "clientExtensionResults": {},
        }

    def sign_in(
        self,
        options: dict[str, Any],
        *,
        uv: bool = True,
        origin: str | None = None,
        count: int | None = None,
    ) -> dict[str, Any]:
        self.sign_count = self.sign_count + 1 if count is None else count
        auth_data = self._auth_data(UP | (UV if uv else 0) | BE | BS, False)
        client = self._client_data("webauthn.get", options["challenge"], origin)
        signature = self.key.sign(
            auth_data + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256())
        )
        return {
            "id": b64url(self.credential_id),
            "rawId": b64url(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64url(client),
                "authenticatorData": b64url(auth_data),
                "signature": b64url(signature),
                "userHandle": b64url(self.user_handle or b""),
            },
            "clientExtensionResults": {},
        }
