"""Cryptographic boundary for the encrypted coordination beta.

The identity and event primitives are real Ed25519, X25519, HKDF-SHA256, and
ChaCha20-Poly1305. The collective cipher is intentionally a simple shared epoch
key. It demonstrates the boundary but MUST be replaced by an audited RFC 9420
MLS implementation before production use.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .codec import b64, canonical_json, digest, parse_json, unb64
from .errors import CryptographicError

PROTOCOL_CONTEXT = b"protocol-plaza/mvp/v1"


def _private_bytes(key: Ed25519PrivateKey | X25519PrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


def _public_bytes(key: Ed25519PublicKey | X25519PublicKey) -> bytes:
    return key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


@dataclass(frozen=True)
class PublicIdentity:
    agent_id: str
    signing_key: str
    agreement_key: str

    def to_dict(self) -> dict[str, str]:
        return {
            "agent_id": self.agent_id,
            "signing_key": self.signing_key,
            "agreement_key": self.agreement_key,
        }

    @classmethod
    def from_dict(cls, value: dict[str, str]) -> PublicIdentity:
        return cls(**value)


class IdentityKeys:
    def __init__(self, signing: Ed25519PrivateKey, agreement: X25519PrivateKey):
        self._signing = signing
        self._agreement = agreement

    @classmethod
    def generate(cls) -> IdentityKeys:
        return cls(Ed25519PrivateKey.generate(), X25519PrivateKey.generate())

    @classmethod
    def from_dict(cls, value: dict[str, str]) -> IdentityKeys:
        return cls(
            Ed25519PrivateKey.from_private_bytes(unb64(value["signing_private"])),
            X25519PrivateKey.from_private_bytes(unb64(value["agreement_private"])),
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "signing_private": b64(_private_bytes(self._signing)),
            "agreement_private": b64(_private_bytes(self._agreement)),
        }

    @property
    def public(self) -> PublicIdentity:
        signing = _public_bytes(self._signing.public_key())
        agreement = _public_bytes(self._agreement.public_key())
        agent_id = f"agent:{digest(signing)[:24]}"
        return PublicIdentity(agent_id, b64(signing), b64(agreement))

    def sign(self, payload: bytes) -> bytes:
        return self._signing.sign(PROTOCOL_CONTEXT + payload)

    def open_sealed(self, box: dict[str, str], *, aad: bytes) -> bytes:
        try:
            ephemeral = X25519PublicKey.from_public_bytes(unb64(box["ephemeral_key"]))
            shared = self._agreement.exchange(ephemeral)
            key = _derive_seal_key(shared, aad)
            return ChaCha20Poly1305(key).decrypt(
                unb64(box["nonce"]), unb64(box["ciphertext"]), aad
            )
        except (InvalidTag, KeyError, TypeError, ValueError) as exc:
            raise CryptographicError(
                "sealed payload is malformed or failed authentication"
            ) from exc


def verify(public: PublicIdentity, payload: bytes, signature: bytes) -> None:
    key = Ed25519PublicKey.from_public_bytes(unb64(public.signing_key))
    try:
        key.verify(signature, PROTOCOL_CONTEXT + payload)
    except InvalidSignature as exc:
        raise CryptographicError("signature verification failed") from exc


def _derive_seal_key(shared_secret: bytes, aad: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=PROTOCOL_CONTEXT + b"/sealed/" + aad,
    ).derive(shared_secret)


def seal_to(recipient: PublicIdentity, plaintext: bytes, *, aad: bytes) -> dict[str, str]:
    ephemeral = X25519PrivateKey.generate()
    peer = X25519PublicKey.from_public_bytes(unb64(recipient.agreement_key))
    key = _derive_seal_key(ephemeral.exchange(peer), aad)
    nonce = os.urandom(12)
    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)
    return {
        "ephemeral_key": b64(_public_bytes(ephemeral.public_key())),
        "nonce": b64(nonce),
        "ciphertext": b64(ciphertext),
    }


def encrypt_group(key: bytes, payload: dict[str, Any], *, aad: bytes) -> dict[str, str]:
    nonce = os.urandom(12)
    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, canonical_json(payload), aad)
    return {"nonce": b64(nonce), "ciphertext": b64(ciphertext)}


def decrypt_group(key: bytes, box: dict[str, str], *, aad: bytes) -> dict[str, Any]:
    try:
        plaintext = ChaCha20Poly1305(key).decrypt(
            unb64(box["nonce"]), unb64(box["ciphertext"]), aad
        )
    except (InvalidTag, KeyError, TypeError, ValueError) as exc:
        raise CryptographicError(
            "collective payload is malformed or failed authentication"
        ) from exc
    value = parse_json(plaintext)
    if not isinstance(value, dict):
        raise CryptographicError("collective payload is not an object")
    return value


def generate_epoch_key() -> bytes:
    return os.urandom(32)


def encrypt_artifact(plaintext: bytes, *, aad: bytes) -> tuple[bytes, bytes, bytes]:
    key = os.urandom(32)
    nonce = os.urandom(12)
    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)
    return key, nonce, ciphertext


def decrypt_artifact(
    key: bytes, nonce: bytes, ciphertext: bytes, *, aad: bytes
) -> bytes:
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)
    except (InvalidTag, TypeError, ValueError) as exc:
        raise CryptographicError("artifact failed authentication") from exc
