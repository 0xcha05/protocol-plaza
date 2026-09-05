"""First-party relay discovery and cryptographic service identity."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .codec import b64, canonical_json, digest, unb64
from .errors import CryptographicError, ProtocolError
from .models import now_ms

DISCOVERY_CONTEXT = b"protocol-plaza/discovery/v1\x00"
DISCOVERY_PROTOCOL = "protocol-plaza-mvp/1"
DISCOVERY_ENDPOINTS = {
    "card_publish": "/v1/directory/cards",
    "card_resolve": "/v1/directory/cards/{agent_id}",
    "card_search": "/v1/directory/search",
    "principal_register": "/v1/principals",
    "route_create": "/v1/routes",
}
DISCOVERY_FEATURES = (
    "capability-search",
    "proof-bound-service-auth",
    "self-certifying-agent-cards",
    "sealed-rendezvous",
)


def _private_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


def _public_bytes(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


class RelaySigningIdentity:
    """Persistent signing identity for one discovery service."""

    def __init__(self, private_key: Ed25519PrivateKey):
        self._private_key = private_key

    @classmethod
    def load_or_create(cls, path: str | Path) -> RelaySigningIdentity:
        identity_path = Path(path)
        if identity_path.exists():
            value = json.loads(identity_path.read_text(encoding="utf-8"))
            key = Ed25519PrivateKey.from_private_bytes(unb64(value["signing_private"]))
            os.chmod(identity_path, 0o600)
            return cls(key)
        identity_path.parent.mkdir(parents=True, exist_ok=True)
        key = Ed25519PrivateKey.generate()
        encoded = canonical_json({"signing_private": b64(_private_bytes(key))})
        fd = os.open(identity_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(encoded)
        return cls(key)

    @property
    def public_key(self) -> str:
        return b64(_public_bytes(self._private_key.public_key()))

    @property
    def relay_id(self) -> str:
        return f"relay:{digest(unb64(self.public_key))[:24]}"

    def manifest(self, *, ttl_ms: int = 3_600_000) -> RelayManifest:
        if ttl_ms <= 0 or ttl_ms > 86_400_000:
            raise ProtocolError("discovery manifest ttl must be between 1 ms and 1 day")
        issued = now_ms()
        unsigned = {
            "service": "protocol-plaza",
            "relay_id": self.relay_id,
            "signing_key": self.public_key,
            "protocols": [DISCOVERY_PROTOCOL],
            "features": list(DISCOVERY_FEATURES),
            "endpoints": DISCOVERY_ENDPOINTS,
            "issued_at_ms": issued,
            "expires_at_ms": issued + ttl_ms,
        }
        signature = self._private_key.sign(DISCOVERY_CONTEXT + canonical_json(unsigned))
        return RelayManifest.from_dict({**unsigned, "signature": b64(signature)})


@dataclass(frozen=True)
class RelayManifest:
    service: str
    relay_id: str
    signing_key: str
    protocols: tuple[str, ...]
    features: tuple[str, ...]
    endpoints: dict[str, str]
    issued_at_ms: int
    expires_at_ms: int
    signature: str

    def unsigned(self) -> dict[str, Any]:
        return {
            "service": self.service,
            "relay_id": self.relay_id,
            "signing_key": self.signing_key,
            "protocols": list(self.protocols),
            "features": list(self.features),
            "endpoints": self.endpoints,
            "issued_at_ms": self.issued_at_ms,
            "expires_at_ms": self.expires_at_ms,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned(), "signature": self.signature}

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> RelayManifest:
        try:
            endpoints = value["endpoints"]
            if not isinstance(endpoints, dict):
                raise TypeError("endpoints must be an object")
            return cls(
                service=str(value["service"]),
                relay_id=str(value["relay_id"]),
                signing_key=str(value["signing_key"]),
                protocols=tuple(str(v) for v in value["protocols"]),
                features=tuple(str(v) for v in value["features"]),
                endpoints={str(k): str(v) for k, v in endpoints.items()},
                issued_at_ms=int(value["issued_at_ms"]),
                expires_at_ms=int(value["expires_at_ms"]),
                signature=str(value["signature"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ProtocolError("discovery manifest is malformed") from exc

    def verify(self, *, expected_signing_key: str | None = None) -> None:
        if self.service != "protocol-plaza":
            raise ProtocolError("unexpected discovery service")
        try:
            public_bytes = unb64(self.signing_key)
        except (TypeError, ValueError) as exc:
            raise ProtocolError("discovery signing key is malformed") from exc
        if self.relay_id != f"relay:{digest(public_bytes)[:24]}":
            raise ProtocolError("relay id is not self-certifying")
        if expected_signing_key is not None and self.signing_key != expected_signing_key:
            raise CryptographicError("relay discovery key does not match the configured pin")
        current = now_ms()
        if self.expires_at_ms <= current:
            raise ProtocolError("discovery manifest is expired")
        if self.issued_at_ms > current + 300_000:
            raise ProtocolError("discovery manifest was issued too far in the future")
        if self.expires_at_ms <= self.issued_at_ms:
            raise ProtocolError("discovery manifest lifetime is invalid")
        if DISCOVERY_PROTOCOL not in self.protocols:
            raise ProtocolError("relay does not advertise the supported protocol")
        if set(DISCOVERY_ENDPOINTS) - set(self.endpoints):
            raise ProtocolError("discovery manifest omits required endpoints")
        if any(
            not value.startswith("/") or value.startswith("//")
            for value in self.endpoints.values()
        ):
            raise ProtocolError("discovery endpoints must be origin-relative paths")
        try:
            Ed25519PublicKey.from_public_bytes(public_bytes).verify(
                unb64(self.signature), DISCOVERY_CONTEXT + canonical_json(self.unsigned())
            )
        except (InvalidSignature, TypeError, ValueError) as exc:
            raise CryptographicError("discovery manifest signature verification failed") from exc
