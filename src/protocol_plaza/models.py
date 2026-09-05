from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from typing import Any

from .codec import b64, canonical_json, digest, unb64
from .crypto import IdentityKeys, PublicIdentity, verify
from .errors import ProtocolError


def now_ms() -> int:
    return time.time_ns() // 1_000_000


def random_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(18)}"


@dataclass(frozen=True)
class PublicCard:
    identity: PublicIdentity
    contact_route: str
    contact_write_token: str
    expires_at_ms: int
    protocol: str = "protocol-plaza-mvp/1"
    signature: str = ""
    capabilities: tuple[str, ...] = ()
    description: str = ""

    def unsigned(self) -> dict[str, Any]:
        return {
            "identity": self.identity.to_dict(),
            "contact_route": self.contact_route,
            "contact_write_token": self.contact_write_token,
            "expires_at_ms": self.expires_at_ms,
            "protocol": self.protocol,
            "capabilities": list(self.capabilities),
            "description": self.description,
        }

    @classmethod
    def create(
        cls,
        keys: IdentityKeys,
        *,
        contact_route: str,
        contact_write_token: str,
        expires_at_ms: int,
        capabilities: tuple[str, ...] = (),
        description: str = "",
    ) -> PublicCard:
        card = cls(
            identity=keys.public,
            contact_route=contact_route,
            contact_write_token=contact_write_token,
            expires_at_ms=expires_at_ms,
            capabilities=tuple(sorted(set(capabilities))),
            description=description[:500],
        )
        return cls(
            identity=card.identity,
            contact_route=card.contact_route,
            contact_write_token=card.contact_write_token,
            expires_at_ms=card.expires_at_ms,
            protocol=card.protocol,
            signature=b64(keys.sign(canonical_json(card.unsigned()))),
            capabilities=card.capabilities,
            description=card.description,
        )

    def verify(self) -> None:
        if self.protocol != "protocol-plaza-mvp/1":
            raise ProtocolError("unsupported public-card protocol")
        if not self.contact_route or not self.contact_write_token:
            raise ProtocolError("public card has an incomplete rendezvous capability")
        if len(self.description) > 500:
            raise ProtocolError("public card description exceeds limit")
        if len(self.capabilities) > 64 or len(set(self.capabilities)) != len(self.capabilities):
            raise ProtocolError("public card capabilities are invalid")
        if any(not value or len(value) > 100 for value in self.capabilities):
            raise ProtocolError("public card capability exceeds limit")
        expected_agent_id = f"agent:{digest(unb64(self.identity.signing_key))[:24]}"
        if self.identity.agent_id != expected_agent_id:
            raise ProtocolError("public card identity is not self-certifying")
        verify(self.identity, canonical_json(self.unsigned()), unb64(self.signature))

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned(), "signature": self.signature}

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> PublicCard:
        return cls(
            identity=PublicIdentity.from_dict(value["identity"]),
            contact_route=value["contact_route"],
            contact_write_token=value["contact_write_token"],
            expires_at_ms=int(value["expires_at_ms"]),
            protocol=value.get("protocol", ""),
            signature=value.get("signature", ""),
            capabilities=tuple(value.get("capabilities", ())),
            description=value.get("description", ""),
        )


@dataclass(frozen=True)
class SignedEvent:
    event_id: str
    collective_id: str
    space_id: str
    author: str
    author_seq: int
    parents: tuple[str, ...]
    event_type: str
    body: dict[str, Any]
    created_at_ms: int
    idempotency_key: str
    signature: str

    @staticmethod
    def unsigned_dict(
        *,
        collective_id: str,
        space_id: str,
        author: str,
        author_seq: int,
        parents: tuple[str, ...],
        event_type: str,
        body: dict[str, Any],
        created_at_ms: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        return {
            "version": 1,
            "collective_id": collective_id,
            "space_id": space_id,
            "author": author,
            "author_seq": author_seq,
            "parents": list(parents),
            "event_type": event_type,
            "body": body,
            "created_at_ms": created_at_ms,
            "idempotency_key": idempotency_key,
        }

    @classmethod
    def create(
        cls,
        keys: IdentityKeys,
        *,
        collective_id: str,
        space_id: str,
        author_seq: int,
        parents: tuple[str, ...],
        event_type: str,
        body: dict[str, Any],
        idempotency_key: str,
        created_at_ms: int | None = None,
    ) -> SignedEvent:
        public = keys.public
        timestamp = now_ms() if created_at_ms is None else created_at_ms
        unsigned = cls.unsigned_dict(
            collective_id=collective_id,
            space_id=space_id,
            author=public.agent_id,
            author_seq=author_seq,
            parents=parents,
            event_type=event_type,
            body=body,
            created_at_ms=timestamp,
            idempotency_key=idempotency_key,
        )
        payload = canonical_json(unsigned)
        signature = keys.sign(payload)
        signed = {**unsigned, "signature": b64(signature)}
        return cls(event_id=digest(canonical_json(signed)), signature=b64(signature), **{
            key: value for key, value in unsigned.items() if key != "version"
        })

    def unsigned(self) -> dict[str, Any]:
        return self.unsigned_dict(
            collective_id=self.collective_id,
            space_id=self.space_id,
            author=self.author,
            author_seq=self.author_seq,
            parents=self.parents,
            event_type=self.event_type,
            body=self.body,
            created_at_ms=self.created_at_ms,
            idempotency_key=self.idempotency_key,
        )

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned(), "event_id": self.event_id, "signature": self.signature}

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> SignedEvent:
        try:
            event = cls(
                event_id=value["event_id"],
                collective_id=value["collective_id"],
                space_id=value["space_id"],
                author=value["author"],
                author_seq=int(value["author_seq"]),
                parents=tuple(value["parents"]),
                event_type=value["event_type"],
                body=dict(value["body"]),
                created_at_ms=int(value["created_at_ms"]),
                idempotency_key=value["idempotency_key"],
                signature=value["signature"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ProtocolError("invalid signed event") from exc
        return event

    def verify(self, public: PublicIdentity) -> None:
        if self.author != public.agent_id:
            raise ProtocolError("event author does not match signing identity")
        signed = {**self.unsigned(), "signature": self.signature}
        if digest(canonical_json(signed)) != self.event_id:
            raise ProtocolError("event id does not match signed content")
        verify(public, canonical_json(self.unsigned()), unb64(self.signature))


@dataclass(frozen=True)
class RelayEnvelope:
    envelope_id: str
    route_id: str
    kind: str
    aad: str
    payload: dict[str, str]
    created_at_ms: int
    expires_at_ms: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope_id": self.envelope_id,
            "route_id": self.route_id,
            "kind": self.kind,
            "aad": self.aad,
            "payload": self.payload,
            "created_at_ms": self.created_at_ms,
            "expires_at_ms": self.expires_at_ms,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> RelayEnvelope:
        return cls(
            envelope_id=value["envelope_id"],
            route_id=value["route_id"],
            kind=value["kind"],
            aad=value["aad"],
            payload=dict(value["payload"]),
            created_at_ms=int(value["created_at_ms"]),
            expires_at_ms=int(value["expires_at_ms"]),
        )
