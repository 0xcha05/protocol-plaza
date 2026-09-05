from __future__ import annotations

import json
import os
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .codec import b64, canonical_json, digest, parse_json, unb64
from .crypto import (
    IdentityKeys,
    PublicIdentity,
    decrypt_artifact,
    decrypt_group,
    encrypt_artifact,
    encrypt_group,
    generate_epoch_key,
    seal_to,
    verify,
)
from .errors import (
    AuthenticationError,
    CausalError,
    CryptographicError,
    ProtocolError,
    ProtocolPlazaError,
)
from .models import PublicCard, RelayEnvelope, SignedEvent, now_ms, random_id
from .relay import RouteCredentials
from .store import GatewayStore
from .transport import RelayTransport


class Gateway:
    """Trusted local boundary presented to an agent runtime."""

    def __init__(
        self, directory: str | Path, relay: RelayTransport, *, label: str = "agent"
    ):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.relay = relay
        self.label = label
        self.keys = self._load_or_create_keys(self.directory / "identity.json")
        self.store = GatewayStore(self.directory / "gateway.db")
        self.route = self._load_or_create_route()
        self.store.audit(
            "gateway.start", self.agent_id, None, "accepted",
            f"Gateway for {self.label} started",
            {"protocol": "protocol-plaza-mvp/1"},
        )

    @property
    def agent_id(self) -> str:
        return self.keys.public.agent_id

    @staticmethod
    def _load_or_create_keys(path: Path) -> IdentityKeys:
        if path.exists():
            return IdentityKeys.from_dict(json.loads(path.read_text(encoding="utf-8")))
        keys = IdentityKeys.generate()
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        fd = os.open(path, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(keys.to_dict(), handle, sort_keys=True)
        return keys

    def _load_or_create_route(self) -> RouteCredentials:
        value = self.store.get_setting("contact_route")
        if value is not None:
            route = RouteCredentials(**value)
            self.store.add_local_route(
                route.route_id, route.write_token, route.read_token,
                purpose="contact", peer_id=None
            )
            return route
        route = self._new_local_route(purpose="contact", peer_id=None)
        self.store.put_setting(
            "contact_route",
            {
                "route_id": route.route_id,
                "write_token": route.write_token,
                "read_token": route.read_token,
            },
        )
        return route

    def _new_local_route(
        self, *, purpose: str, peer_id: str | None
    ) -> RouteCredentials:
        route = self.relay.create_route()
        self.store.add_local_route(
            route.route_id, route.write_token, route.read_token,
            purpose=purpose, peer_id=peer_id
        )
        return route

    def _relationship_inbound(self, peer_id: str) -> RouteCredentials:
        row = self.store.local_route_for_peer(peer_id)
        if row is not None:
            return RouteCredentials(
                route_id=str(row["route_id"]),
                write_token=str(row["write_token"]),
                read_token=str(row["read_token"]),
            )
        return self._new_local_route(purpose="relationship", peer_id=peer_id)

    def _rotate_contact_route(self) -> None:
        old = self.route
        replacement = self._new_local_route(purpose="contact", peer_id=None)
        self.store.put_setting(
            "contact_route",
            {
                "route_id": replacement.route_id,
                "write_token": replacement.write_token,
                "read_token": replacement.read_token,
            },
        )
        self.route = replacement
        self.relay.revoke_route(old.route_id, read_token=old.read_token)
        self.store.deactivate_local_route(old.route_id)
        self.store.audit(
            "route.rotate", self.agent_id, replacement.route_id, "accepted",
            "Replaced a used public rendezvous route",
            {"retired_route": old.route_id, "replacement_route": replacement.route_id},
        )

    def close(self) -> None:
        self.store.close()

    def public_card(
        self, *, ttl_ms: int = 86_400_000,
        capabilities: tuple[str, ...] = (), description: str = ""
    ) -> PublicCard:
        return PublicCard.create(
            self.keys,
            contact_route=self.route.route_id,
            contact_write_token=self.route.write_token,
            expires_at_ms=now_ms() + ttl_ms,
            capabilities=capabilities,
            description=description,
        )

    def publish_card(
        self, *, capabilities: tuple[str, ...] = (), description: str = "",
        ttl_ms: int = 86_400_000
    ) -> PublicCard:
        card = self.public_card(
            ttl_ms=ttl_ms, capabilities=capabilities, description=description
        )
        if not hasattr(self.relay, "publish_public_card"):
            raise ProtocolError("relay transport does not support directory publication")
        try:
            self.relay.publish_public_card(card)  # type: ignore[call-arg]
        except TypeError:
            raise ProtocolError(
                "direct relay publication requires a service principal"
            ) from None
        self.store.audit(
            "directory.publish", self.agent_id, self.agent_id, "accepted",
            f"Published a signed discovery card with {len(capabilities)} capabilities",
            {"capabilities": list(capabilities), "expires_at_ms": card.expires_at_ms},
        )
        return card

    def discover(
        self, query: str = "", capabilities: tuple[str, ...] = (), *, limit: int = 20
    ) -> list[PublicCard]:
        if not hasattr(self.relay, "search_public_cards"):
            raise ProtocolError("relay transport does not support discovery")
        cards = self.relay.search_public_cards(query, capabilities, limit=limit)
        for card in cards:
            card.verify()
            if card.expires_at_ms <= now_ms():
                raise ProtocolError("directory returned an expired public card")
        return cards

    def resolve(self, agent_id: str) -> PublicCard | None:
        if not hasattr(self.relay, "resolve_public_card"):
            raise ProtocolError("relay transport does not support discovery")
        card = self.relay.resolve_public_card(agent_id)
        if card is not None:
            card.verify()
        return card

    def remember(self, card: PublicCard) -> None:
        if card.expires_at_ms <= now_ms():
            raise ProtocolError("public card is expired")
        card.verify()
        if card.identity.agent_id == self.agent_id:
            return
        self.store.add_peer(card.to_dict())
        self.store.audit(
            "peer.remember", self.agent_id, card.identity.agent_id, "accepted",
            f"Verified and learned a signed public card for {card.identity.agent_id}",
            {"expires_at_ms": card.expires_at_ms, "protocol": card.protocol},
        )

    def create_collective(
        self, name: str, peer_ids: Iterable[str], *, policy: dict[str, Any] | None = None
    ) -> str:
        collective_id = random_id("collective")
        members = [self.keys.public.to_dict()]
        normalized_peers: list[str] = []
        for peer_id in dict.fromkeys(peer_ids):
            row = self.store.get_peer(peer_id)
            if row is None:
                raise ProtocolError(f"unknown peer: {peer_id}")
            members.append(parse_json(bytes(row["identity_json"])))
            normalized_peers.append(peer_id)
        chosen_policy = dict(policy or {"membership_remove_threshold": 1})
        threshold = int(chosen_policy.get("membership_remove_threshold", 1))
        if threshold < 1 or threshold > len(members):
            raise ProtocolError("membership removal threshold is outside member count")
        chosen_policy["membership_remove_threshold"] = threshold
        self.store.add_collective(
            collective_id, name, 1, generate_epoch_key(), members, chosen_policy
        )
        self.store.audit(
            "collective.create", self.agent_id, collective_id, "accepted",
            f"Created collective {name!r} with {1 + len(normalized_peers)} members",
            {"member_ids": [m["agent_id"] for m in members], "epoch": 1},
        )
        for peer_id in normalized_peers:
            self._send_invitation(collective_id, peer_id)
        return collective_id

    def connect(self, peer_id: str) -> str:
        peer = self.store.get_peer(peer_id)
        if peer is None:
            raise ProtocolError(f"unknown peer: {peer_id}")
        if self.store.get_peer_route(peer_id) is not None:
            raise ProtocolError("relationship is already established")
        inbound = self._relationship_inbound(peer_id)
        content = {
            "version": 1,
            "type": "relationship_offer",
            "sender": self.keys.public.to_dict(),
            "return_route": {
                "route_id": inbound.route_id,
                "write_token": inbound.write_token,
            },
            "created_at_ms": now_ms(),
        }
        recipient = PublicIdentity.from_dict(parse_json(bytes(peer["identity_json"])))
        envelope_id = self._queue_sealed(
            content, recipient=recipient, route_id=str(peer["contact_route"]),
            write_token=str(peer["contact_write_token"]), peer_id=peer_id
        )
        self.flush_outbox()
        self.store.audit(
            "relationship.offer", self.agent_id, peer_id, "accepted",
            f"Sent a sealed relationship offer to {peer_id}",
            {"envelope_id": envelope_id},
        )
        return envelope_id

    def _send_invitation(self, collective_id: str, peer_id: str) -> str:
        collective = self._require_collective(collective_id)
        peer = self.store.get_peer(peer_id)
        if peer is None:
            raise ProtocolError(f"unknown peer: {peer_id}")
        member_rows = self.store.db.execute(
            "SELECT identity_json FROM members WHERE collective_id = ? AND active = 1",
            (collective_id,),
        ).fetchall()
        return_route = self._relationship_inbound(peer_id)
        content = {
            "version": 1,
            "type": "collective_invitation",
            "collective_id": collective_id,
            "name": collective["name"],
            "epoch": int(collective["epoch"]),
            "epoch_key": b64(bytes(collective["epoch_key"])),
            "members": [parse_json(bytes(row["identity_json"])) for row in member_rows],
            "policy": self.store.collective_policy(collective_id),
            "inviter": self.keys.public.to_dict(),
            "return_route": {
                "route_id": return_route.route_id,
                "write_token": return_route.write_token,
            },
            "created_at_ms": now_ms(),
        }
        recipient = PublicIdentity.from_dict(parse_json(bytes(peer["identity_json"])))
        established_route = self.store.get_peer_route(peer_id)
        delivery_route = (
            {
                "route_id": established_route["route_id"],
                "write_token": established_route["write_token"],
            }
            if established_route is not None
            else {
                "route_id": peer["contact_route"],
                "write_token": peer["contact_write_token"],
            }
        )
        envelope_id = self._queue_sealed(
            content,
            recipient=recipient,
            route_id=str(delivery_route["route_id"]),
            write_token=str(delivery_route["write_token"]),
            peer_id=peer_id,
        )
        self.flush_outbox()
        self.store.audit(
            "collective.invite", self.agent_id, collective_id, "accepted",
            f"Sent a sealed invitation to {peer_id}",
            {"envelope_id": envelope_id, "peer_id": peer_id},
        )
        return envelope_id

    def _queue_sealed(
        self,
        content: dict[str, Any],
        *,
        recipient: PublicIdentity,
        route_id: str,
        write_token: str,
        peer_id: str,
    ) -> str:
        signed = {
            "content": content,
            "signature": b64(self.keys.sign(canonical_json(content))),
        }
        envelope_id = random_id("env")
        encrypted = seal_to(
            recipient, canonical_json(signed), aad=envelope_id.encode("utf-8")
        )
        envelope = RelayEnvelope(
            envelope_id=envelope_id,
            route_id=route_id,
            kind="opaque/v1",
            aad=envelope_id,
            payload=encrypted,
            created_at_ms=now_ms(),
            expires_at_ms=now_ms() + 7 * 86_400_000,
        )
        self.store.queue_outbox(
            envelope.to_dict(), peer_id, None,
            route_id=route_id, write_token=write_token
        )
        return envelope_id

    def flush_outbox(self, *, limit: int = 100) -> dict[str, int]:
        counts = {"attempted": 0, "sent": 0, "failed": 0}
        for row in self.store.pending_outbox(limit):
            counts["attempted"] += 1
            try:
                envelope = RelayEnvelope.from_dict(
                    parse_json(bytes(row["envelope_json"]))
                )
                self.relay.push(envelope, write_token=str(row["write_token"]))
            except (ConnectionError, ProtocolPlazaError) as exc:
                self.store.fail_outbox(row["envelope_id"], str(exc))
                counts["failed"] += 1
                continue
            self.store.finish_outbox(row["envelope_id"])
            counts["sent"] += 1
        return counts

    def post_message(
        self,
        collective_id: str,
        body: str,
        *,
        recipients: Iterable[str],
        space_id: str = "main",
        idempotency_key: str | None = None,
    ) -> SignedEvent:
        return self._post_event(
            collective_id, "message.posted", {"text": body},
            recipients=recipients, space_id=space_id,
            idempotency_key=idempotency_key,
        )

    def _post_event(
        self,
        collective_id: str,
        event_type: str,
        body: dict[str, Any],
        *,
        recipients: Iterable[str],
        space_id: str = "main",
        idempotency_key: str | None = None,
    ) -> SignedEvent:
        key = idempotency_key or random_id("idem")
        existing = self.store.event_by_idempotency(self.agent_id, key)
        if existing is not None:
            return existing
        collective = self._require_collective(collective_id)
        event = SignedEvent.create(
            self.keys,
            collective_id=collective_id,
            space_id=space_id,
            author_seq=self.store.next_author_seq(collective_id, self.agent_id),
            parents=self.store.heads(collective_id, space_id),
            event_type=event_type,
            body=body,
            idempotency_key=key,
        )
        self.store.append_event(event, direction="outgoing")
        queued: list[str] = []
        for peer_id in dict.fromkeys(recipients):
            if peer_id == self.agent_id:
                continue
            if self.store.get_member_identity(collective_id, peer_id) is None:
                raise ProtocolError(f"recipient is not an active member: {peer_id}")
            peer_route = self.store.get_peer_route(peer_id)
            if peer_route is None:
                raise ProtocolError(
                    f"relationship route is not established for member: {peer_id}"
                )
            envelope_id = random_id("env")
            encrypted = encrypt_group(
                bytes(collective["epoch_key"]), event.to_dict(),
                aad=envelope_id.encode("utf-8")
            )
            envelope = RelayEnvelope(
                envelope_id=envelope_id,
                route_id=str(peer_route["route_id"]),
                kind="opaque/v1",
                aad=envelope_id,
                payload={**encrypted, "ephemeral_key": b64(os.urandom(32))},
                created_at_ms=now_ms(),
                expires_at_ms=now_ms() + 30 * 86_400_000,
            )
            self.store.queue_outbox(
                envelope.to_dict(), peer_id, event.event_id,
                route_id=str(peer_route["route_id"]),
                write_token=str(peer_route["write_token"]),
            )
            queued.append(peer_id)
        flush = self.flush_outbox()
        self.store.audit(
            event_type, self.agent_id, event.event_id, "accepted",
            f"Queued one encrypted {event_type} event for {len(queued)} peer(s); "
            f"{flush['sent']} envelope(s) reached the relay",
            {
                "collective_id": collective_id,
                "space_id": space_id,
                "recipients": queued,
                "event_id": event.event_id,
                "outbox": flush,
            },
        )
        return event

    def create_task(
        self, collective_id: str, title: str, description: str, *,
        recipients: Iterable[str], space_id: str = "main",
        idempotency_key: str | None = None
    ) -> dict[str, Any]:
        task_id = random_id("task")
        self._post_event(
            collective_id, "task.created",
            {"task_id": task_id, "title": title, "description": description},
            recipients=recipients, space_id=space_id,
            idempotency_key=idempotency_key,
        )
        return self._task(task_id)

    def claim_task(
        self, collective_id: str, task_id: str, expected_version: int, *,
        recipients: Iterable[str], space_id: str = "main",
        idempotency_key: str | None = None
    ) -> dict[str, Any]:
        self._post_event(
            collective_id, "task.claimed",
            {
                "task_id": task_id,
                "claimant": self.agent_id,
                "expected_version": expected_version,
            },
            recipients=recipients, space_id=space_id,
            idempotency_key=idempotency_key,
        )
        return self._task(task_id)

    def update_task(
        self, collective_id: str, task_id: str, expected_version: int,
        status: str, *, recipients: Iterable[str], evidence: Any = None,
        space_id: str = "main", idempotency_key: str | None = None
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "task_id": task_id,
            "expected_version": expected_version,
            "status": status,
        }
        if evidence is not None:
            body["evidence"] = evidence
        self._post_event(
            collective_id, "task.updated", body, recipients=recipients,
            space_id=space_id, idempotency_key=idempotency_key,
        )
        return self._task(task_id)

    def propose_decision(
        self, collective_id: str, question: str, options: Iterable[str],
        threshold: int, *, recipients: Iterable[str], space_id: str = "main",
        idempotency_key: str | None = None
    ) -> dict[str, Any]:
        normalized = list(dict.fromkeys(str(option) for option in options))
        if len(normalized) < 2 or threshold < 1:
            raise ProtocolError("a decision requires two options and a positive threshold")
        decision_id = random_id("decision")
        self._post_event(
            collective_id, "decision.proposed",
            {
                "decision_id": decision_id, "question": question,
                "options": normalized, "threshold": threshold,
            },
            recipients=recipients, space_id=space_id,
            idempotency_key=idempotency_key,
        )
        return self._decision(decision_id)

    def vote(
        self, collective_id: str, decision_id: str, choice: str, *,
        recipients: Iterable[str], space_id: str = "main",
        idempotency_key: str | None = None
    ) -> dict[str, Any]:
        self._post_event(
            collective_id, "decision.voted",
            {"decision_id": decision_id, "choice": choice},
            recipients=recipients, space_id=space_id,
            idempotency_key=idempotency_key,
        )
        return self._decision(decision_id)

    def create_commitment(
        self, collective_id: str, description: str, *, recipients: Iterable[str],
        owner: str | None = None, due_at_ms: int | None = None,
        space_id: str = "main", idempotency_key: str | None = None
    ) -> dict[str, Any]:
        commitment_id = random_id("commitment")
        self._post_event(
            collective_id, "commitment.created",
            {
                "commitment_id": commitment_id, "description": description,
                "owner": owner or self.agent_id, "due_at_ms": due_at_ms,
            },
            recipients=recipients, space_id=space_id,
            idempotency_key=idempotency_key,
        )
        return self._commitment(commitment_id)

    def update_commitment(
        self, collective_id: str, commitment_id: str, expected_version: int,
        status: str, *, recipients: Iterable[str], evidence: Any = None,
        space_id: str = "main", idempotency_key: str | None = None
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "commitment_id": commitment_id,
            "expected_version": expected_version,
            "status": status,
        }
        if evidence is not None:
            body["evidence"] = evidence
        self._post_event(
            collective_id, "commitment.updated", body, recipients=recipients,
            space_id=space_id, idempotency_key=idempotency_key,
        )
        return self._commitment(commitment_id)

    def tasks(self, collective_id: str | None = None) -> list[dict[str, Any]]:
        return self.store.tasks(collective_id)

    def decisions(self, collective_id: str | None = None) -> list[dict[str, Any]]:
        return self.store.decisions(collective_id)

    def commitments(self, collective_id: str | None = None) -> list[dict[str, Any]]:
        return self.store.commitments(collective_id)

    def publish_artifact(
        self,
        collective_id: str,
        source: bytes | str | Path,
        *,
        recipients: Iterable[str],
        name: str | None = None,
        media_type: str = "application/octet-stream",
        space_id: str = "main",
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        uploader = getattr(self.relay, "artifact_put", None)
        if uploader is None:
            raise ProtocolError("relay transport does not support artifact storage")
        if isinstance(source, bytes):
            plaintext = source
            artifact_name = name or "artifact.bin"
        else:
            path = Path(source)
            plaintext = path.read_bytes()
            artifact_name = name or path.name
        if not plaintext:
            raise ProtocolError("empty artifacts are not supported in this beta")
        if len(plaintext) > 32 * 1024 * 1024:
            raise ProtocolError("artifact exceeds the 32 MiB beta limit")
        artifact_id = random_id("artifact")
        aad = f"{collective_id}/{space_id}/{artifact_id}".encode()
        key, nonce, ciphertext = encrypt_artifact(plaintext, aad=aad)
        blob_id = digest(ciphertext)
        uploader(blob_id, ciphertext)
        self._post_event(
            collective_id,
            "artifact.published",
            {
                "artifact_id": artifact_id,
                "name": artifact_name,
                "media_type": media_type,
                "byte_size": len(plaintext),
                "plaintext_sha256": digest(plaintext),
                "blob_id": blob_id,
                "key": b64(key),
                "nonce": b64(nonce),
            },
            recipients=recipients,
            space_id=space_id,
            idempotency_key=idempotency_key,
        )
        return self._artifact(artifact_id)

    def fetch_artifact(
        self, artifact_id: str, *, destination: str | Path | None = None
    ) -> bytes:
        downloader = getattr(self.relay, "artifact_get", None)
        if downloader is None:
            raise ProtocolError("relay transport does not support artifact storage")
        artifact = self._artifact(artifact_id)
        ciphertext = downloader(artifact["blob_id"])
        if digest(ciphertext) != artifact["blob_id"]:
            raise ProtocolError("downloaded artifact ciphertext hash mismatch")
        aad = (
            f"{artifact['collective_id']}/{artifact['space_id']}/{artifact_id}"
        ).encode()
        plaintext = decrypt_artifact(
            unb64(artifact["key_b64"]), unb64(artifact["nonce_b64"]),
            ciphertext, aad=aad
        )
        if len(plaintext) != artifact["byte_size"]:
            raise ProtocolError("artifact byte size mismatch")
        if digest(plaintext) != artifact["plaintext_sha256"]:
            raise ProtocolError("artifact plaintext hash mismatch")
        if destination is not None:
            Path(destination).write_bytes(plaintext)
        self.store.audit(
            "artifact.fetch", self.agent_id, artifact_id, "accepted",
            f"Fetched and verified artifact {artifact['name']!r}",
            {"blob_id": artifact["blob_id"], "byte_size": len(plaintext)},
        )
        return plaintext

    def artifacts(self, collective_id: str | None = None) -> list[dict[str, Any]]:
        return [
            {
                key: value for key, value in artifact.items()
                if key not in {"key_b64", "nonce_b64"}
            }
            for artifact in self.store.artifacts(collective_id)
        ]

    def governance_proposals(
        self, collective_id: str | None = None
    ) -> list[dict[str, Any]]:
        return self.store.governance_proposals(collective_id)

    def create_space(
        self, collective_id: str, name: str, purpose: str, *,
        recipients: Iterable[str], idempotency_key: str | None = None
    ) -> dict[str, Any]:
        space_id = random_id("space")
        self._post_event(
            collective_id, "space.created",
            {"space_id": space_id, "name": name, "purpose": purpose},
            recipients=recipients, space_id="main",
            idempotency_key=idempotency_key,
        )
        return self._space(collective_id, space_id)

    def spaces(self, collective_id: str | None = None) -> list[dict[str, Any]]:
        return self.store.spaces(collective_id)

    def create_document(
        self, collective_id: str, title: str, *, recipients: Iterable[str],
        space_id: str = "main", idempotency_key: str | None = None
    ) -> dict[str, Any]:
        document_id = random_id("document")
        self._post_event(
            collective_id, "document.created",
            {"document_id": document_id, "title": title},
            recipients=recipients, space_id=space_id,
            idempotency_key=idempotency_key,
        )
        return self._document(document_id)

    def set_document_field(
        self, collective_id: str, document_id: str, field: str, value: Any, *,
        recipients: Iterable[str], space_id: str = "main",
        idempotency_key: str | None = None
    ) -> dict[str, Any]:
        self._post_event(
            collective_id, "document.field_set",
            {"document_id": document_id, "field": field, "value": value},
            recipients=recipients, space_id=space_id,
            idempotency_key=idempotency_key,
        )
        return self._document(document_id)

    def documents(self, collective_id: str | None = None) -> list[dict[str, Any]]:
        return self.store.documents(collective_id)

    def create_checkpoint(
        self, collective_id: str, summary: str, source_events: Iterable[str], *,
        recipients: Iterable[str], confidence: float = 0.5,
        space_id: str = "main", idempotency_key: str | None = None
    ) -> dict[str, Any]:
        checkpoint_id = random_id("checkpoint")
        self._post_event(
            collective_id, "memory.checkpoint",
            {
                "checkpoint_id": checkpoint_id,
                "summary": summary,
                "source_events": list(source_events),
                "confidence": confidence,
            },
            recipients=recipients, space_id=space_id,
            idempotency_key=idempotency_key,
        )
        return self._checkpoint(checkpoint_id)

    def checkpoints(self, collective_id: str | None = None) -> list[dict[str, Any]]:
        return self.store.checkpoints(collective_id)

    def _task(self, task_id: str) -> dict[str, Any]:
        rows = [task for task in self.store.tasks() if task["task_id"] == task_id]
        if not rows:
            raise ProtocolError(f"unknown task: {task_id}")
        return rows[0]

    def _decision(self, decision_id: str) -> dict[str, Any]:
        rows = [v for v in self.store.decisions() if v["decision_id"] == decision_id]
        if not rows:
            raise ProtocolError(f"unknown decision: {decision_id}")
        return rows[0]

    def _commitment(self, commitment_id: str) -> dict[str, Any]:
        rows = [v for v in self.store.commitments() if v["commitment_id"] == commitment_id]
        if not rows:
            raise ProtocolError(f"unknown commitment: {commitment_id}")
        return rows[0]

    def _artifact(self, artifact_id: str) -> dict[str, Any]:
        rows = [v for v in self.store.artifacts() if v["artifact_id"] == artifact_id]
        if not rows:
            raise ProtocolError(f"unknown artifact: {artifact_id}")
        return rows[0]

    def _proposal(self, proposal_id: str) -> dict[str, Any]:
        rows = [
            value for value in self.store.governance_proposals()
            if value["proposal_id"] == proposal_id
        ]
        if not rows:
            raise ProtocolError(f"unknown governance proposal: {proposal_id}")
        return rows[0]

    def _space(self, collective_id: str, space_id: str) -> dict[str, Any]:
        rows = [
            value for value in self.store.spaces(collective_id)
            if value["space_id"] == space_id
        ]
        if not rows:
            raise ProtocolError(f"unknown space: {space_id}")
        return rows[0]

    def _document(self, document_id: str) -> dict[str, Any]:
        rows = [
            value for value in self.store.documents()
            if value["document_id"] == document_id
        ]
        if not rows:
            raise ProtocolError(f"unknown document: {document_id}")
        return rows[0]

    def _checkpoint(self, checkpoint_id: str) -> dict[str, Any]:
        rows = [
            value for value in self.store.checkpoints()
            if value["checkpoint_id"] == checkpoint_id
        ]
        if not rows:
            raise ProtocolError(f"unknown checkpoint: {checkpoint_id}")
        return rows[0]

    def sync(self, *, limit: int = 100) -> dict[str, int]:
        self.flush_outbox(limit=limit)
        counts = {
            "seen": 0, "accepted": 0, "duplicate": 0,
            "pending": 0, "rejected": 0
        }
        rotate_contact = False
        for route in self.store.active_local_routes():
            route_id = str(route["route_id"])
            try:
                envelopes = self.relay.pull(
                    route_id, read_token=str(route["read_token"]), limit=limit
                )
            except AuthenticationError:
                self.store.deactivate_local_route(route_id)
                continue
            except ConnectionError:
                continue
            counts["seen"] += len(envelopes)
            acknowledged: list[str] = []
            group_envelopes: list[RelayEnvelope] = []
            for envelope in envelopes:
                prior = self.store.inbox_status(envelope.envelope_id)
                if prior == "accepted":
                    acknowledged.append(envelope.envelope_id)
                    counts["duplicate"] += 1
                    continue
                try:
                    sealed_type = self._accept_sealed(envelope)
                    if (
                        sealed_type in {"collective_invitation", "relationship_offer"}
                        and route_id == self.route.route_id
                    ):
                        rotate_contact = True
                except CryptographicError:
                    # Control envelopes such as epoch updates must be applied
                    # before group ciphertext from the same pull. Millisecond
                    # timestamps can tie, so relay order alone is insufficient.
                    group_envelopes.append(envelope)
                    continue
                except CausalError as exc:
                    self.store.mark_inbox(envelope.envelope_id, "pending", str(exc))
                    counts["pending"] += 1
                    continue
                except ProtocolPlazaError as exc:
                    self.store.mark_inbox(envelope.envelope_id, "rejected", str(exc))
                    self.store.audit(
                        "envelope.receive", self.agent_id, envelope.envelope_id,
                        "rejected", "Rejected an invalid encrypted envelope",
                        {"reason": type(exc).__name__, "detail": str(exc)},
                    )
                    acknowledged.append(envelope.envelope_id)
                    counts["rejected"] += 1
                    continue
                except (KeyError, TypeError, ValueError) as exc:
                    reason = f"malformed decrypted payload: {type(exc).__name__}"
                    self.store.mark_inbox(envelope.envelope_id, "rejected", reason)
                    self.store.audit(
                        "envelope.receive", self.agent_id, envelope.envelope_id,
                        "rejected", "Rejected a malformed decrypted envelope",
                        {"reason": type(exc).__name__},
                    )
                    acknowledged.append(envelope.envelope_id)
                    counts["rejected"] += 1
                    continue
                self.store.mark_inbox(envelope.envelope_id, "accepted")
                acknowledged.append(envelope.envelope_id)
                counts["accepted"] += 1

            for envelope in group_envelopes:
                try:
                    self._accept_group_event(envelope)
                except CausalError as exc:
                    self.store.mark_inbox(envelope.envelope_id, "pending", str(exc))
                    counts["pending"] += 1
                    continue
                except ProtocolPlazaError as exc:
                    self.store.mark_inbox(envelope.envelope_id, "rejected", str(exc))
                    self.store.audit(
                        "envelope.receive", self.agent_id, envelope.envelope_id,
                        "rejected", "Rejected an invalid encrypted envelope",
                        {"reason": type(exc).__name__, "detail": str(exc)},
                    )
                    acknowledged.append(envelope.envelope_id)
                    counts["rejected"] += 1
                    continue
                except (KeyError, TypeError, ValueError) as exc:
                    reason = f"malformed decrypted payload: {type(exc).__name__}"
                    self.store.mark_inbox(envelope.envelope_id, "rejected", reason)
                    self.store.audit(
                        "envelope.receive", self.agent_id, envelope.envelope_id,
                        "rejected", "Rejected a malformed decrypted envelope",
                        {"reason": type(exc).__name__},
                    )
                    acknowledged.append(envelope.envelope_id)
                    counts["rejected"] += 1
                    continue
                self.store.mark_inbox(envelope.envelope_id, "accepted")
                acknowledged.append(envelope.envelope_id)
                counts["accepted"] += 1
            if acknowledged:
                self.relay.acknowledge(
                    route_id, acknowledged, read_token=str(route["read_token"])
                )
        if rotate_contact:
            self._rotate_contact_route()
        self.flush_outbox(limit=limit)
        return counts

    def _accept_sealed(self, envelope: RelayEnvelope) -> str:
        plaintext = self.keys.open_sealed(
            {k: envelope.payload[k] for k in ("ephemeral_key", "nonce", "ciphertext")},
            aad=envelope.aad.encode("utf-8"),
        )
        value = parse_json(plaintext)
        content = value["content"]
        if content.get("version") != 1:
            raise ProtocolError("unsupported sealed-control version")
        sealed_type = content.get("type")
        if sealed_type == "collective_invitation":
            signer = PublicIdentity.from_dict(content["inviter"])
        elif sealed_type in {
            "relationship_offer", "relationship_acceptance", "route_update", "epoch_update"
        }:
            signer = PublicIdentity.from_dict(content["sender"])
        else:
            raise ProtocolError("unsupported sealed-control type")
        verify(signer, canonical_json(content), unb64(value["signature"]))
        if sealed_type == "collective_invitation":
            self._accept_invitation_content(content, signer)
        elif sealed_type == "relationship_offer":
            self._accept_relationship_offer(content, signer)
        elif sealed_type in {"relationship_acceptance", "route_update"}:
            self._accept_route_content(content, signer, sealed_type)
        else:
            self._accept_epoch_update(content, signer)
        return str(sealed_type)

    def _accept_relationship_offer(
        self, content: dict[str, Any], sender: PublicIdentity
    ) -> None:
        return_route = content["return_route"]
        existing_peer = self.store.get_peer(sender.agent_id)
        if existing_peer is None:
            self.store.db.execute(
                """INSERT OR REPLACE INTO peers
                   (agent_id, identity_json, contact_route, contact_write_token, learned_at_ms)
                   VALUES (?, ?, ?, ?, ?)""",
                (
                    sender.agent_id, canonical_json(sender.to_dict()),
                    return_route["route_id"], return_route["write_token"], now_ms(),
                ),
            )
            self.store.db.commit()
        self.store.set_peer_route(
            sender.agent_id, return_route["route_id"], return_route["write_token"]
        )
        inbound = self._relationship_inbound(sender.agent_id)
        acceptance = {
            "version": 1,
            "type": "relationship_acceptance",
            "sender": self.keys.public.to_dict(),
            "route": {
                "route_id": inbound.route_id,
                "write_token": inbound.write_token,
            },
            "created_at_ms": now_ms(),
        }
        self._queue_sealed(
            acceptance, recipient=sender,
            route_id=return_route["route_id"],
            write_token=return_route["write_token"], peer_id=sender.agent_id,
        )
        self.store.audit(
            "relationship.accept", sender.agent_id, sender.agent_id, "accepted",
            f"Accepted a direct relationship from {sender.agent_id}",
            {"inbound_route": inbound.route_id},
        )

    def _accept_invitation_content(
        self, content: dict[str, Any], inviter: PublicIdentity
    ) -> None:
        member_ids = {member["agent_id"] for member in content["members"]}
        if self.agent_id not in member_ids or inviter.agent_id not in member_ids:
            raise ProtocolError("invitation membership is inconsistent")
        existing = self.store.get_collective(content["collective_id"])
        if existing is not None and (
            str(existing["name"]) != content["name"]
            or int(existing["epoch"]) != int(content["epoch"])
            or bytes(existing["epoch_key"]) != unb64(content["epoch_key"])
            or self.store.collective_policy(content["collective_id"]) != content["policy"]
        ):
            raise ProtocolError("invitation conflicts with existing collective state")
        self.store.add_collective(
            content["collective_id"], content["name"], int(content["epoch"]),
            unb64(content["epoch_key"]), list(content["members"]), dict(content["policy"])
        )
        return_route = content["return_route"]
        self.store.set_peer_route(
            inviter.agent_id, return_route["route_id"], return_route["write_token"]
        )
        inbound = self._relationship_inbound(inviter.agent_id)
        acceptance = {
            "version": 1,
            "type": "relationship_acceptance",
            "collective_id": content["collective_id"],
            "sender": self.keys.public.to_dict(),
            "route": {
                "route_id": inbound.route_id,
                "write_token": inbound.write_token,
            },
            "created_at_ms": now_ms(),
        }
        self._queue_sealed(
            acceptance,
            recipient=inviter,
            route_id=return_route["route_id"],
            write_token=return_route["write_token"],
            peer_id=inviter.agent_id,
        )
        self.store.audit(
            "collective.admit", inviter.agent_id, content["collective_id"], "accepted",
            f"Accepted a sealed invitation to {content['name']!r}",
            {"member_ids": sorted(member_ids), "epoch": int(content["epoch"])},
        )

    def _accept_route_content(
        self, content: dict[str, Any], sender: PublicIdentity, control_type: str
    ) -> None:
        if self.store.get_peer(sender.agent_id) is None:
            raise ProtocolError("route control came from an unknown peer")
        collective_id = content.get("collective_id")
        if collective_id is not None and (
            self.store.get_member_identity(collective_id, sender.agent_id) is None
        ):
            raise ProtocolError("route control sender is not a collective member")
        route = content["route"]
        self.store.set_peer_route(
            sender.agent_id, route["route_id"], route["write_token"]
        )
        self.store.audit(
            "route.establish" if control_type == "relationship_acceptance" else "route.update",
            sender.agent_id, route["route_id"], "accepted",
            f"Accepted a private delivery route from {sender.agent_id}",
            {"collective_id": collective_id, "control_type": control_type},
        )

    def rotate_relationship(self, peer_id: str) -> str:
        peer = self.store.get_peer(peer_id)
        outbound = self.store.get_peer_route(peer_id)
        if peer is None or outbound is None:
            raise ProtocolError("relationship is not established")
        replacement = self._new_local_route(purpose="relationship", peer_id=peer_id)
        content = {
            "version": 1,
            "type": "route_update",
            "sender": self.keys.public.to_dict(),
            "route": {
                "route_id": replacement.route_id,
                "write_token": replacement.write_token,
            },
            "created_at_ms": now_ms(),
        }
        recipient = PublicIdentity.from_dict(parse_json(bytes(peer["identity_json"])))
        envelope_id = self._queue_sealed(
            content, recipient=recipient, route_id=str(outbound["route_id"]),
            write_token=str(outbound["write_token"]), peer_id=peer_id
        )
        self.flush_outbox()
        return envelope_id

    def propose_member_removal(
        self, collective_id: str, target: str, *, recipients: Iterable[str],
        threshold: int | None = None, idempotency_key: str | None = None
    ) -> dict[str, Any]:
        if target == self.agent_id:
            raise ProtocolError("use collective leave semantics to remove self")
        if self.store.get_member_identity(collective_id, target) is None:
            raise ProtocolError("target is not an active member")
        policy = self.store.collective_policy(collective_id)
        required = int(
            threshold if threshold is not None
            else policy.get("membership_remove_threshold", 1)
        )
        active_count = len(self.store.active_member_ids(collective_id))
        if required < 1 or required >= active_count:
            raise ProtocolError("removal threshold must leave an executable coalition")
        proposal_id = random_id("proposal")
        self._post_event(
            collective_id, "governance.proposed",
            {
                "proposal_id": proposal_id,
                "operation": "remove_member",
                "target": target,
                "threshold": required,
                "expected_epoch": int(self._require_collective(collective_id)["epoch"]),
            },
            recipients=recipients, idempotency_key=idempotency_key,
        )
        return self._proposal(proposal_id)

    def approve_proposal(
        self, collective_id: str, proposal_id: str, *, recipients: Iterable[str],
        idempotency_key: str | None = None
    ) -> dict[str, Any]:
        self._post_event(
            collective_id, "governance.approved",
            {"proposal_id": proposal_id}, recipients=recipients,
            idempotency_key=idempotency_key,
        )
        return self._proposal(proposal_id)

    def execute_member_removal(
        self, collective_id: str, proposal_id: str
    ) -> dict[str, Any]:
        proposal = self._proposal(proposal_id)
        if proposal["collective_id"] != collective_id:
            raise ProtocolError("proposal belongs to another collective")
        if proposal["operation"] != "remove_member" or proposal["status"] != "authorized":
            raise ProtocolError("proposal is not an authorized member removal")
        target = proposal["target"]
        collective = self._require_collective(collective_id)
        old_epoch = int(collective["epoch"])
        new_epoch = old_epoch + 1
        new_key = generate_epoch_key()
        remaining = [
            member for member in self.store.active_member_ids(collective_id)
            if member != target
        ]
        deliveries: list[tuple[str, PublicIdentity, Any]] = []
        for peer_id in remaining:
            if peer_id == self.agent_id:
                continue
            route = self.store.get_peer_route(peer_id)
            peer = self.store.get_peer(peer_id)
            if route is None or peer is None:
                raise ProtocolError(f"no private control route for remaining member: {peer_id}")
            deliveries.append((
                peer_id,
                PublicIdentity.from_dict(parse_json(bytes(peer["identity_json"]))),
                route,
            ))
        for peer_id, identity, route in deliveries:
            content = {
                "version": 1,
                "type": "epoch_update",
                "sender": self.keys.public.to_dict(),
                "collective_id": collective_id,
                "proposal_id": proposal_id,
                "removed_member": target,
                "old_epoch": old_epoch,
                "new_epoch": new_epoch,
                "new_epoch_key": b64(new_key),
                "remaining_members": remaining,
                "created_at_ms": now_ms(),
            }
            self._queue_sealed(
                content, recipient=identity, route_id=str(route["route_id"]),
                write_token=str(route["write_token"]), peer_id=peer_id
            )
        self.store.update_collective_epoch(
            collective_id, expected_epoch=old_epoch, new_epoch=new_epoch,
            epoch_key=new_key, removed_member=target
        )
        self.store.mark_proposal_executed(proposal_id, new_epoch)
        self.flush_outbox()
        self._post_event(
            collective_id, "membership.removed",
            {
                "proposal_id": proposal_id,
                "removed_member": target,
                "epoch": new_epoch,
            },
            recipients=[member for member in remaining if member != self.agent_id],
            idempotency_key=f"membership-removal:{proposal_id}",
        )
        self.store.audit(
            "membership.remove", self.agent_id, target, "accepted",
            f"Removed {target} and advanced collective epoch to {new_epoch}",
            {"proposal_id": proposal_id, "remaining_members": remaining},
        )
        return self._proposal(proposal_id)

    def _accept_epoch_update(
        self, content: dict[str, Any], sender: PublicIdentity
    ) -> None:
        collective_id = str(content["collective_id"])
        if self.store.get_member_identity(collective_id, sender.agent_id) is None:
            raise ProtocolError("epoch update sender is not an active member")
        proposal = self._proposal(str(content["proposal_id"]))
        if (
            proposal["status"] != "authorized"
            or proposal["operation"] != "remove_member"
            or proposal["target"] != content["removed_member"]
        ):
            raise ProtocolError("epoch update lacks matching local authorization")
        collective = self._require_collective(collective_id)
        old_epoch = int(content["old_epoch"])
        new_epoch = int(content["new_epoch"])
        if int(collective["epoch"]) != old_epoch:
            raise ProtocolError("epoch update precondition does not match local state")
        expected_remaining = sorted(
            member for member in self.store.active_member_ids(collective_id)
            if member != content["removed_member"]
        )
        if sorted(content["remaining_members"]) != expected_remaining:
            raise ProtocolError("epoch update remaining membership is inconsistent")
        if self.agent_id not in expected_remaining:
            raise ProtocolError("removed endpoint must not accept the new epoch")
        self.store.update_collective_epoch(
            collective_id, expected_epoch=old_epoch, new_epoch=new_epoch,
            epoch_key=unb64(content["new_epoch_key"]),
            removed_member=str(content["removed_member"]),
        )
        self.store.mark_proposal_executed(str(content["proposal_id"]), new_epoch)
        self.store.audit(
            "membership.rekey", sender.agent_id, collective_id, "accepted",
            f"Installed epoch {new_epoch} after an authorized member removal",
            {
                "proposal_id": content["proposal_id"],
                "removed_member": content["removed_member"],
            },
        )

    def _accept_group_event(self, envelope: RelayEnvelope) -> None:
        errors: list[str] = []
        for collective in self.store.list_collectives():
            try:
                value = decrypt_group(
                    bytes(collective["epoch_key"]),
                    {k: envelope.payload[k] for k in ("nonce", "ciphertext")},
                    aad=envelope.aad.encode("utf-8"),
                )
            except ProtocolPlazaError as exc:
                errors.append(str(exc))
                continue
            event = SignedEvent.from_dict(value)
            if event.collective_id != collective["collective_id"]:
                raise ProtocolError("event collective does not match decryption context")
            member = self.store.get_member_identity(event.collective_id, event.author)
            if member is None:
                raise ProtocolError("event author is not an active collective member")
            event.verify(PublicIdentity.from_dict(member))
            if self.store.has_event(event.event_id):
                self.store.audit(
                    "message.receive", event.author, event.event_id, "duplicate",
                    f"Ignored an already verified {event.event_type} event",
                    {"collective_id": event.collective_id},
                )
                return
            expected_seq = self.store.next_author_seq(event.collective_id, event.author)
            if event.author_seq > expected_seq:
                raise CausalError(
                    f"author sequence gap: expected {expected_seq}, received {event.author_seq}"
                )
            if event.author_seq < expected_seq:
                raise ProtocolError(
                    "author sequence conflict: "
                    f"expected {expected_seq}, received {event.author_seq}"
                )
            missing = [parent for parent in event.parents if not self.store.has_event(parent)]
            if missing:
                raise CausalError(f"missing {len(missing)} causal parent(s)")
            inserted = self.store.append_event(event, direction="incoming")
            self.store.audit(
                "message.receive", event.author, event.event_id,
                "accepted" if inserted else "duplicate",
                f"Received a verified {event.event_type} event",
                {
                    "collective_id": event.collective_id,
                    "space_id": event.space_id,
                    "author_seq": event.author_seq,
                    "parents": list(event.parents),
                },
            )
            return
        raise ProtocolError(f"no local collective key opened envelope ({len(errors)} tried)")

    def messages(self, collective_id: str | None = None) -> list[dict[str, Any]]:
        events = self.store.list_events()
        if collective_id is not None:
            events = [event for event in events if event.collective_id == collective_id]
        return [
            {
                "event_id": event.event_id,
                "collective_id": event.collective_id,
                "space_id": event.space_id,
                "author": event.author,
                "author_seq": event.author_seq,
                "parents": list(event.parents),
                "text": event.body.get("text"),
                "created_at_ms": event.created_at_ms,
            }
            for event in events
            if event.event_type == "message.posted"
        ]

    def _require_collective(self, collective_id: str):
        row = self.store.get_collective(collective_id)
        if row is None:
            raise ProtocolError(f"unknown collective: {collective_id}")
        return row
