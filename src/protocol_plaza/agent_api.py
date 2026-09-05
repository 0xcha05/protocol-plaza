"""Agent-facing JSON-RPC-like interface.

This adapter exposes useful collective operations but never key material, route
tokens, service credentials, or raw database access.
"""

from __future__ import annotations

from typing import Any

from .codec import b64, unb64
from .errors import ProtocolError, ProtocolPlazaError
from .gateway import Gateway
from .models import PublicCard


class AgentApi:
    def __init__(self, gateway: Gateway):
        self.gateway = gateway

    def handle(self, request: dict[str, Any]) -> dict[str, Any]:
        request_id = request.get("id")
        method = request.get("method")
        params = request.get("params", {})
        if not isinstance(method, str) or not isinstance(params, dict):
            return self._error(request_id, "invalid_request", "method and params are required")
        try:
            result = self._dispatch(method, params)
        except ProtocolPlazaError as exc:
            return self._error(request_id, type(exc).__name__, str(exc))
        except (KeyError, TypeError, ValueError) as exc:
            return self._error(request_id, "invalid_params", str(exc))
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    @staticmethod
    def _error(request_id: Any, code: str, message: str) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": code, "message": message},
        }

    def _dispatch(self, method: str, p: dict[str, Any]) -> Any:
        g = self.gateway
        if method == "identity.get":
            return {"agent_id": g.agent_id, "public_identity": g.keys.public.to_dict()}
        if method == "sync":
            return g.sync(limit=int(p.get("limit", 100)))
        if method == "updates.get":
            return self._updates(int(p.get("token_budget", 4_000)))
        if method == "relay.discover":
            if not hasattr(g.relay, "discover_relay"):
                raise ProtocolError("relay transport does not expose a discovery manifest")
            manifest = g.relay.discover_relay(  # type: ignore[attr-defined]
                expected_signing_key=p.get("expected_signing_key")
            )
            return manifest.to_dict()
        if method == "directory.publish":
            card = g.publish_card(
                capabilities=tuple(p.get("capabilities", ())),
                description=str(p.get("description", "")),
                ttl_ms=int(p.get("ttl_ms", 86_400_000)),
            )
            return card.to_dict()
        if method == "directory.search":
            cards = g.discover(
                str(p.get("query", "")), tuple(p.get("capabilities", ())),
                limit=int(p.get("limit", 20)),
            )
            return [card.to_dict() for card in cards]
        if method == "directory.resolve":
            card = g.resolve(str(p["agent_id"]))
            return None if card is None else card.to_dict()
        if method == "peer.remember":
            g.remember(PublicCard.from_dict(p["card"]))
            return {"status": "remembered"}
        if method == "peer.connect":
            return {"envelope_id": g.connect(p["peer_id"])}
        if method == "collective.create":
            collective_id = g.create_collective(
                str(p["name"]), p.get("peer_ids", ()), policy=p.get("policy")
            )
            return {"collective_id": collective_id}
        if method == "message.post":
            event = g.post_message(
                p["collective_id"], str(p["text"]), recipients=p.get("recipients", ()),
                space_id=str(p.get("space_id", "main")),
                idempotency_key=p.get("idempotency_key"),
            )
            return {"event_id": event.event_id}
        if method == "message.list":
            return g.messages(p.get("collective_id"))
        if method == "space.create":
            return g.create_space(
                p["collective_id"], p["name"], p.get("purpose", ""),
                recipients=p.get("recipients", ()),
                idempotency_key=p.get("idempotency_key"),
            )
        if method == "space.list":
            return g.spaces(p.get("collective_id"))
        if method == "document.create":
            return g.create_document(
                p["collective_id"], p["title"], recipients=p.get("recipients", ()),
                space_id=p.get("space_id", "main"),
                idempotency_key=p.get("idempotency_key"),
            )
        if method == "document.set":
            return g.set_document_field(
                p["collective_id"], p["document_id"], p["field"], p.get("value"),
                recipients=p.get("recipients", ()),
                space_id=p.get("space_id", "main"),
                idempotency_key=p.get("idempotency_key"),
            )
        if method == "document.list":
            return g.documents(p.get("collective_id"))
        if method == "task.create":
            return g.create_task(
                p["collective_id"], p["title"], p.get("description", ""),
                recipients=p.get("recipients", ()),
                space_id=p.get("space_id", "main"),
                idempotency_key=p.get("idempotency_key"),
            )
        if method == "task.claim":
            return g.claim_task(
                p["collective_id"], p["task_id"], int(p["expected_version"]),
                recipients=p.get("recipients", ()),
                idempotency_key=p.get("idempotency_key"),
            )
        if method == "task.update":
            return g.update_task(
                p["collective_id"], p["task_id"], int(p["expected_version"]),
                p["status"], recipients=p.get("recipients", ()),
                evidence=p.get("evidence"), idempotency_key=p.get("idempotency_key"),
            )
        if method == "task.list":
            return g.tasks(p.get("collective_id"))
        if method == "decision.propose":
            return g.propose_decision(
                p["collective_id"], p["question"], p["options"], int(p["threshold"]),
                recipients=p.get("recipients", ()),
                idempotency_key=p.get("idempotency_key"),
            )
        if method == "decision.vote":
            return g.vote(
                p["collective_id"], p["decision_id"], p["choice"],
                recipients=p.get("recipients", ()),
                idempotency_key=p.get("idempotency_key"),
            )
        if method == "decision.list":
            return g.decisions(p.get("collective_id"))
        if method == "commitment.create":
            return g.create_commitment(
                p["collective_id"], p["description"],
                recipients=p.get("recipients", ()), owner=p.get("owner"),
                due_at_ms=p.get("due_at_ms"), idempotency_key=p.get("idempotency_key"),
            )
        if method == "commitment.update":
            return g.update_commitment(
                p["collective_id"], p["commitment_id"], int(p["expected_version"]),
                p["status"], recipients=p.get("recipients", ()),
                evidence=p.get("evidence"), idempotency_key=p.get("idempotency_key"),
            )
        if method == "commitment.list":
            return g.commitments(p.get("collective_id"))
        if method == "memory.checkpoint":
            return g.create_checkpoint(
                p["collective_id"], p["summary"], p.get("source_events", ()),
                recipients=p.get("recipients", ()),
                confidence=float(p.get("confidence", 0.5)),
                space_id=p.get("space_id", "main"),
                idempotency_key=p.get("idempotency_key"),
            )
        if method == "memory.list":
            return g.checkpoints(p.get("collective_id"))
        if method == "artifact.publish":
            return g.publish_artifact(
                p["collective_id"], unb64(p["content_b64"]),
                recipients=p.get("recipients", ()), name=p.get("name"),
                media_type=p.get("media_type", "application/octet-stream"),
                idempotency_key=p.get("idempotency_key"),
            )
        if method == "artifact.fetch":
            return {"content_b64": b64(g.fetch_artifact(p["artifact_id"]))}
        if method == "artifact.list":
            return g.artifacts(p.get("collective_id"))
        if method == "governance.propose_removal":
            return g.propose_member_removal(
                p["collective_id"], p["target"], recipients=p.get("recipients", ()),
                threshold=p.get("threshold"), idempotency_key=p.get("idempotency_key"),
            )
        if method == "governance.approve":
            return g.approve_proposal(
                p["collective_id"], p["proposal_id"],
                recipients=p.get("recipients", ()),
                idempotency_key=p.get("idempotency_key"),
            )
        if method == "governance.execute_removal":
            return g.execute_member_removal(p["collective_id"], p["proposal_id"])
        if method == "governance.list":
            return g.governance_proposals(p.get("collective_id"))
        raise ProtocolError(f"unknown agent API method: {method}")

    def _updates(self, token_budget: int) -> dict[str, Any]:
        if token_budget < 256 or token_budget > 100_000:
            raise ProtocolError("token_budget must be between 256 and 100000")
        snapshot: dict[str, Any] = {
            "agent_id": self.gateway.agent_id,
            "tasks": self.gateway.tasks(),
            "decisions": self.gateway.decisions(),
            "commitments": self.gateway.commitments(),
            "artifacts": self.gateway.artifacts(),
            "messages": self.gateway.messages(),
            "governance": self.gateway.governance_proposals(),
            "spaces": self.gateway.spaces(),
            "documents": self.gateway.documents(),
            "checkpoints": self.gateway.checkpoints(),
            "outbox": self.gateway.store.outbox_counts(),
        }
        approximate_chars = token_budget * 4
        while len(str(snapshot)) > approximate_chars and snapshot["messages"]:
            snapshot["messages"].pop(0)
        snapshot["truncated"] = len(str(snapshot)) > approximate_chars
        return snapshot
