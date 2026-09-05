from __future__ import annotations

from typing import Protocol

from .models import PublicCard, RelayEnvelope
from .relay import RouteCredentials


class RelayTransport(Protocol):
    """Narrow content-blind API required by a gateway."""

    def create_route(self, *, ttl_ms: int | None = None) -> RouteCredentials: ...

    def revoke_route(self, route_id: str, *, read_token: str) -> None: ...

    def push(self, envelope: RelayEnvelope, *, write_token: str) -> bool: ...

    def pull(
        self, route_id: str, *, read_token: str, limit: int = 100
    ) -> list[RelayEnvelope]: ...

    def acknowledge(
        self, route_id: str, envelope_ids: list[str], *, read_token: str
    ) -> int: ...

    def publish_public_card(self, card: PublicCard) -> None: ...

    def resolve_public_card(self, agent_id: str) -> PublicCard | None: ...

    def search_public_cards(
        self, query: str = "", capabilities: tuple[str, ...] = (), *, limit: int = 20
    ) -> list[PublicCard]: ...
