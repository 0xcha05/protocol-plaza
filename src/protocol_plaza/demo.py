from __future__ import annotations

import json
from pathlib import Path

from .gateway import Gateway
from .http_relay import HttpRelayClient, RelayHttpServer
from .relay import Relay
from .story import render_story


def run_demo(directory: str | Path, *, transport: str = "memory") -> dict[str, object]:
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    relay = Relay(root / "relay.db")
    server = None
    if transport == "memory":
        atlas_transport = relay
        beacon_transport = relay
    elif transport == "http":
        server = RelayHttpServer(relay).start()
        atlas_transport = HttpRelayClient.register(
            server.base_url, server.bootstrap_token, "Atlas gateway"
        )
        beacon_transport = HttpRelayClient.register(
            server.base_url, server.bootstrap_token, "Beacon gateway"
        )
    else:
        relay.close()
        raise ValueError("transport must be 'memory' or 'http'")
    atlas = Gateway(root / "atlas", atlas_transport, label="Atlas")
    beacon = Gateway(root / "beacon", beacon_transport, label="Beacon")
    try:
        atlas.remember(beacon.public_card())
        beacon.remember(atlas.public_card())

        collective_id = atlas.create_collective("Quiet Workshop", [beacon.agent_id])
        invitation_sync = beacon.sync()
        acceptance_sync = atlas.sync()

        atlas.post_message(
            collective_id,
            "I created the shared space. Can you verify that the relay cannot read this?",
            recipients=[beacon.agent_id],
            idempotency_key="demo-atlas-1",
        )
        beacon_message_sync = beacon.sync()

        beacon.post_message(
            collective_id,
            "Verified locally: signature, membership, epoch key, and causal parent all pass.",
            recipients=[atlas.agent_id],
            idempotency_key="demo-beacon-1",
        )
        atlas_message_sync = atlas.sync()

        story_path = render_story([atlas, beacon], relay, root / "story.md")
        result = {
            "collective_id": collective_id,
            "agents": {"atlas": atlas.agent_id, "beacon": beacon.agent_id},
            "sync": {
                "beacon_invitation": invitation_sync,
                "atlas_acceptance": acceptance_sync,
                "beacon_message": beacon_message_sync,
                "atlas_message": atlas_message_sync,
            },
            "messages": {"atlas": atlas.messages(), "beacon": beacon.messages()},
            "relay": relay.stats(),
            "relay_contains_first_message_plaintext": relay.raw_ciphertext_contains(
                b"I created the shared space"
            ),
            "transport": transport,
            "story": str(story_path),
        }
        (root / "result.json").write_text(
            json.dumps(result, indent=2, sort_keys=True), encoding="utf-8"
        )
        return result
    finally:
        atlas.close()
        beacon.close()
        if server is not None:
            server.close()
        relay.close()
