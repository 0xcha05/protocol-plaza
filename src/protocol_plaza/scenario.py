from __future__ import annotations

import json
from pathlib import Path

from .gateway import Gateway
from .http_relay import HttpRelayClient, RelayHttpServer
from .relay import Relay
from .story import render_story


def run_full_scenario(directory: str | Path) -> dict[str, object]:
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    relay = Relay(root / "relay.db")
    server = RelayHttpServer(relay).start()
    gateways: list[Gateway] = []
    try:
        relay_manifest = HttpRelayClient(server.base_url).discover_relay(
            expected_signing_key=server.discovery_manifest.signing_key
        )
        profiles = [
            ("Atlas", ("coordinate", "research")),
            ("Beacon", ("verify", "artifact.verify")),
            ("Cipher", ("research", "document.edit")),
        ]
        for label, _ in profiles:
            client = HttpRelayClient.register(
                server.base_url, server.bootstrap_token, f"{label} gateway"
            )
            gateways.append(Gateway(root / label.lower(), client, label=label))
        atlas, beacon, cipher = gateways

        cards = []
        for gateway, (label, capabilities) in zip(gateways, profiles):
            cards.append(gateway.publish_card(
                capabilities=capabilities,
                description=f"{label} participant in a private collective acceptance run",
            ))
        for gateway in gateways:
            for card in gateway.discover("private collective"):
                gateway.remember(card)

        atlas.connect(beacon.agent_id)
        atlas.connect(cipher.agent_id)
        beacon.connect(cipher.agent_id)
        beacon.sync()
        cipher.sync()
        atlas.sync()
        beacon.sync()

        collective = atlas.create_collective(
            "Acceptance Collective",
            [beacon.agent_id, cipher.agent_id],
            policy={"membership_remove_threshold": 2},
        )
        beacon.sync()
        cipher.sync()
        atlas.sync()

        peers_of_atlas = [beacon.agent_id, cipher.agent_id]
        space = atlas.create_space(
            collective, "Protocol Review", "Verify the private coordination substrate",
            recipients=peers_of_atlas, idempotency_key="scenario-space",
        )
        beacon.sync()
        cipher.sync()
        task = atlas.create_task(
            collective, "Audit the relay", "Check content privacy and event integrity",
            recipients=peers_of_atlas, space_id=space["space_id"],
            idempotency_key="scenario-task",
        )
        beacon.sync()
        cipher.sync()
        beacon.claim_task(
            collective, task["task_id"], 1,
            recipients=[atlas.agent_id, cipher.agent_id],
            space_id=space["space_id"], idempotency_key="scenario-claim",
        )
        atlas.sync()
        cipher.sync()
        beacon.update_task(
            collective, task["task_id"], 2, "submitted",
            recipients=[atlas.agent_id, cipher.agent_id],
            evidence={"check": "relay plaintext scan false"},
            space_id=space["space_id"], idempotency_key="scenario-submit",
        )
        atlas.sync()
        cipher.sync()
        atlas.update_task(
            collective, task["task_id"], 3, "verified",
            recipients=peers_of_atlas, evidence={"reviewed_by": atlas.agent_id},
            space_id=space["space_id"], idempotency_key="scenario-verify",
        )
        beacon.sync()
        cipher.sync()

        decision = atlas.propose_decision(
            collective, "Accept the encrypted relay slice?", ["accept", "revise"], 2,
            recipients=peers_of_atlas, space_id=space["space_id"],
            idempotency_key="scenario-decision",
        )
        beacon.sync()
        cipher.sync()
        atlas.vote(
            collective, decision["decision_id"], "accept",
            recipients=peers_of_atlas, space_id=space["space_id"],
            idempotency_key="scenario-vote-atlas",
        )
        beacon.vote(
            collective, decision["decision_id"], "accept",
            recipients=[atlas.agent_id, cipher.agent_id], space_id=space["space_id"],
            idempotency_key="scenario-vote-beacon",
        )
        for gateway in gateways:
            gateway.sync()

        document = cipher.create_document(
            collective, "Shared findings", recipients=[atlas.agent_id, beacon.agent_id],
            space_id=space["space_id"], idempotency_key="scenario-document",
        )
        atlas.sync()
        beacon.sync()
        cipher.set_document_field(
            collective, document["document_id"], "relay_content", "unavailable",
            recipients=[atlas.agent_id, beacon.agent_id], space_id=space["space_id"],
            idempotency_key="scenario-document-field",
        )
        atlas.sync()
        beacon.sync()
        commitment = cipher.create_commitment(
            collective, "Record the shared relay finding",
            recipients=[atlas.agent_id, beacon.agent_id],
            owner=cipher.agent_id, space_id=space["space_id"],
            idempotency_key="scenario-commitment",
        )
        atlas.sync()
        beacon.sync()
        cipher.update_commitment(
            collective, commitment["commitment_id"], 1, "fulfilled",
            recipients=[atlas.agent_id, beacon.agent_id],
            evidence={"document_id": document["document_id"]},
            space_id=space["space_id"],
            idempotency_key="scenario-commitment-complete",
        )
        atlas.sync()
        beacon.sync()

        artifact_bytes = b"verified acceptance evidence\nrelay_plaintext=false\n"
        artifact = atlas.publish_artifact(
            collective, artifact_bytes, name="acceptance-evidence.txt",
            media_type="text/plain", recipients=peers_of_atlas,
            space_id=space["space_id"], idempotency_key="scenario-artifact",
        )
        beacon.sync()
        cipher.sync()
        artifact_verified = beacon.fetch_artifact(artifact["artifact_id"]) == artifact_bytes
        checkpoint = beacon.create_checkpoint(
            collective,
            "Relay privacy, signatures, task convergence and artifact integrity verified.",
            [task["updated_event_id"], artifact["published_event_id"]],
            recipients=[atlas.agent_id, cipher.agent_id], confidence=0.98,
            space_id=space["space_id"], idempotency_key="scenario-checkpoint",
        )
        atlas.sync()
        cipher.sync()

        proposal = atlas.propose_member_removal(
            collective, cipher.agent_id, recipients=peers_of_atlas,
            idempotency_key="scenario-removal",
        )
        beacon.sync()
        cipher.sync()
        beacon.approve_proposal(
            collective, proposal["proposal_id"],
            recipients=[atlas.agent_id, cipher.agent_id],
            idempotency_key="scenario-removal-approval",
        )
        atlas.sync()
        cipher.sync()
        atlas.execute_member_removal(collective, proposal["proposal_id"])
        beacon.sync()
        atlas.post_message(
            collective, "Epoch rotation complete; continuing with remaining members.",
            recipients=[beacon.agent_id], idempotency_key="scenario-final-message",
        )
        beacon.sync()

        story_path = render_story(gateways, relay, root / "story.md")
        result = {
            "collective_id": collective,
            "agents": {gateway.label: gateway.agent_id for gateway in gateways},
            "relay_discovery": {
                "relay_id": relay_manifest.relay_id,
                "signing_key": relay_manifest.signing_key,
                "integrity_verified": True,
                "identity_pinned": True,
                "external_identity_provider": None,
            },
            "artifact_verified": artifact_verified,
            "checkpoint_id": checkpoint["checkpoint_id"],
            "relay": relay.stats(),
            "relay_plaintext_checks": {
                "collective_name": relay.raw_ciphertext_contains(b"Acceptance Collective"),
                "artifact_name": relay.raw_ciphertext_contains(b"acceptance-evidence.txt"),
                "final_message": relay.raw_ciphertext_contains(b"Epoch rotation complete"),
            },
            "state": {
                gateway.label: {
                    "epoch": int(gateway.store.get_collective(collective)["epoch"]),
                    "tasks": gateway.tasks(collective),
                    "decisions": gateway.decisions(collective),
                    "documents": gateway.documents(collective),
                    "commitments": gateway.commitments(collective),
                    "artifacts": gateway.artifacts(collective),
                    "checkpoints": gateway.checkpoints(collective),
                    "governance": gateway.governance_proposals(collective),
                }
                for gateway in gateways
            },
            "story": str(story_path),
        }
        (root / "result.json").write_text(
            json.dumps(result, indent=2, sort_keys=True), encoding="utf-8"
        )
        return result
    finally:
        for gateway in gateways:
            gateway.close()
        server.close()
        relay.close()
