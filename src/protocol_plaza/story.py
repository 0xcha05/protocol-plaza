from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from .gateway import Gateway
from .relay import Relay


def _when(timestamp_ms: int) -> str:
    return datetime.fromtimestamp(timestamp_ms / 1000, tz=UTC).isoformat()


def render_story(gateways: list[Gateway], relay: Relay, destination: str | Path) -> Path:
    path = Path(destination)
    lines = [
        "# Protocol Plaza run story",
        "",
        "This report is reconstructed from each trusted gateway's private audit trail. "
        "The relay contains operational metadata and ciphertext only.",
        "",
        "## Cast",
        "",
    ]
    for gateway in gateways:
        lines.append(f"- **{gateway.label}** — `{gateway.agent_id}`")
    lines.extend(["", "## Timeline", ""])
    records = []
    for gateway in gateways:
        for row in gateway.store.audit_rows():
            records.append((int(row["occurred_at_ms"]), int(row["audit_id"]), gateway, row))
    records.sort(key=lambda item: (item[0], item[2].agent_id, item[1]))
    for timestamp, _, gateway, row in records:
        lines.append(
            f"- **{_when(timestamp)} — {gateway.label}:** {row['summary']} "
            f"(`{row['action']}`, {row['outcome']})"
        )
    stats = relay.stats()
    lines.extend(
        [
            "",
            "## Relay's limited view",
            "",
            f"- Opaque routes: {stats['routes']}",
            f"- Ciphertext envelopes retained: {stats['envelopes']}",
            f"- Ciphertext bytes: {stats['bytes']}",
            f"- Unacknowledged envelopes: {stats['pending']}",
            "- Message text, collective names, membership and causal event types: "
            "unavailable to relay",
            "",
            "## Verified messages by gateway",
            "",
        ]
    )
    for gateway in gateways:
        lines.append(f"### {gateway.label}")
        lines.append("")
        messages = gateway.messages()
        if not messages:
            lines.append("No verified messages.")
        for message in messages:
            lines.append(
                f"- `{message['event_id'][:12]}` from `{message['author']}` "
                f"(sequence {message['author_seq']}): {message['text']}"
            )
        lines.append("")
    lines.extend(["## Structured collective state", ""])
    for gateway in gateways:
        lines.extend([f"### {gateway.label}", ""])
        collectives = gateway.store.list_collectives()
        lines.append(f"- Collectives: {len(collectives)}")
        for collective in collectives:
            members = gateway.store.active_member_ids(collective["collective_id"])
            lines.append(
                f"  - `{collective['collective_id']}` — {collective['name']}, "
                f"epoch {collective['epoch']}, {len(members)} active members"
            )
        spaces = gateway.spaces()
        lines.append(f"- Spaces: {len(spaces)}")
        for space in spaces:
            lines.append(
                f"  - `{space['space_id']}` — {space['name']}: {space['purpose']}"
            )
        tasks = gateway.tasks()
        decisions = gateway.decisions()
        commitments = gateway.commitments()
        artifacts = gateway.artifacts()
        governance = gateway.governance_proposals()
        lines.append(f"- Tasks: {len(tasks)}")
        for task in tasks:
            lines.append(
                f"  - `{task['task_id']}` — {task['status']}, version {task['version']}, "
                f"assignee `{task['assignee'] or 'unassigned'}`: {task['title']}"
            )
        lines.append(f"- Decisions: {len(decisions)}")
        for decision in decisions:
            lines.append(
                f"  - `{decision['decision_id']}` — {decision['status']}; "
                f"resolution `{decision['resolution'] or 'none'}`: {decision['question']}"
            )
        lines.append(f"- Commitments: {len(commitments)}")
        for commitment in commitments:
            lines.append(
                f"  - `{commitment['commitment_id']}` — {commitment['status']}, "
                f"owner `{commitment['owner']}`: {commitment['description']}"
            )
        lines.append(f"- Artifacts: {len(artifacts)}")
        for artifact in artifacts:
            lines.append(
                f"  - `{artifact['artifact_id']}` — {artifact['name']} "
                f"({artifact['byte_size']} bytes, SHA-256 `{artifact['plaintext_sha256']}`)"
            )
        documents = gateway.documents()
        lines.append(f"- Documents: {len(documents)}")
        for document in documents:
            lines.append(
                f"  - `{document['document_id']}` — {document['title']}; "
                f"fields: {', '.join(document['fields']) or 'none'}"
            )
        checkpoints = gateway.checkpoints()
        lines.append(f"- Memory checkpoints: {len(checkpoints)}")
        for checkpoint in checkpoints:
            lines.append(
                f"  - `{checkpoint['checkpoint_id']}` — confidence "
                f"{checkpoint['confidence']:.2f}: {checkpoint['summary']}"
            )
        lines.append(f"- Governance proposals: {len(governance)}")
        for proposal in governance:
            lines.append(
                f"  - `{proposal['proposal_id']}` — {proposal['operation']} "
                f"`{proposal['target']}` is {proposal['status']} with "
                f"{len(proposal['approvals'])}/{proposal['threshold']} approvals"
            )
        conflicts = gateway.store.db.execute(
            "SELECT object_type, object_id, reason, event_id FROM projection_conflicts "
            "ORDER BY object_type, object_id, event_id"
        ).fetchall()
        lines.append(f"- Preserved projection conflicts: {len(conflicts)}")
        for conflict in conflicts:
            lines.append(
                f"  - `{conflict['event_id'][:12]}` on {conflict['object_type']} "
                f"`{conflict['object_id']}`: {conflict['reason']}"
            )
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")
    return path
