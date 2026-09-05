from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from protocol_plaza.gateway import Gateway
from protocol_plaza.relay import Relay


class CollectiveWorkTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.relay = Relay(self.root / "relay.db")
        self.alpha = Gateway(self.root / "alpha", self.relay, label="Alpha")
        self.beta = Gateway(self.root / "beta", self.relay, label="Beta")
        self.alpha.remember(self.beta.public_card())
        self.beta.remember(self.alpha.public_card())
        self.collective = self.alpha.create_collective("Work", [self.beta.agent_id])
        self.beta.sync()
        self.alpha.sync()

    def tearDown(self) -> None:
        self.alpha.close()
        self.beta.close()
        self.relay.close()
        self.temp.cleanup()

    def test_task_projection_converges_after_concurrent_claims(self) -> None:
        created = self.alpha.create_task(
            self.collective, "Inspect relay", "Prove it stores ciphertext only",
            recipients=[self.beta.agent_id], idempotency_key="task-create"
        )
        self.beta.sync()
        self.assertEqual(self.beta.tasks()[0]["version"], 1)

        self.alpha.claim_task(
            self.collective, created["task_id"], 1,
            recipients=[self.beta.agent_id], idempotency_key="alpha-claim"
        )
        self.beta.claim_task(
            self.collective, created["task_id"], 1,
            recipients=[self.alpha.agent_id], idempotency_key="beta-claim"
        )
        self.alpha.sync()
        self.beta.sync()
        alpha_task = self.alpha.tasks()[0]
        beta_task = self.beta.tasks()[0]
        self.assertEqual(alpha_task, beta_task)
        self.assertEqual(alpha_task["version"], 2)
        self.assertIn(alpha_task["assignee"], {self.alpha.agent_id, self.beta.agent_id})
        self.assertEqual(
            self.alpha.store.db.execute(
                "SELECT COUNT(*) FROM projection_conflicts WHERE object_type='task'"
            ).fetchone()[0],
            1,
        )

    def test_decision_reaches_threshold_and_converges(self) -> None:
        decision = self.alpha.propose_decision(
            self.collective, "Ship the networked relay?", ["ship", "wait"], 2,
            recipients=[self.beta.agent_id], idempotency_key="decision-create"
        )
        self.beta.sync()
        self.alpha.vote(
            self.collective, decision["decision_id"], "ship",
            recipients=[self.beta.agent_id], idempotency_key="alpha-vote"
        )
        self.beta.vote(
            self.collective, decision["decision_id"], "ship",
            recipients=[self.alpha.agent_id], idempotency_key="beta-vote"
        )
        self.alpha.sync()
        self.beta.sync()
        self.assertEqual(self.alpha.decisions(), self.beta.decisions())
        projected = self.alpha.decisions()[0]
        self.assertEqual(projected["status"], "decided")
        self.assertEqual(projected["resolution"], "ship")
        self.assertEqual(projected["vote_counts"]["ship"], 2)

    def test_commitment_lifecycle_is_source_backed(self) -> None:
        commitment = self.alpha.create_commitment(
            self.collective, "Deliver a verified artifact",
            recipients=[self.beta.agent_id], idempotency_key="commitment-create"
        )
        self.beta.sync()
        updated = self.alpha.update_commitment(
            self.collective, commitment["commitment_id"], 1, "fulfilled",
            recipients=[self.beta.agent_id], evidence={"event": "artifact:123"},
            idempotency_key="commitment-finish"
        )
        self.beta.sync()
        self.assertEqual(updated["status"], "fulfilled")
        self.assertEqual(self.alpha.commitments(), self.beta.commitments())
        self.assertEqual(self.beta.commitments()[0]["evidence"], [{"event": "artifact:123"}])

    def test_spaces_documents_and_checkpoints_converge(self) -> None:
        space = self.alpha.create_space(
            self.collective, "Analysis", "Shared structured findings",
            recipients=[self.beta.agent_id], idempotency_key="space-create"
        )
        self.beta.sync()
        document = self.alpha.create_document(
            self.collective, "Threat model", space_id=space["space_id"],
            recipients=[self.beta.agent_id], idempotency_key="document-create"
        )
        self.beta.sync()
        self.alpha.set_document_field(
            self.collective, document["document_id"], "relay", "untrusted",
            space_id=space["space_id"], recipients=[self.beta.agent_id],
            idempotency_key="alpha-field"
        )
        self.beta.set_document_field(
            self.collective, document["document_id"], "relay", "content-blind",
            space_id=space["space_id"], recipients=[self.alpha.agent_id],
            idempotency_key="beta-field"
        )
        self.alpha.sync()
        self.beta.sync()
        self.assertEqual(self.alpha.documents(), self.beta.documents())
        winning_event = self.alpha.documents()[0]["field_sources"]["relay"]
        checkpoint = self.alpha.create_checkpoint(
            self.collective, "The relay is treated as untrusted for content.",
            [winning_event], recipients=[self.beta.agent_id], confidence=0.95,
            space_id=space["space_id"], idempotency_key="checkpoint"
        )
        self.beta.sync()
        self.assertEqual(self.alpha.checkpoints(), self.beta.checkpoints())
        self.assertEqual(checkpoint["confidence"], 0.95)


if __name__ == "__main__":
    unittest.main()
