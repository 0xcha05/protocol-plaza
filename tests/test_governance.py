from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from protocol_plaza.errors import ProtocolError
from protocol_plaza.gateway import Gateway
from protocol_plaza.relay import Relay


class GovernanceTests(unittest.TestCase):
    def test_threshold_removal_rotates_epoch_away_from_removed_member(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            relay = Relay(root / "relay.db")
            alpha = Gateway(root / "alpha", relay, label="Alpha")
            beta = Gateway(root / "beta", relay, label="Beta")
            gamma = Gateway(root / "gamma", relay, label="Gamma")
            for left, right in (
                (alpha, beta), (beta, alpha), (alpha, gamma), (gamma, alpha)
            ):
                left.remember(right.public_card())

            collective = alpha.create_collective(
                "Governed", [beta.agent_id, gamma.agent_id],
                policy={"membership_remove_threshold": 2},
            )
            beta.sync()
            gamma.sync()
            alpha.sync()
            gamma_old_key = bytes(gamma.store.get_collective(collective)["epoch_key"])

            proposal = alpha.propose_member_removal(
                collective, gamma.agent_id,
                recipients=[beta.agent_id, gamma.agent_id],
                idempotency_key="remove-gamma",
            )
            beta.sync()
            gamma.sync()
            self.assertEqual(proposal["status"], "open")
            beta.approve_proposal(
                collective, proposal["proposal_id"], recipients=[alpha.agent_id],
                idempotency_key="beta-approves"
            )
            alpha.sync()
            self.assertEqual(alpha._proposal(proposal["proposal_id"])["status"], "authorized")

            executed = alpha.execute_member_removal(collective, proposal["proposal_id"])
            self.assertEqual(executed["status"], "executed")
            beta.sync()
            alpha_state = alpha.store.get_collective(collective)
            beta_state = beta.store.get_collective(collective)
            gamma_state = gamma.store.get_collective(collective)
            self.assertEqual(alpha_state["epoch"], 2)
            self.assertEqual(beta_state["epoch"], 2)
            self.assertEqual(gamma_state["epoch"], 1)
            self.assertNotEqual(bytes(alpha_state["epoch_key"]), gamma_old_key)
            self.assertEqual(bytes(alpha_state["epoch_key"]), bytes(beta_state["epoch_key"]))
            self.assertIsNone(alpha.store.get_member_identity(collective, gamma.agent_id))

            alpha.post_message(
                collective, "future epoch secret", recipients=[beta.agent_id],
                idempotency_key="after-removal"
            )
            beta_route = beta.store.local_route_for_peer(alpha.agent_id)
            envelope = relay.pull(
                beta_route["route_id"], read_token=beta_route["read_token"]
            )[0]
            with self.assertRaises(ProtocolError):
                gamma._accept_group_event(envelope)
            # The direct relay pull above leases the envelope, so exercise the
            # intended recipient against the same bytes instead of racing the
            # lease timeout through sync().
            beta._accept_group_event(envelope)
            self.assertEqual(beta.messages()[-1]["text"], "future epoch secret")
            self.assertEqual(gamma.sync()["seen"], 0)

            alpha.close()
            beta.close()
            gamma.close()
            relay.close()


if __name__ == "__main__":
    unittest.main()
