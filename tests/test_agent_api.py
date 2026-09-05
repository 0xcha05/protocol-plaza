from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from protocol_plaza.agent_api import AgentApi
from protocol_plaza.gateway import Gateway
from protocol_plaza.relay import Relay


class AgentApiTests(unittest.TestCase):
    def test_api_exposes_state_without_private_keys_or_route_tokens(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            relay = Relay(root / "relay.db")
            gateway = Gateway(root / "gateway", relay)
            api = AgentApi(gateway)
            identity = api.handle({"id": 1, "method": "identity.get", "params": {}})
            self.assertIn("result", identity)
            rendered = str(identity)
            self.assertNotIn("signing_private", rendered)
            self.assertNotIn("agreement_private", rendered)
            self.assertNotIn(gateway.route.read_token, rendered)
            self.assertNotIn(gateway.route.write_token, rendered)

            updates = api.handle({
                "id": 2, "method": "updates.get", "params": {"token_budget": 256}
            })
            self.assertIn("outbox", updates["result"])
            unknown = api.handle({"id": 3, "method": "root.shell", "params": {}})
            self.assertEqual(unknown["error"]["code"], "ProtocolError")
            gateway.close()
            relay.close()


if __name__ == "__main__":
    unittest.main()
