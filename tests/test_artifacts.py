from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from protocol_plaza.errors import ProtocolError
from protocol_plaza.gateway import Gateway
from protocol_plaza.http_relay import HttpRelayClient, RelayHttpServer
from protocol_plaza.relay import Relay


class ArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.relay = Relay(self.root / "relay.db")
        self.server = RelayHttpServer(self.relay).start()
        alpha_client = HttpRelayClient.register(
            self.server.base_url, self.server.bootstrap_token, "Alpha"
        )
        beta_client = HttpRelayClient.register(
            self.server.base_url, self.server.bootstrap_token, "Beta"
        )
        self.alpha = Gateway(self.root / "alpha", alpha_client, label="Alpha")
        self.beta = Gateway(self.root / "beta", beta_client, label="Beta")
        self.alpha.remember(self.beta.public_card())
        self.beta.remember(self.alpha.public_card())
        self.collective = self.alpha.create_collective("Artifacts", [self.beta.agent_id])
        self.beta.sync()
        self.alpha.sync()

    def tearDown(self) -> None:
        self.alpha.close()
        self.beta.close()
        self.server.close()
        self.relay.close()
        self.temp.cleanup()

    def test_encrypted_artifact_round_trip_and_relay_opacity(self) -> None:
        secret = b"private model result: 4f819e\n" * 100
        artifact = self.alpha.publish_artifact(
            self.collective, secret, name="result.txt", media_type="text/plain",
            recipients=[self.beta.agent_id], idempotency_key="artifact-one"
        )
        self.beta.sync()
        self.assertEqual(self.beta.fetch_artifact(artifact["artifact_id"]), secret)
        self.assertNotIn(secret[:20], (self.root / "relay.db").read_bytes())
        self.assertNotIn(b"result.txt", (self.root / "relay.db").read_bytes())
        self.assertEqual(self.alpha.artifacts(), self.beta.artifacts())

    def test_ciphertext_corruption_is_detected(self) -> None:
        artifact = self.alpha.publish_artifact(
            self.collective, b"integrity matters", name="proof.bin",
            recipients=[self.beta.agent_id]
        )
        self.beta.sync()
        with self.relay._db:
            self.relay._db.execute(
                "UPDATE blobs SET ciphertext = ? WHERE blob_id = ?",
                (b"corrupt", artifact["blob_id"]),
            )
        with self.assertRaisesRegex(ProtocolError, "ciphertext hash"):
            self.beta.fetch_artifact(artifact["artifact_id"])


if __name__ == "__main__":
    unittest.main()
