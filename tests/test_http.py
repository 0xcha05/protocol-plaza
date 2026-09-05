from __future__ import annotations

import stat
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from protocol_plaza.codec import b64
from protocol_plaza.discovery import RelayManifest
from protocol_plaza.errors import AuthenticationError, CryptographicError, ProtocolError
from protocol_plaza.gateway import Gateway
from protocol_plaza.http_relay import HttpRelayClient, RelayHttpServer
from protocol_plaza.models import RelayEnvelope, now_ms, random_id
from protocol_plaza.relay import Relay, ServiceCredential


class HttpRelayTests(unittest.TestCase):
    def test_first_party_discovery_manifest_is_signed_pinnable_and_persistent(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            relay_path = root / "relay.db"
            relay = Relay(relay_path)
            with RelayHttpServer(relay) as server:
                client = HttpRelayClient(server.base_url)
                manifest = client.discover_relay()
                self.assertEqual(manifest.service, "protocol-plaza")
                self.assertIn("capability-search", manifest.features)
                self.assertEqual(
                    manifest.endpoints["card_search"], "/v1/directory/search"
                )
                pinned = client.discover_relay(
                    expected_signing_key=manifest.signing_key
                )
                self.assertEqual(pinned.relay_id, manifest.relay_id)
                with self.assertRaises(CryptographicError):
                    client.discover_relay(expected_signing_key=b64(b"x" * 32))

                tampered = manifest.to_dict()
                tampered["endpoints"] = {
                    **tampered["endpoints"], "card_search": "/v1/other"
                }
                with self.assertRaises(CryptographicError):
                    RelayManifest.from_dict(tampered).verify()
                original_key = manifest.signing_key
            relay.close()

            identity_path = Path(str(relay_path) + ".identity.json")
            self.assertEqual(stat.S_IMODE(identity_path.stat().st_mode), 0o600)

            restarted_relay = Relay(relay_path)
            with RelayHttpServer(restarted_relay) as restarted:
                after_restart = HttpRelayClient(restarted.base_url).discover_relay(
                    expected_signing_key=original_key
                )
                self.assertEqual(after_restart.signing_key, original_key)
            restarted_relay.close()

    def test_complete_route_lifecycle_over_http(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            relay = Relay(Path(temp) / "relay.db")
            with RelayHttpServer(relay) as server:
                client = HttpRelayClient.register(
                    server.base_url, server.bootstrap_token, "test gateway"
                )
                self.assertEqual(client.health()["status"], "ok")
                route = client.create_route()
                envelope_id = random_id("env")
                envelope = RelayEnvelope(
                    envelope_id=envelope_id,
                    route_id=route.route_id,
                    kind="opaque/v1",
                    aad=envelope_id,
                    payload={"ephemeral_key": "AA", "ciphertext": "AA", "nonce": "AA"},
                    created_at_ms=now_ms(),
                    expires_at_ms=now_ms() + 60_000,
                )
                self.assertTrue(client.push(envelope, write_token=route.write_token))
                self.assertFalse(client.push(envelope, write_token=route.write_token))
                with self.assertRaises(AuthenticationError):
                    client.pull(route.route_id, read_token="wrong")
                received = client.pull(route.route_id, read_token=route.read_token)
                self.assertEqual(received[0].envelope_id, envelope_id)
                self.assertEqual(client.acknowledge(
                    route.route_id, [envelope_id], read_token=route.read_token
                ), 1)
                client.revoke_route(route.route_id, read_token=route.read_token)
                with self.assertRaises(AuthenticationError):
                    client.pull(route.route_id, read_token=route.read_token)
            relay.close()

    def test_signed_directory_discovery(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            relay = Relay(root / "relay.db")
            with RelayHttpServer(relay) as server:
                publisher_client = HttpRelayClient.register(
                    server.base_url, server.bootstrap_token, "publisher"
                )
                seeker_client = HttpRelayClient.register(
                    server.base_url, server.bootstrap_token, "seeker"
                )
                publisher = Gateway(root / "publisher", publisher_client)
                card = publisher.publish_card(
                    capabilities=("research", "artifact.verify"),
                    description="Audits encrypted coordination protocols",
                )
                found = seeker_client.search_public_cards(
                    "coordination", ("artifact.verify",)
                )
                self.assertEqual([item.identity.agent_id for item in found], [publisher.agent_id])
                resolved = seeker_client.resolve_public_card(publisher.agent_id)
                self.assertEqual(resolved.to_dict(), card.to_dict())
                resolved.verify()
                publisher.close()
            relay.close()

    def test_service_route_and_byte_quotas(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            relay = Relay(Path(temp) / "relay.db")
            with RelayHttpServer(relay) as server:
                limited = HttpRelayClient.register(
                    server.base_url, server.bootstrap_token, "limited",
                    route_limit=1, daily_byte_limit=100,
                )
                route = limited.create_route()
                with self.assertRaises(ProtocolError):
                    limited.create_route()
                envelope_id = random_id("env")
                envelope = RelayEnvelope(
                    envelope_id=envelope_id, route_id=route.route_id,
                    kind="opaque/v1", aad=envelope_id,
                    payload={
                        "ephemeral_key": "A" * 32,
                        "nonce": "B" * 16,
                        "ciphertext": "C" * 200,
                    },
                    created_at_ms=now_ms(), expires_at_ms=now_ms() + 60_000,
                )
                with self.assertRaises(ProtocolError):
                    limited.push(envelope, write_token=route.write_token)
                self.assertEqual(relay.stats()["envelopes"], 0)
            relay.close()

    def test_stolen_bearer_without_proof_key_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            relay = Relay(Path(temp) / "relay.db")
            with RelayHttpServer(relay) as server:
                legitimate = HttpRelayClient.register(
                    server.base_url, server.bootstrap_token, "bound"
                )
                wrong_key = Ed25519PrivateKey.generate().private_bytes(
                    serialization.Encoding.Raw,
                    serialization.PrivateFormat.Raw,
                    serialization.NoEncryption(),
                )
                stolen = HttpRelayClient(
                    server.base_url,
                    credential=ServiceCredential(
                        legitimate.credential.principal_id,
                        legitimate.credential.access_token,
                        b64(wrong_key),
                    ),
                )
                with self.assertRaises(AuthenticationError):
                    stolen.create_route()
                self.assertIsNotNone(legitimate.create_route().route_id)
            relay.close()


if __name__ == "__main__":
    unittest.main()
