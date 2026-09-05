from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from protocol_plaza.codec import canonical_json
from protocol_plaza.crypto import IdentityKeys, seal_to
from protocol_plaza.errors import AuthenticationError, CryptographicError, ProtocolError
from protocol_plaza.gateway import Gateway
from protocol_plaza.models import RelayEnvelope, SignedEvent, now_ms, random_id
from protocol_plaza.relay import Relay


class ProtocolTests(unittest.TestCase):
    def test_canonical_json_is_deterministic(self) -> None:
        self.assertEqual(canonical_json({"b": 2, "a": [3, 1]}), b'{"a":[3,1],"b":2}')

    def test_signed_event_detects_body_tampering(self) -> None:
        keys = IdentityKeys.generate()
        event = SignedEvent.create(
            keys, collective_id="c1", space_id="main", author_seq=1, parents=(),
            event_type="message.posted", body={"text": "original"},
            idempotency_key="one", created_at_ms=1,
        )
        event.verify(keys.public)
        value = event.to_dict()
        value["body"] = {"text": "changed"}
        tampered = SignedEvent.from_dict(value)
        with self.assertRaisesRegex(ProtocolError, "event id"):
            tampered.verify(keys.public)

    def test_signed_event_rejects_wrong_identity(self) -> None:
        first = IdentityKeys.generate()
        second = IdentityKeys.generate()
        event = SignedEvent.create(
            first, collective_id="c1", space_id="main", author_seq=1, parents=(),
            event_type="message.posted", body={"text": "hello"}, idempotency_key="one",
        )
        with self.assertRaisesRegex(ProtocolError, "author"):
            event.verify(second.public)

    def test_relay_tokens_and_idempotency(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            relay = Relay(Path(temp) / "relay.db")
            route = relay.create_route()
            envelope_id = random_id("env")
            envelope = RelayEnvelope(
                envelope_id=envelope_id, route_id=route.route_id,
                kind="opaque/v1", aad=envelope_id,
                payload={"ephemeral_key": "z", "nonce": "x", "ciphertext": "y"},
                created_at_ms=now_ms(), expires_at_ms=now_ms() + 60_000,
            )
            with self.assertRaises(AuthenticationError):
                relay.push(envelope, write_token="wrong")
            self.assertTrue(relay.push(envelope, write_token=route.write_token))
            self.assertFalse(relay.push(envelope, write_token=route.write_token))
            with self.assertRaises(AuthenticationError):
                relay.pull(route.route_id, read_token="wrong")
            self.assertEqual(
                [
                    item.envelope_id
                    for item in relay.pull(
                        route.route_id, read_token=route.read_token
                    )
                ],
                [envelope.envelope_id],
            )
            self.assertEqual(relay.acknowledge(
                route.route_id, [envelope.envelope_id], read_token=route.read_token
            ), 1)
            self.assertEqual(relay.pull(route.route_id, read_token=route.read_token), [])
            relay.close()

    def test_two_gateways_exchange_without_relay_plaintext(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            relay = Relay(root / "relay.db")
            alpha = Gateway(root / "alpha", relay, label="Alpha")
            beta = Gateway(root / "beta", relay, label="Beta")
            alpha.remember(beta.public_card())
            beta.remember(alpha.public_card())
            collective = alpha.create_collective("Private", [beta.agent_id])
            self.assertEqual(beta.sync()["accepted"], 1)
            self.assertEqual(alpha.sync()["accepted"], 1)

            text = "a message the relay must never learn"
            first = alpha.post_message(
                collective, text, recipients=[beta.agent_id], idempotency_key="same"
            )
            repeated = alpha.post_message(
                collective, "ignored due to idempotency", recipients=[beta.agent_id],
                idempotency_key="same"
            )
            self.assertEqual(repeated.event_id, first.event_id)
            self.assertEqual(beta.sync()["accepted"], 1)
            self.assertEqual(beta.messages()[0]["text"], text)
            self.assertFalse(relay.raw_ciphertext_contains(text.encode()))
            self.assertEqual(os.stat(root / "alpha" / "identity.json").st_mode & 0o777, 0o600)
            alpha.close()
            beta.close()
            relay.close()

    def test_public_card_tampering_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            relay = Relay(root / "relay.db")
            alpha = Gateway(root / "alpha", relay)
            beta = Gateway(root / "beta", relay)
            value = alpha.public_card().to_dict()
            value["contact_route"] = "route_attacker"
            from protocol_plaza.models import PublicCard
            with self.assertRaises(CryptographicError):
                beta.remember(PublicCard.from_dict(value))
            alpha.close()
            beta.close()
            relay.close()

    def test_corrupted_ciphertext_is_rejected_and_acknowledged(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            relay = Relay(root / "relay.db")
            receiver = Gateway(root / "receiver", relay)
            envelope_id = random_id("env")
            envelope = RelayEnvelope(
                envelope_id=envelope_id, route_id=receiver.route.route_id,
                kind="opaque/v1", aad=envelope_id,
                payload={"ephemeral_key": "AAAA", "nonce": "AAAA", "ciphertext": "AAAA"},
                created_at_ms=now_ms(), expires_at_ms=now_ms() + 60_000,
            )
            relay.push(envelope, write_token=receiver.route.write_token)
            self.assertEqual(receiver.sync()["rejected"], 1)
            self.assertEqual(relay.stats()["pending"], 0)
            receiver.close()
            relay.close()

    def test_authenticated_but_malformed_invitation_does_not_crash_sync(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            relay = Relay(root / "relay.db")
            receiver = Gateway(root / "receiver", relay)
            envelope_id = random_id("env")
            sealed = seal_to(
                receiver.keys.public, b"this is not json", aad=envelope_id.encode()
            )
            envelope = RelayEnvelope(
                envelope_id=envelope_id, route_id=receiver.route.route_id,
                kind="opaque/v1", aad=envelope_id,
                payload=sealed,
                created_at_ms=now_ms(), expires_at_ms=now_ms() + 60_000,
            )
            relay.push(envelope, write_token=receiver.route.write_token)
            result = receiver.sync()
            self.assertEqual(result["rejected"], 1)
            self.assertEqual(relay.stats()["pending"], 0)
            receiver.close()
            relay.close()

    def test_relay_schema_has_no_plaintext_social_tables(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            relay = Relay(Path(temp) / "relay.db")
            names = {row[0] for row in relay._db.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()}
            self.assertFalse({"messages", "collectives", "members", "tasks"} & names)
            self.assertLessEqual({"routes", "envelopes", "relay_audit"}, names)
            relay.close()

    def test_public_route_rotates_to_pairwise_routes(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            relay = Relay(root / "relay.db")
            alpha = Gateway(root / "alpha", relay)
            beta = Gateway(root / "beta", relay)
            alpha_card = alpha.public_card()
            beta_card = beta.public_card()
            beta_old_read_token = beta.route.read_token
            alpha.remember(beta_card)
            beta.remember(alpha_card)
            collective = alpha.create_collective("Private", [beta.agent_id])
            beta.sync()
            self.assertNotEqual(beta.route.route_id, beta_card.contact_route)
            with self.assertRaises(AuthenticationError):
                relay.pull(beta_card.contact_route, read_token=beta_old_read_token)
            alpha.sync()
            self.assertIsNotNone(alpha.store.get_peer_route(beta.agent_id))
            self.assertIsNotNone(beta.store.get_peer_route(alpha.agent_id))

            before = str(alpha.store.get_peer_route(beta.agent_id)["route_id"])
            beta.rotate_relationship(alpha.agent_id)
            alpha.sync()
            after = str(alpha.store.get_peer_route(beta.agent_id)["route_id"])
            self.assertNotEqual(before, after)
            alpha.post_message(collective, "after rotation", recipients=[beta.agent_id])
            beta.sync()
            self.assertEqual(beta.messages()[-1]["text"], "after rotation")
            alpha.close()
            beta.close()
            relay.close()

    def test_outbox_survives_failure_and_gateway_restart(self) -> None:
        class FlakyRelay:
            def __init__(self, inner):
                self.inner = inner
                self.fail_push = False

            def __getattr__(self, name):
                return getattr(self.inner, name)

            def push(self, envelope, *, write_token):
                if self.fail_push:
                    raise ConnectionError("simulated outage")
                return self.inner.push(envelope, write_token=write_token)

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            relay = Relay(root / "relay.db")
            flaky = FlakyRelay(relay)
            alpha = Gateway(root / "alpha", flaky)
            beta = Gateway(root / "beta", relay)
            alpha.remember(beta.public_card())
            beta.remember(alpha.public_card())
            collective = alpha.create_collective("Durable", [beta.agent_id])
            beta.sync()
            alpha.sync()

            flaky.fail_push = True
            alpha.post_message(
                collective, "survive the outage", recipients=[beta.agent_id],
                idempotency_key="durable-1"
            )
            self.assertEqual(alpha.store.outbox_counts().get("pending"), 1)
            alpha.close()

            restarted = Gateway(root / "alpha", relay)
            restarted.sync()
            self.assertEqual(restarted.store.outbox_counts().get("sent"), 2)
            beta.sync()
            self.assertEqual(beta.messages()[-1]["text"], "survive the outage")
            restarted.close()
            beta.close()
            relay.close()

    def test_direct_relationships_form_a_collective_delivery_mesh(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            relay = Relay(root / "relay.db")
            alpha = Gateway(root / "alpha", relay)
            beta = Gateway(root / "beta", relay)
            gamma = Gateway(root / "gamma", relay)
            gateways = [alpha, beta, gamma]
            cards = {gateway.agent_id: gateway.public_card() for gateway in gateways}
            for gateway in gateways:
                for agent_id, card in cards.items():
                    if agent_id != gateway.agent_id:
                        gateway.remember(card)

            alpha.connect(beta.agent_id)
            alpha.connect(gamma.agent_id)
            beta.connect(gamma.agent_id)
            beta.sync()
            gamma.sync()
            alpha.sync()
            beta.sync()
            for sender in gateways:
                for recipient in gateways:
                    if sender is not recipient:
                        self.assertIsNotNone(sender.store.get_peer_route(recipient.agent_id))

            collective = alpha.create_collective(
                "Mesh", [beta.agent_id, gamma.agent_id]
            )
            beta.sync()
            gamma.sync()
            alpha.sync()
            beta.post_message(
                collective, "member-to-all",
                recipients=[alpha.agent_id, gamma.agent_id],
                idempotency_key="mesh-message",
            )
            alpha.sync()
            gamma.sync()
            self.assertEqual(alpha.messages()[-1]["text"], "member-to-all")
            self.assertEqual(gamma.messages()[-1]["text"], "member-to-all")
            for gateway in gateways:
                gateway.close()
            relay.close()


if __name__ == "__main__":
    unittest.main()
