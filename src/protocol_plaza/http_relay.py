"""Minimal authenticated HTTP boundary for the content-blind relay."""

from __future__ import annotations

import json
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import AbstractContextManager
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .codec import b64, canonical_json, unb64
from .discovery import RelayManifest, RelaySigningIdentity
from .errors import AuthenticationError, ProtocolError, ProtocolPlazaError
from .models import PublicCard, RelayEnvelope
from .relay import Relay, RouteCredentials, ServiceCredential

MAX_HTTP_BODY = 2 * 1024 * 1024


def _bearer(handler: BaseHTTPRequestHandler) -> str:
    value = handler.headers.get("Authorization", "")
    prefix = "Bearer "
    if not value.startswith(prefix) or not value[len(prefix):]:
        raise AuthenticationError("missing bearer route credential")
    return value[len(prefix):]


class RelayRequestHandler(BaseHTTPRequestHandler):
    server_version = "ProtocolPlazaRelay/0.6"

    @property
    def relay(self) -> Relay:
        return self.server.relay  # type: ignore[attr-defined]

    def log_message(self, format: str, *args: object) -> None:
        return

    def _json_body(self) -> dict[str, Any]:
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            raise ProtocolError("content length required")
        try:
            length = int(raw_length)
        except ValueError as exc:
            raise ProtocolError("invalid content length") from exc
        if length < 0 or length > MAX_HTTP_BODY:
            raise ProtocolError("request body exceeds limit")
        try:
            value = json.loads(self.rfile.read(length))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProtocolError("invalid JSON body") from exc
        if not isinstance(value, dict):
            raise ProtocolError("JSON body must be an object")
        return value

    def _service_principal(self) -> str:
        token = self.headers.get("X-Service-Token", "")
        if not token:
            raise AuthenticationError("missing service credential")
        principal_id = self.relay.authenticate_service(token)
        try:
            timestamp_ms = int(self.headers["X-Service-Proof-Time"])
            nonce = self.headers["X-Service-Proof-Nonce"]
            signature = unb64(self.headers["X-Service-Proof"])
        except (KeyError, TypeError, ValueError) as exc:
            raise AuthenticationError("missing or malformed service proof") from exc
        self.relay.verify_service_proof(
            principal_id, method=self.command, path=self.path,
            timestamp_ms=timestamp_ms, nonce=nonce, signature=signature,
        )
        return principal_id

    def _send(
        self, status: HTTPStatus, value: dict[str, Any],
        *, cache_control: str = "no-store"
    ) -> None:
        encoded = canonical_json(value)
        self.send_response(status.value)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", cache_control)
        self.end_headers()
        self.wfile.write(encoded)

    def _dispatch(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        parts = [part for part in parsed.path.split("/") if part]
        if self.command == "GET" and parts == [".well-known", "protocol-plaza"]:
            manifest = self.server.discovery_identity.manifest()  # type: ignore[attr-defined]
            self._send(
                HTTPStatus.OK, manifest.to_dict(),
                cache_control="public, max-age=300",
            )
            return
        if self.command == "GET" and parts == ["v1", "health"]:
            self._send(HTTPStatus.OK, {"status": "ok", "protocol": 1})
            return
        if self.command == "POST" and parts == ["v1", "principals"]:
            supplied = self.headers.get("X-Bootstrap-Token", "")
            expected = self.server.bootstrap_token  # type: ignore[attr-defined]
            if not secrets.compare_digest(supplied, expected):
                raise AuthenticationError("invalid bootstrap credential")
            body = self._json_body()
            credential = self.relay.issue_service_credential(
                str(body.get("label", "gateway")),
                route_limit=int(body.get("route_limit", 1_000)),
                daily_byte_limit=int(body.get("daily_byte_limit", 1_000_000_000)),
                proof_public_key=unb64(body["proof_public_key"]),
            )
            self._send(HTTPStatus.CREATED, {
                "principal_id": credential.principal_id,
                "access_token": credential.access_token,
            })
            return
        if self.command == "POST" and parts == ["v1", "routes"]:
            principal_id = self._service_principal()
            body = self._json_body()
            ttl = body.get("ttl_ms")
            route = self.relay.create_route(
                ttl_ms=None if ttl is None else int(ttl), principal_id=principal_id
            )
            self._send(HTTPStatus.CREATED, {
                "route_id": route.route_id,
                "write_token": route.write_token,
                "read_token": route.read_token,
            })
            return
        if self.command == "POST" and parts == ["v1", "directory", "cards"]:
            principal_id = self._service_principal()
            card = PublicCard.from_dict(self._json_body()["card"])
            self.relay.publish_public_card(principal_id, card)
            self._send(HTTPStatus.OK, {"status": "published"})
            return
        if self.command == "GET" and len(parts) == 4 and parts[:3] == ["v1", "directory", "cards"]:
            card = self.relay.resolve_public_card(urllib.parse.unquote(parts[3]))
            if card is None:
                self._send(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            else:
                self._send(HTTPStatus.OK, {"card": card.to_dict()})
            return
        if self.command == "GET" and parts == ["v1", "directory", "search"]:
            query = urllib.parse.parse_qs(parsed.query)
            text_query = query.get("q", [""])[0]
            capabilities = tuple(query.get("capability", []))
            limit = int(query.get("limit", ["20"])[0])
            cards = self.relay.search_public_cards(
                text_query, capabilities, limit=limit
            )
            self._send(HTTPStatus.OK, {"cards": [card.to_dict() for card in cards]})
            return
        if len(parts) == 3 and parts[:2] == ["v1", "blobs"]:
            principal_id = self._service_principal()
            blob_id = parts[2]
            if self.command == "POST":
                body = self._json_body()
                inserted = self.relay.put_blob(
                    principal_id, blob_id, unb64(body["ciphertext"]),
                    ttl_ms=body.get("ttl_ms", 30 * 86_400_000),
                )
                self._send(HTTPStatus.OK, {"status": "accepted", "inserted": inserted})
                return
            if self.command == "GET":
                ciphertext = self.relay.get_blob(principal_id, blob_id)
                self._send(HTTPStatus.OK, {"ciphertext": b64(ciphertext)})
                return
            if self.command == "DELETE":
                self.relay.delete_blob(principal_id, blob_id)
                self._send(HTTPStatus.OK, {"status": "deleted"})
                return
        if len(parts) == 4 and parts[:2] == ["v1", "routes"]:
            route_id, operation = parts[2], parts[3]
            principal_id = self._service_principal()
            token = _bearer(self)
            if self.command == "POST" and operation == "envelopes":
                envelope = RelayEnvelope.from_dict(self._json_body()["envelope"])
                if envelope.route_id != route_id:
                    raise ProtocolError("path and envelope routes differ")
                self.relay.charge(
                    principal_id,
                    byte_count=len(canonical_json(envelope.to_dict())),
                    envelopes=1,
                )
                inserted = self.relay.push(envelope, write_token=token)
                self._send(HTTPStatus.OK, {"status": "accepted", "inserted": inserted})
                return
            self.relay.assert_route_owner(route_id, principal_id)
            if self.command == "GET" and operation == "envelopes":
                query = urllib.parse.parse_qs(parsed.query)
                limit = int(query.get("limit", ["100"])[0])
                envelopes = self.relay.pull(route_id, read_token=token, limit=limit)
                self._send(HTTPStatus.OK, {
                    "envelopes": [item.to_dict() for item in envelopes]
                })
                return
            if self.command == "POST" and operation == "acks":
                body = self._json_body()
                ids = body.get("envelope_ids")
                if not isinstance(ids, list) or not all(isinstance(v, str) for v in ids):
                    raise ProtocolError("envelope_ids must be a list of strings")
                count = self.relay.acknowledge(route_id, ids, read_token=token)
                self._send(HTTPStatus.OK, {"acknowledged": count})
                return
            if self.command == "POST" and operation == "revoke":
                self._json_body()
                self.relay.revoke_route(route_id, read_token=token)
                self._send(HTTPStatus.OK, {"status": "revoked"})
                return
        self._send(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def do_GET(self) -> None:
        self._handle()

    def do_POST(self) -> None:
        self._handle()

    def do_DELETE(self) -> None:
        self._handle()

    def _handle(self) -> None:
        try:
            self._dispatch()
        except AuthenticationError as exc:
            self._send(HTTPStatus.UNAUTHORIZED, {"error": "authentication", "detail": str(exc)})
        except (ProtocolPlazaError, KeyError, TypeError, ValueError) as exc:
            self._send(HTTPStatus.BAD_REQUEST, {"error": "protocol", "detail": str(exc)})
        except Exception:
            self._send(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal"})


class RelayHttpServer(AbstractContextManager["RelayHttpServer"]):
    def __init__(
        self, relay: Relay, host: str = "127.0.0.1", port: int = 0,
        *, bootstrap_token: str | None = None,
        discovery_identity_path: str | Path | None = None,
    ):
        server_class = type("BoundRelayServer", (ThreadingHTTPServer,), {})
        self._server = server_class((host, port), RelayRequestHandler)
        self._server.relay = relay  # type: ignore[attr-defined]
        self._server.bootstrap_token = bootstrap_token or secrets.token_urlsafe(32)  # type: ignore[attr-defined]
        identity_path = (
            Path(discovery_identity_path)
            if discovery_identity_path is not None
            else Path(relay.path + ".identity.json")
        )
        self._server.discovery_identity = RelaySigningIdentity.load_or_create(  # type: ignore[attr-defined]
            identity_path
        )
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    @property
    def bootstrap_token(self) -> str:
        return self._server.bootstrap_token  # type: ignore[attr-defined]

    @property
    def discovery_manifest(self) -> RelayManifest:
        return self._server.discovery_identity.manifest()  # type: ignore[attr-defined]

    def start(self) -> RelayHttpServer:
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="plaza-relay", daemon=True
        )
        self._thread.start()
        return self

    def serve_forever(self) -> None:
        self._server.serve_forever()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def __enter__(self) -> RelayHttpServer:
        return self.start()

    def __exit__(self, *exc_info: object) -> None:
        self.close()


class HttpRelayClient:
    def __init__(
        self, base_url: str, *, credential: ServiceCredential | None = None,
        timeout: float = 5.0
    ):
        self.base_url = base_url.rstrip("/")
        self.credential = credential
        self.timeout = timeout

    @classmethod
    def register(
        cls, base_url: str, bootstrap_token: str, label: str,
        *, route_limit: int = 1_000, daily_byte_limit: int = 1_000_000_000
    ) -> HttpRelayClient:
        client = cls(base_url)
        proof_key = Ed25519PrivateKey.generate()
        proof_private = proof_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        proof_public = proof_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        value = client._request(
            "POST", "/v1/principals",
            {
                "label": label,
                "route_limit": route_limit,
                "daily_byte_limit": daily_byte_limit,
                "proof_public_key": b64(proof_public),
            },
            extra_headers={"X-Bootstrap-Token": bootstrap_token},
        )
        return cls(
            base_url,
            credential=ServiceCredential(
                value["principal_id"], value["access_token"], b64(proof_private)
            ),
        )

    def _request(
        self, method: str, path: str, body: dict[str, Any] | None = None,
        token: str | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        headers = {"Accept": "application/json"}
        if extra_headers:
            headers.update(extra_headers)
        data = None
        if body is not None:
            data = canonical_json(body)
            headers["Content-Type"] = "application/json"
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        if self.credential is not None:
            headers["X-Service-Token"] = self.credential.access_token
            timestamp_ms = time.time_ns() // 1_000_000
            nonce = secrets.token_urlsafe(18)
            proof_message = canonical_json({
                "method": method.upper(), "path": path,
                "timestamp_ms": timestamp_ms, "nonce": nonce,
            })
            proof_key = Ed25519PrivateKey.from_private_bytes(
                unb64(self.credential.proof_private_key)
            )
            headers["X-Service-Proof-Time"] = str(timestamp_ms)
            headers["X-Service-Proof-Nonce"] = nonce
            headers["X-Service-Proof"] = b64(proof_key.sign(proof_message))
        request = urllib.request.Request(
            f"{self.base_url}{path}", data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                value = json.loads(response.read())
        except urllib.error.HTTPError as exc:
            try:
                detail = json.loads(exc.read()).get("detail", exc.reason)
            except Exception:
                detail = exc.reason
            if exc.code == HTTPStatus.UNAUTHORIZED:
                raise AuthenticationError(str(detail)) from exc
            raise ProtocolError(f"relay HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ConnectionError(f"relay unavailable: {exc}") from exc
        if not isinstance(value, dict):
            raise ProtocolError("relay returned a non-object response")
        return value

    def discover_relay(
        self, *, expected_signing_key: str | None = None
    ) -> RelayManifest:
        """Fetch and verify the relay's first-party discovery manifest.

        A self-signature protects integrity. Callers that need authentication
        must provide an out-of-band pinned signing key.
        """
        value = self._request("GET", "/.well-known/protocol-plaza")
        manifest = RelayManifest.from_dict(value)
        manifest.verify(expected_signing_key=expected_signing_key)
        return manifest

    def health(self) -> dict[str, Any]:
        return self._request("GET", "/v1/health")

    def create_route(self, *, ttl_ms: int | None = None) -> RouteCredentials:
        value = self._request("POST", "/v1/routes", {"ttl_ms": ttl_ms})
        return RouteCredentials(
            route_id=value["route_id"],
            write_token=value["write_token"],
            read_token=value["read_token"],
        )

    def revoke_route(self, route_id: str, *, read_token: str) -> None:
        self._request("POST", f"/v1/routes/{route_id}/revoke", {}, read_token)

    def push(self, envelope: RelayEnvelope, *, write_token: str) -> bool:
        value = self._request(
            "POST", f"/v1/routes/{envelope.route_id}/envelopes",
            {"envelope": envelope.to_dict()}, write_token
        )
        return bool(value["inserted"])

    def pull(
        self, route_id: str, *, read_token: str, limit: int = 100
    ) -> list[RelayEnvelope]:
        value = self._request(
            "GET", f"/v1/routes/{route_id}/envelopes?limit={int(limit)}",
            token=read_token
        )
        return [RelayEnvelope.from_dict(item) for item in value["envelopes"]]

    def acknowledge(
        self, route_id: str, envelope_ids: list[str], *, read_token: str
    ) -> int:
        value = self._request(
            "POST", f"/v1/routes/{route_id}/acks",
            {"envelope_ids": envelope_ids}, read_token
        )
        return int(value["acknowledged"])

    def publish_public_card(self, card: PublicCard) -> None:
        if self.credential is None:
            raise AuthenticationError("service credential required")
        self._request("POST", "/v1/directory/cards", {"card": card.to_dict()})

    def resolve_public_card(self, agent_id: str) -> PublicCard | None:
        encoded = urllib.parse.quote(agent_id, safe="")
        try:
            value = self._request("GET", f"/v1/directory/cards/{encoded}")
        except ProtocolError as exc:
            if "404" in str(exc):
                return None
            raise
        card = PublicCard.from_dict(value["card"])
        card.verify()
        return card

    def search_public_cards(
        self, query: str = "", capabilities: tuple[str, ...] = (), *, limit: int = 20
    ) -> list[PublicCard]:
        params: list[tuple[str, str]] = [("q", query), ("limit", str(limit))]
        params.extend(("capability", capability) for capability in capabilities)
        value = self._request(
            "GET", f"/v1/directory/search?{urllib.parse.urlencode(params)}"
        )
        cards = [PublicCard.from_dict(card) for card in value["cards"]]
        for card in cards:
            card.verify()
        return cards

    def put_blob(
        self, blob_id: str, ciphertext: bytes,
        *, ttl_ms: int | None = 30 * 86_400_000
    ) -> bool:
        value = self._request(
            "POST", f"/v1/blobs/{blob_id}",
            {"ciphertext": b64(ciphertext), "ttl_ms": ttl_ms},
        )
        return bool(value["inserted"])

    def get_blob(self, blob_id: str) -> bytes:
        value = self._request("GET", f"/v1/blobs/{blob_id}")
        return unb64(value["ciphertext"])

    def delete_blob(self, blob_id: str) -> None:
        self._request("DELETE", f"/v1/blobs/{blob_id}")

    artifact_put = put_blob
    artifact_get = get_blob
    artifact_delete = delete_blob
