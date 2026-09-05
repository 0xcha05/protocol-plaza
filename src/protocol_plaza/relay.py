"""Content-blind SQLite relay.

The relay authenticates opaque route access, stores ciphertext, handles
idempotency, and acknowledges delivery. It never receives collective keys.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .codec import canonical_json, parse_json
from .errors import AuthenticationError, AuthorizationError, ProtocolError
from .models import PublicCard, RelayEnvelope, now_ms, random_id


def _token_hash(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()


def _check_token(candidate: str, expected: bytes) -> bool:
    return hmac.compare_digest(_token_hash(candidate), expected)


@dataclass(frozen=True)
class RouteCredentials:
    route_id: str
    write_token: str
    read_token: str


@dataclass(frozen=True)
class ServiceCredential:
    principal_id: str
    access_token: str
    proof_private_key: str


class Relay:
    """A tiny relay with a production-shaped privacy boundary."""

    def __init__(self, path: str | Path):
        self.path = str(path)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA foreign_keys=ON")
        self._create_schema()

    def _create_schema(self) -> None:
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS routes (
                route_id TEXT PRIMARY KEY,
                principal_id TEXT,
                write_token_hash BLOB NOT NULL,
                read_token_hash BLOB NOT NULL,
                created_at_ms INTEGER NOT NULL,
                expires_at_ms INTEGER,
                revoked_at_ms INTEGER
            );
            CREATE TABLE IF NOT EXISTS principals (
                principal_id TEXT PRIMARY KEY,
                label TEXT NOT NULL,
                access_token_hash BLOB NOT NULL UNIQUE,
                route_limit INTEGER NOT NULL,
                daily_byte_limit INTEGER NOT NULL,
                created_at_ms INTEGER NOT NULL,
                revoked_at_ms INTEGER,
                proof_public_key BLOB
            );
            CREATE TABLE IF NOT EXISTS service_nonces (
                principal_id TEXT NOT NULL REFERENCES principals(principal_id),
                nonce TEXT NOT NULL,
                used_at_ms INTEGER NOT NULL,
                PRIMARY KEY (principal_id, nonce)
            );
            CREATE TABLE IF NOT EXISTS usage_daily (
                principal_id TEXT NOT NULL REFERENCES principals(principal_id),
                day TEXT NOT NULL,
                bytes INTEGER NOT NULL DEFAULT 0,
                envelopes INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (principal_id, day)
            );
            CREATE TABLE IF NOT EXISTS public_cards (
                agent_id TEXT PRIMARY KEY,
                principal_id TEXT NOT NULL REFERENCES principals(principal_id),
                card_json BLOB NOT NULL,
                description TEXT NOT NULL,
                capabilities_json BLOB NOT NULL,
                expires_at_ms INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS blobs (
                blob_id TEXT PRIMARY KEY,
                principal_id TEXT NOT NULL REFERENCES principals(principal_id),
                ciphertext BLOB NOT NULL,
                byte_size INTEGER NOT NULL,
                created_at_ms INTEGER NOT NULL,
                expires_at_ms INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_public_cards_expiry
                ON public_cards(expires_at_ms);
            CREATE TABLE IF NOT EXISTS envelopes (
                envelope_id TEXT PRIMARY KEY,
                route_id TEXT NOT NULL REFERENCES routes(route_id),
                envelope_json BLOB NOT NULL,
                byte_size INTEGER NOT NULL,
                created_at_ms INTEGER NOT NULL,
                expires_at_ms INTEGER NOT NULL,
                acked_at_ms INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_envelopes_pickup
                ON envelopes(route_id, acked_at_ms, created_at_ms);
            CREATE TABLE IF NOT EXISTS relay_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                occurred_at_ms INTEGER NOT NULL,
                operation TEXT NOT NULL,
                route_id TEXT,
                envelope_id TEXT,
                byte_size INTEGER,
                outcome TEXT NOT NULL
            );
            """
        )
        columns = {row[1] for row in self._db.execute("PRAGMA table_info(routes)")}
        if "principal_id" not in columns:
            self._db.execute("ALTER TABLE routes ADD COLUMN principal_id TEXT")
        if "revoked_at_ms" not in columns:
            self._db.execute("ALTER TABLE routes ADD COLUMN revoked_at_ms INTEGER")
        principal_columns = {
            row[1] for row in self._db.execute("PRAGMA table_info(principals)")
        }
        if "proof_public_key" not in principal_columns:
            self._db.execute("ALTER TABLE principals ADD COLUMN proof_public_key BLOB")
        self._db.commit()

    def close(self) -> None:
        self._db.close()

    def issue_service_credential(
        self,
        label: str,
        *,
        route_limit: int = 1_000,
        daily_byte_limit: int = 1_000_000_000,
        proof_public_key: bytes,
        proof_private_key: str = "",
    ) -> ServiceCredential:
        if not label.strip() or route_limit < 1 or daily_byte_limit < 1:
            raise ProtocolError("invalid service credential limits")
        credential = ServiceCredential(
            principal_id=random_id("principal"),
            access_token=secrets.token_urlsafe(32),
            proof_private_key=proof_private_key,
        )
        with self._lock, self._db:
            self._db.execute(
                """INSERT INTO principals
                   (principal_id, label, access_token_hash, route_limit,
                    daily_byte_limit, created_at_ms, revoked_at_ms, proof_public_key)
                   VALUES (?, ?, ?, ?, ?, ?, NULL, ?)""",
                (
                    credential.principal_id, label.strip(),
                    _token_hash(credential.access_token), route_limit,
                    daily_byte_limit, now_ms(), proof_public_key,
                ),
            )
            self._audit(
                "principal.issue", None, None, None,
                f"accepted:{credential.principal_id}"
            )
        return credential

    def authenticate_service(self, access_token: str) -> str:
        token_hash = _token_hash(access_token)
        rows = self._db.execute(
            """SELECT principal_id, access_token_hash FROM principals
               WHERE revoked_at_ms IS NULL"""
        ).fetchall()
        for row in rows:
            if hmac.compare_digest(token_hash, bytes(row["access_token_hash"])):
                return str(row["principal_id"])
        raise AuthenticationError("invalid service credential")

    def verify_service_proof(
        self, principal_id: str, *, method: str, path: str,
        timestamp_ms: int, nonce: str, signature: bytes
    ) -> None:
        if abs(now_ms() - timestamp_ms) > 5 * 60_000:
            raise AuthenticationError("service proof timestamp is outside allowed skew")
        if len(nonce) < 16 or len(nonce) > 200:
            raise AuthenticationError("invalid service proof nonce")
        principal = self._principal(principal_id)
        public_bytes = principal["proof_public_key"]
        if public_bytes is None:
            raise AuthenticationError("service credential has no proof key")
        message = canonical_json({
            "method": method.upper(), "path": path,
            "timestamp_ms": timestamp_ms, "nonce": nonce,
        })
        try:
            Ed25519PublicKey.from_public_bytes(bytes(public_bytes)).verify(
                signature, message
            )
        except (InvalidSignature, ValueError) as exc:
            raise AuthenticationError("invalid service proof signature") from exc
        with self._lock, self._db:
            self._db.execute(
                "DELETE FROM service_nonces WHERE used_at_ms < ?",
                (now_ms() - 10 * 60_000,),
            )
            try:
                self._db.execute(
                    """INSERT INTO service_nonces(principal_id, nonce, used_at_ms)
                       VALUES (?, ?, ?)""",
                    (principal_id, nonce, now_ms()),
                )
            except sqlite3.IntegrityError as exc:
                raise AuthenticationError("replayed service proof") from exc

    def revoke_service_credential(self, principal_id: str) -> None:
        with self._lock, self._db:
            cursor = self._db.execute(
                """UPDATE principals SET revoked_at_ms = ?
                   WHERE principal_id = ? AND revoked_at_ms IS NULL""",
                (now_ms(), principal_id),
            )
            if cursor.rowcount != 1:
                raise AuthenticationError("unknown or revoked principal")

    def create_route(
        self, *, ttl_ms: int | None = None, principal_id: str | None = None
    ) -> RouteCredentials:
        if ttl_ms is not None and ttl_ms <= 0:
            raise ProtocolError("route ttl must be positive")
        created = now_ms()
        credentials = RouteCredentials(
            route_id=random_id("route"),
            write_token=secrets.token_urlsafe(32),
            read_token=secrets.token_urlsafe(32),
        )
        expires = created + ttl_ms if ttl_ms is not None else None
        with self._lock, self._db:
            if principal_id is not None:
                principal = self._principal(principal_id)
                count = self._db.execute(
                    """SELECT COUNT(*) FROM routes
                       WHERE principal_id = ? AND revoked_at_ms IS NULL
                         AND (expires_at_ms IS NULL OR expires_at_ms > ?)""",
                    (principal_id, created),
                ).fetchone()[0]
                if int(count) >= int(principal["route_limit"]):
                    raise AuthorizationError("route quota exceeded")
            self._db.execute(
                """INSERT INTO routes
                   (route_id, principal_id, write_token_hash, read_token_hash,
                    created_at_ms, expires_at_ms, revoked_at_ms)
                   VALUES (?, ?, ?, ?, ?, ?, NULL)""",
                (
                    credentials.route_id, principal_id,
                    _token_hash(credentials.write_token),
                    _token_hash(credentials.read_token),
                    created,
                    expires,
                ),
            )
            self._audit("route.create", credentials.route_id, None, None, "accepted")
        return credentials

    def assert_route_owner(self, route_id: str, principal_id: str) -> None:
        row = self._route(route_id)
        if row["principal_id"] != principal_id:
            raise AuthenticationError("route does not belong to service principal")

    def charge(self, principal_id: str, *, byte_count: int, envelopes: int = 0) -> None:
        if byte_count < 0 or envelopes < 0:
            raise ProtocolError("usage increments cannot be negative")
        day = datetime.now(UTC).date().isoformat()
        with self._lock, self._db:
            principal = self._principal(principal_id)
            row = self._db.execute(
                "SELECT bytes FROM usage_daily WHERE principal_id = ? AND day = ?",
                (principal_id, day),
            ).fetchone()
            used = 0 if row is None else int(row["bytes"])
            if used + byte_count > int(principal["daily_byte_limit"]):
                raise AuthorizationError("daily byte quota exceeded")
            self._db.execute(
                """INSERT INTO usage_daily(principal_id, day, bytes, envelopes)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(principal_id, day) DO UPDATE SET
                     bytes = bytes + excluded.bytes,
                     envelopes = envelopes + excluded.envelopes""",
                (principal_id, day, byte_count, envelopes),
            )

    def usage(self, principal_id: str) -> dict[str, int]:
        day = datetime.now(UTC).date().isoformat()
        row = self._db.execute(
            """SELECT bytes, envelopes FROM usage_daily
               WHERE principal_id = ? AND day = ?""",
            (principal_id, day),
        ).fetchone()
        return {
            "bytes": 0 if row is None else int(row["bytes"]),
            "envelopes": 0 if row is None else int(row["envelopes"]),
        }

    def publish_public_card(self, principal_id: str, card: PublicCard) -> None:
        self._principal(principal_id)
        card.verify()
        if card.expires_at_ms <= now_ms():
            raise ProtocolError("cannot publish an expired card")
        self.assert_route_owner(card.contact_route, principal_id)
        with self._lock, self._db:
            existing = self._db.execute(
                "SELECT principal_id FROM public_cards WHERE agent_id = ?",
                (card.identity.agent_id,),
            ).fetchone()
            if existing is not None and existing["principal_id"] != principal_id:
                raise AuthorizationError("agent card is owned by another principal")
            self._db.execute(
                """INSERT INTO public_cards
                   (agent_id, principal_id, card_json, description,
                    capabilities_json, expires_at_ms, updated_at_ms)
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(agent_id) DO UPDATE SET
                     card_json = excluded.card_json,
                     description = excluded.description,
                     capabilities_json = excluded.capabilities_json,
                     expires_at_ms = excluded.expires_at_ms,
                     updated_at_ms = excluded.updated_at_ms""",
                (
                    card.identity.agent_id, principal_id,
                    canonical_json(card.to_dict()), card.description,
                    canonical_json(list(card.capabilities)),
                    card.expires_at_ms, now_ms(),
                ),
            )
            self._audit(
                "directory.publish", card.contact_route, None,
                len(canonical_json(card.to_dict())), "accepted"
            )

    def resolve_public_card(self, agent_id: str) -> PublicCard | None:
        row = self._db.execute(
            """SELECT card_json FROM public_cards
               WHERE agent_id = ? AND expires_at_ms > ?""",
            (agent_id, now_ms()),
        ).fetchone()
        if row is None:
            return None
        card = PublicCard.from_dict(parse_json(bytes(row["card_json"])))
        card.verify()
        return card

    def search_public_cards(
        self, query: str = "", capabilities: tuple[str, ...] = (), *, limit: int = 20
    ) -> list[PublicCard]:
        if limit < 1 or limit > 100:
            raise ProtocolError("directory limit must be between 1 and 100")
        rows = self._db.execute(
            """SELECT card_json, description, capabilities_json FROM public_cards
               WHERE expires_at_ms > ? ORDER BY updated_at_ms DESC LIMIT 500""",
            (now_ms(),),
        ).fetchall()
        needle = query.casefold().strip()
        required = set(capabilities)
        results: list[PublicCard] = []
        for row in rows:
            offered = set(parse_json(bytes(row["capabilities_json"])))
            description = str(row["description"])
            if required <= offered and (not needle or needle in description.casefold()):
                card = PublicCard.from_dict(parse_json(bytes(row["card_json"])))
                card.verify()
                results.append(card)
                if len(results) >= limit:
                    break
        return results

    def put_blob(
        self, principal_id: str, blob_id: str, ciphertext: bytes,
        *, ttl_ms: int | None = 30 * 86_400_000
    ) -> bool:
        self._principal(principal_id)
        if not ciphertext or len(ciphertext) > 64 * 1024 * 1024:
            raise ProtocolError("blob must be between 1 byte and 64 MiB")
        if hashlib.sha256(ciphertext).hexdigest() != blob_id:
            raise ProtocolError("blob id must be the ciphertext SHA-256")
        expires = None if ttl_ms is None else now_ms() + ttl_ms
        with self._lock, self._db:
            existing = self._db.execute(
                "SELECT ciphertext FROM blobs WHERE blob_id = ?", (blob_id,)
            ).fetchone()
            if existing is not None:
                if not hmac.compare_digest(bytes(existing["ciphertext"]), ciphertext):
                    raise ProtocolError("blob id collision")
                return False
            self.charge(principal_id, byte_count=len(ciphertext), envelopes=0)
            self._db.execute(
                """INSERT INTO blobs
                   (blob_id, principal_id, ciphertext, byte_size, created_at_ms, expires_at_ms)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (blob_id, principal_id, ciphertext, len(ciphertext), now_ms(), expires),
            )
        return True

    def get_blob(self, principal_id: str, blob_id: str) -> bytes:
        self._principal(principal_id)
        row = self._db.execute(
            """SELECT ciphertext FROM blobs WHERE blob_id = ?
               AND (expires_at_ms IS NULL OR expires_at_ms > ?)""",
            (blob_id, now_ms()),
        ).fetchone()
        if row is None:
            raise ProtocolError("unknown or expired blob")
        ciphertext = bytes(row["ciphertext"])
        self.charge(principal_id, byte_count=len(ciphertext), envelopes=0)
        return ciphertext

    def delete_blob(self, principal_id: str, blob_id: str) -> None:
        with self._lock, self._db:
            cursor = self._db.execute(
                "DELETE FROM blobs WHERE blob_id = ? AND principal_id = ?",
                (blob_id, principal_id),
            )
            if cursor.rowcount != 1:
                raise AuthorizationError("blob not found or not owned by principal")

    def _principal(self, principal_id: str) -> sqlite3.Row:
        row = self._db.execute(
            """SELECT * FROM principals
               WHERE principal_id = ? AND revoked_at_ms IS NULL""",
            (principal_id,),
        ).fetchone()
        if row is None:
            raise AuthenticationError("unknown or revoked principal")
        return row

    def revoke_route(self, route_id: str, *, read_token: str) -> None:
        with self._lock, self._db:
            row = self._route(route_id)
            self._authorize(row, read_token, "read_token_hash")
            self._db.execute(
                "UPDATE routes SET revoked_at_ms = ? WHERE route_id = ?",
                (now_ms(), route_id),
            )
            self._audit("route.revoke", route_id, None, None, "accepted")

    def push(self, envelope: RelayEnvelope, *, write_token: str) -> bool:
        if (
            envelope.route_id == ""
            or envelope.aad != envelope.envelope_id
            or envelope.kind != "opaque/v1"
            or set(envelope.payload) != {"ephemeral_key", "nonce", "ciphertext"}
            or envelope.expires_at_ms <= now_ms()
        ):
            raise ProtocolError("invalid or expired envelope")
        encoded = canonical_json(envelope.to_dict())
        if len(encoded) > 1024 * 1024:
            raise ProtocolError("envelope exceeds one MiB")
        with self._lock, self._db:
            row = self._route(envelope.route_id)
            self._authorize(row, write_token, "write_token_hash")
            existing = self._db.execute(
                "SELECT envelope_json FROM envelopes WHERE envelope_id = ?",
                (envelope.envelope_id,),
            ).fetchone()
            if existing is not None:
                if not hmac.compare_digest(bytes(existing["envelope_json"]), encoded):
                    raise ProtocolError("envelope id reused with different bytes")
                self._audit(
                    "mailbox.push", envelope.route_id, envelope.envelope_id,
                    len(encoded), "duplicate"
                )
                return False
            self._db.execute(
                """INSERT INTO envelopes
                   (envelope_id, route_id, envelope_json, byte_size,
                    created_at_ms, expires_at_ms, acked_at_ms)
                   VALUES (?, ?, ?, ?, ?, ?, NULL)""",
                (
                    envelope.envelope_id,
                    envelope.route_id,
                    encoded,
                    len(encoded),
                    envelope.created_at_ms,
                    envelope.expires_at_ms,
                ),
            )
            self._audit(
                "mailbox.push", envelope.route_id, envelope.envelope_id,
                len(encoded), "accepted"
            )
        return True

    def pull(
        self, route_id: str, *, read_token: str, limit: int = 100
    ) -> list[RelayEnvelope]:
        if limit < 1 or limit > 1_000:
            raise ProtocolError("limit must be between 1 and 1000")
        with self._lock, self._db:
            row = self._route(route_id)
            self._authorize(row, read_token, "read_token_hash")
            rows = self._db.execute(
                """SELECT envelope_json FROM envelopes
                   WHERE route_id = ? AND acked_at_ms IS NULL AND expires_at_ms > ?
                   ORDER BY created_at_ms, envelope_id LIMIT ?""",
                (route_id, now_ms(), limit),
            ).fetchall()
            self._audit("mailbox.pull", route_id, None, None, f"returned:{len(rows)}")
        return [RelayEnvelope.from_dict(parse_json(bytes(r["envelope_json"]))) for r in rows]

    def acknowledge(
        self, route_id: str, envelope_ids: list[str], *, read_token: str
    ) -> int:
        with self._lock, self._db:
            row = self._route(route_id)
            self._authorize(row, read_token, "read_token_hash")
            count = 0
            for envelope_id in envelope_ids:
                cursor = self._db.execute(
                    """UPDATE envelopes SET acked_at_ms = COALESCE(acked_at_ms, ?)
                       WHERE route_id = ? AND envelope_id = ? AND acked_at_ms IS NULL""",
                    (now_ms(), route_id, envelope_id),
                )
                count += cursor.rowcount
                self._audit(
                    "mailbox.ack", route_id, envelope_id, None,
                    "accepted" if cursor.rowcount else "unknown_or_duplicate"
                )
        return count

    def stats(self) -> dict[str, int]:
        row = self._db.execute(
            """SELECT COUNT(*) AS envelopes,
                      COALESCE(SUM(byte_size), 0) AS bytes,
                      SUM(CASE WHEN acked_at_ms IS NULL THEN 1 ELSE 0 END) AS pending
               FROM envelopes"""
        ).fetchone()
        routes = self._db.execute("SELECT COUNT(*) FROM routes").fetchone()[0]
        return {
            "routes": int(routes),
            "envelopes": int(row["envelopes"]),
            "bytes": int(row["bytes"]),
            "pending": int(row["pending"] or 0),
        }

    def raw_ciphertext_contains(self, needle: bytes) -> bool:
        """Test/diagnostic helper proving no serialized relay envelope contains text."""
        rows = self._db.execute("SELECT envelope_json FROM envelopes").fetchall()
        return any(needle in bytes(row["envelope_json"]) for row in rows)

    def _route(self, route_id: str) -> sqlite3.Row:
        row = self._db.execute(
            "SELECT * FROM routes WHERE route_id = ?", (route_id,)
        ).fetchone()
        if row is None:
            raise AuthenticationError("unknown route")
        if row["revoked_at_ms"] is not None:
            raise AuthenticationError("revoked route")
        if row["expires_at_ms"] is not None and int(row["expires_at_ms"]) <= now_ms():
            raise AuthenticationError("expired route")
        return row

    @staticmethod
    def _authorize(row: sqlite3.Row, token: str, field: str) -> None:
        if not _check_token(token, bytes(row[field])):
            raise AuthenticationError("invalid route credential")

    def _audit(
        self,
        operation: str,
        route_id: str | None,
        envelope_id: str | None,
        byte_size: int | None,
        outcome: str,
    ) -> None:
        self._db.execute(
            """INSERT INTO relay_audit
               (occurred_at_ms, operation, route_id, envelope_id, byte_size, outcome)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (now_ms(), operation, route_id, envelope_id, byte_size, outcome),
        )
