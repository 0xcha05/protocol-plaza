from __future__ import annotations

import heapq
import sqlite3
from pathlib import Path
from typing import Any

from .codec import canonical_json, parse_json
from .models import SignedEvent, now_ms


class GatewayStore:
    def __init__(self, path: str | Path):
        self.path = str(path)
        self.db = sqlite3.connect(self.path)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self._create_schema()

    def _create_schema(self) -> None:
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS peers (
                agent_id TEXT PRIMARY KEY,
                identity_json BLOB NOT NULL,
                contact_route TEXT NOT NULL,
                contact_write_token TEXT NOT NULL,
                learned_at_ms INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS local_routes (
                route_id TEXT PRIMARY KEY,
                write_token TEXT NOT NULL,
                read_token TEXT NOT NULL,
                purpose TEXT NOT NULL,
                peer_id TEXT,
                active INTEGER NOT NULL DEFAULT 1,
                created_at_ms INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS peer_routes (
                peer_id TEXT PRIMARY KEY,
                route_id TEXT NOT NULL,
                write_token TEXT NOT NULL,
                learned_at_ms INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS collectives (
                collective_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                epoch INTEGER NOT NULL,
                epoch_key BLOB NOT NULL,
                created_at_ms INTEGER NOT NULL,
                policy_json BLOB NOT NULL DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS members (
                collective_id TEXT NOT NULL REFERENCES collectives(collective_id),
                agent_id TEXT NOT NULL,
                identity_json BLOB NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY (collective_id, agent_id)
            );
            CREATE TABLE IF NOT EXISTS spaces (
                collective_id TEXT NOT NULL,
                space_id TEXT NOT NULL,
                name TEXT NOT NULL,
                purpose TEXT NOT NULL,
                created_event_id TEXT,
                PRIMARY KEY (collective_id, space_id)
            );
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                collective_id TEXT NOT NULL REFERENCES collectives(collective_id),
                space_id TEXT NOT NULL,
                author TEXT NOT NULL,
                author_seq INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                body_json BLOB NOT NULL,
                event_json BLOB NOT NULL,
                created_at_ms INTEGER NOT NULL,
                received_at_ms INTEGER NOT NULL,
                direction TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                UNIQUE(author, idempotency_key),
                UNIQUE(collective_id, author, author_seq)
            );
            CREATE TABLE IF NOT EXISTS event_parents (
                event_id TEXT NOT NULL REFERENCES events(event_id),
                parent_id TEXT NOT NULL,
                PRIMARY KEY (event_id, parent_id)
            );
            CREATE TABLE IF NOT EXISTS inbox (
                envelope_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                reason TEXT,
                received_at_ms INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS outbox (
                envelope_id TEXT PRIMARY KEY,
                peer_id TEXT NOT NULL,
                event_id TEXT,
                status TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL,
                route_id TEXT,
                write_token TEXT,
                envelope_json BLOB,
                attempts INTEGER NOT NULL DEFAULT 0,
                last_error TEXT
            );
            CREATE TABLE IF NOT EXISTS audit (
                audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                occurred_at_ms INTEGER NOT NULL,
                action TEXT NOT NULL,
                actor TEXT,
                object_id TEXT,
                outcome TEXT NOT NULL,
                summary TEXT NOT NULL,
                evidence_json BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS tasks (
                task_id TEXT PRIMARY KEY,
                collective_id TEXT NOT NULL,
                space_id TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                status TEXT NOT NULL,
                assignee TEXT,
                version INTEGER NOT NULL,
                updated_event_id TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS decisions (
                decision_id TEXT PRIMARY KEY,
                collective_id TEXT NOT NULL,
                space_id TEXT NOT NULL,
                question TEXT NOT NULL,
                options_json BLOB NOT NULL,
                threshold INTEGER NOT NULL,
                status TEXT NOT NULL,
                resolution TEXT,
                vote_counts_json BLOB NOT NULL,
                updated_event_id TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS commitments (
                commitment_id TEXT PRIMARY KEY,
                collective_id TEXT NOT NULL,
                space_id TEXT NOT NULL,
                description TEXT NOT NULL,
                owner TEXT NOT NULL,
                status TEXT NOT NULL,
                due_at_ms INTEGER,
                evidence_json BLOB NOT NULL,
                version INTEGER NOT NULL,
                updated_event_id TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS artifacts (
                artifact_id TEXT PRIMARY KEY,
                collective_id TEXT NOT NULL,
                space_id TEXT NOT NULL,
                name TEXT NOT NULL,
                media_type TEXT NOT NULL,
                byte_size INTEGER NOT NULL,
                plaintext_sha256 TEXT NOT NULL,
                blob_id TEXT NOT NULL,
                key_b64 TEXT NOT NULL,
                nonce_b64 TEXT NOT NULL,
                published_by TEXT NOT NULL,
                published_event_id TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS governance_proposals (
                proposal_id TEXT PRIMARY KEY,
                collective_id TEXT NOT NULL,
                operation TEXT NOT NULL,
                target TEXT NOT NULL,
                threshold INTEGER NOT NULL,
                approvals_json BLOB NOT NULL,
                status TEXT NOT NULL,
                proposed_event_id TEXT NOT NULL,
                executed_epoch INTEGER
            );
            CREATE TABLE IF NOT EXISTS documents (
                document_id TEXT PRIMARY KEY,
                collective_id TEXT NOT NULL,
                space_id TEXT NOT NULL,
                title TEXT NOT NULL,
                created_event_id TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS document_fields (
                document_id TEXT NOT NULL REFERENCES documents(document_id),
                field TEXT NOT NULL,
                value_json BLOB NOT NULL,
                winning_event_id TEXT NOT NULL,
                PRIMARY KEY (document_id, field)
            );
            CREATE TABLE IF NOT EXISTS checkpoints (
                checkpoint_id TEXT PRIMARY KEY,
                collective_id TEXT NOT NULL,
                space_id TEXT NOT NULL,
                author TEXT NOT NULL,
                summary TEXT NOT NULL,
                confidence REAL NOT NULL,
                source_events_json BLOB NOT NULL,
                event_id TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS projection_conflicts (
                event_id TEXT PRIMARY KEY,
                object_type TEXT NOT NULL,
                object_id TEXT NOT NULL,
                reason TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_collective_time
                ON events(collective_id, created_at_ms, event_id);
            CREATE INDEX IF NOT EXISTS idx_audit_time ON audit(occurred_at_ms, audit_id);
            """
        )
        outbox_columns = {
            row[1] for row in self.db.execute("PRAGMA table_info(outbox)")
        }
        migrations = {
            "route_id": "TEXT",
            "write_token": "TEXT",
            "envelope_json": "BLOB",
            "attempts": "INTEGER NOT NULL DEFAULT 0",
            "last_error": "TEXT",
        }
        for name, declaration in migrations.items():
            if name not in outbox_columns:
                self.db.execute(f"ALTER TABLE outbox ADD COLUMN {name} {declaration}")
        collective_columns = {
            row[1] for row in self.db.execute("PRAGMA table_info(collectives)")
        }
        if "policy_json" not in collective_columns:
            self.db.execute(
                "ALTER TABLE collectives ADD COLUMN policy_json BLOB NOT NULL DEFAULT '{}'"
            )
        self.db.commit()

    def close(self) -> None:
        self.db.close()

    def put_setting(self, key: str, value: Any) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO settings(key, value) VALUES (?, ?)",
            (key, canonical_json(value)),
        )
        self.db.commit()

    def get_setting(self, key: str) -> Any | None:
        row = self.db.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return None if row is None else parse_json(bytes(row["value"]))

    def add_peer(self, card: dict[str, Any]) -> None:
        identity = card["identity"]
        with self.db:
            self.db.execute(
                """INSERT OR REPLACE INTO peers
                   (agent_id, identity_json, contact_route, contact_write_token, learned_at_ms)
                   VALUES (?, ?, ?, ?, ?)""",
                (
                    identity["agent_id"], canonical_json(identity),
                    card["contact_route"], card["contact_write_token"], now_ms()
                ),
            )

    def add_local_route(
        self, route_id: str, write_token: str, read_token: str,
        *, purpose: str, peer_id: str | None
    ) -> None:
        with self.db:
            self.db.execute(
                """INSERT OR REPLACE INTO local_routes
                   (route_id, write_token, read_token, purpose, peer_id, active, created_at_ms)
                   VALUES (?, ?, ?, ?, ?, 1, ?)""",
                (route_id, write_token, read_token, purpose, peer_id, now_ms()),
            )

    def active_local_routes(self) -> list[sqlite3.Row]:
        return self.db.execute(
            "SELECT * FROM local_routes WHERE active = 1 ORDER BY created_at_ms"
        ).fetchall()

    def deactivate_local_route(self, route_id: str) -> None:
        with self.db:
            self.db.execute(
                "UPDATE local_routes SET active = 0 WHERE route_id = ?", (route_id,)
            )

    def local_route_for_peer(self, peer_id: str) -> sqlite3.Row | None:
        return self.db.execute(
            """SELECT * FROM local_routes
               WHERE peer_id = ? AND purpose = 'relationship' AND active = 1
               ORDER BY created_at_ms DESC LIMIT 1""",
            (peer_id,),
        ).fetchone()

    def set_peer_route(self, peer_id: str, route_id: str, write_token: str) -> None:
        with self.db:
            self.db.execute(
                """INSERT OR REPLACE INTO peer_routes
                   (peer_id, route_id, write_token, learned_at_ms)
                   VALUES (?, ?, ?, ?)""",
                (peer_id, route_id, write_token, now_ms()),
            )

    def get_peer_route(self, peer_id: str) -> sqlite3.Row | None:
        return self.db.execute(
            "SELECT * FROM peer_routes WHERE peer_id = ?", (peer_id,)
        ).fetchone()

    def get_peer(self, agent_id: str) -> sqlite3.Row | None:
        return self.db.execute("SELECT * FROM peers WHERE agent_id = ?", (agent_id,)).fetchone()

    def add_collective(
        self, collective_id: str, name: str, epoch: int, epoch_key: bytes,
        members: list[dict[str, str]], policy: dict[str, Any] | None = None
    ) -> None:
        with self.db:
            self.db.execute(
                """INSERT OR REPLACE INTO collectives
                   (collective_id, name, epoch, epoch_key, created_at_ms, policy_json)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    collective_id, name, epoch, epoch_key, now_ms(),
                    canonical_json(policy or {"membership_remove_threshold": 1}),
                ),
            )
            for identity in members:
                self.db.execute(
                    """INSERT OR REPLACE INTO members
                       (collective_id, agent_id, identity_json, active)
                       VALUES (?, ?, ?, 1)""",
                    (collective_id, identity["agent_id"], canonical_json(identity)),
                )
            self.db.execute(
                """INSERT OR IGNORE INTO spaces
                   (collective_id, space_id, name, purpose, created_event_id)
                   VALUES (?, 'main', 'Main', 'Default collective space', NULL)""",
                (collective_id,),
            )

    def get_collective(self, collective_id: str) -> sqlite3.Row | None:
        return self.db.execute(
            "SELECT * FROM collectives WHERE collective_id = ?", (collective_id,)
        ).fetchone()

    def list_collectives(self) -> list[sqlite3.Row]:
        return self.db.execute("SELECT * FROM collectives ORDER BY created_at_ms").fetchall()

    def collective_policy(self, collective_id: str) -> dict[str, Any]:
        row = self.get_collective(collective_id)
        if row is None:
            raise KeyError(collective_id)
        return parse_json(bytes(row["policy_json"]))

    def active_member_ids(self, collective_id: str) -> list[str]:
        return [
            str(row["agent_id"])
            for row in self.db.execute(
                """SELECT agent_id FROM members
                   WHERE collective_id = ? AND active = 1 ORDER BY agent_id""",
                (collective_id,),
            ).fetchall()
        ]

    def update_collective_epoch(
        self, collective_id: str, *, expected_epoch: int, new_epoch: int,
        epoch_key: bytes, removed_member: str
    ) -> None:
        if new_epoch != expected_epoch + 1:
            raise ValueError("new epoch must increment exactly once")
        with self.db:
            cursor = self.db.execute(
                """UPDATE collectives SET epoch = ?, epoch_key = ?
                   WHERE collective_id = ? AND epoch = ?""",
                (new_epoch, epoch_key, collective_id, expected_epoch),
            )
            if cursor.rowcount != 1:
                raise ValueError("collective epoch precondition failed")
            cursor = self.db.execute(
                """UPDATE members SET active = 0
                   WHERE collective_id = ? AND agent_id = ? AND active = 1""",
                (collective_id, removed_member),
            )
            if cursor.rowcount != 1:
                raise ValueError("removed member was not active")

    def get_member_identity(self, collective_id: str, agent_id: str) -> dict[str, str] | None:
        row = self.db.execute(
            """SELECT identity_json FROM members
               WHERE collective_id = ? AND agent_id = ? AND active = 1""",
            (collective_id, agent_id),
        ).fetchone()
        return None if row is None else parse_json(bytes(row["identity_json"]))

    def next_author_seq(self, collective_id: str, author: str) -> int:
        row = self.db.execute(
            """SELECT COALESCE(MAX(author_seq), 0) + 1 AS seq FROM events
               WHERE collective_id = ? AND author = ?""",
            (collective_id, author),
        ).fetchone()
        return int(row["seq"])

    def heads(self, collective_id: str, space_id: str) -> tuple[str, ...]:
        rows = self.db.execute(
            """SELECT e.event_id FROM events e
               WHERE e.collective_id = ? AND e.space_id = ?
                 AND NOT EXISTS (
                   SELECT 1 FROM event_parents p
                   JOIN events child ON child.event_id = p.event_id
                   WHERE p.parent_id = e.event_id
                     AND child.collective_id = e.collective_id
                     AND child.space_id = e.space_id
                 )
               ORDER BY e.event_id""",
            (collective_id, space_id),
        ).fetchall()
        return tuple(row["event_id"] for row in rows)

    def event_by_idempotency(self, author: str, key: str) -> SignedEvent | None:
        row = self.db.execute(
            "SELECT event_json FROM events WHERE author = ? AND idempotency_key = ?",
            (author, key),
        ).fetchone()
        return None if row is None else SignedEvent.from_dict(parse_json(bytes(row["event_json"])))

    def has_event(self, event_id: str) -> bool:
        return self.db.execute(
            "SELECT 1 FROM events WHERE event_id = ?", (event_id,)
        ).fetchone() is not None

    def append_event(self, event: SignedEvent, *, direction: str) -> bool:
        if self.has_event(event.event_id):
            return False
        with self.db:
            self.db.execute(
                """INSERT INTO events
                   (event_id, collective_id, space_id, author, author_seq,
                    event_type, body_json, event_json, created_at_ms, received_at_ms,
                    direction, idempotency_key)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    event.event_id, event.collective_id, event.space_id, event.author,
                    event.author_seq, event.event_type, canonical_json(event.body),
                    canonical_json(event.to_dict()), event.created_at_ms, now_ms(),
                    direction, event.idempotency_key,
                ),
            )
            for parent in event.parents:
                self.db.execute(
                    "INSERT INTO event_parents(event_id, parent_id) VALUES (?, ?)",
                    (event.event_id, parent),
                )
            self._apply_projection(event)
        return True

    def _apply_projection(self, event: SignedEvent) -> None:
        if event.event_type.startswith("task.") and "task_id" in event.body:
            self._rebuild_task(str(event.body["task_id"]))
        elif event.event_type.startswith("decision.") and "decision_id" in event.body:
            self._rebuild_decision(str(event.body["decision_id"]))
        elif event.event_type.startswith("commitment.") and "commitment_id" in event.body:
            self._rebuild_commitment(str(event.body["commitment_id"]))
        elif event.event_type == "artifact.published" and "artifact_id" in event.body:
            self._project_artifact(event)
        elif event.event_type.startswith("governance.") and "proposal_id" in event.body:
            self._rebuild_governance(str(event.body["proposal_id"]))
        elif event.event_type == "space.created" and "space_id" in event.body:
            self._project_space(event)
        elif event.event_type.startswith("document.") and "document_id" in event.body:
            self._rebuild_document(str(event.body["document_id"]))
        elif event.event_type == "memory.checkpoint" and "checkpoint_id" in event.body:
            self._project_checkpoint(event)

    def _object_events(self, prefix: str, id_field: str, object_id: str) -> list[SignedEvent]:
        return [
            event for event in self._causally_ordered_events()
            if event.event_type.startswith(f"{prefix}.")
            and str(event.body.get(id_field)) == object_id
        ]

    def _causally_ordered_events(self) -> list[SignedEvent]:
        events = {event.event_id: event for event in self.list_events()}
        children: dict[str, set[str]] = {event_id: set() for event_id in events}
        indegree = {event_id: 0 for event_id in events}
        for event in events.values():
            for parent in event.parents:
                if parent in events:
                    children[parent].add(event.event_id)
                    indegree[event.event_id] += 1
        ready = [event_id for event_id, degree in indegree.items() if degree == 0]
        heapq.heapify(ready)
        ordered: list[SignedEvent] = []
        while ready:
            event_id = heapq.heappop(ready)
            ordered.append(events[event_id])
            for child in sorted(children[event_id]):
                indegree[child] -= 1
                if indegree[child] == 0:
                    heapq.heappush(ready, child)
        if len(ordered) != len(events):
            raise ValueError("event graph contains a causal cycle")
        return ordered

    def _conflict(self, event: SignedEvent, kind: str, object_id: str, reason: str) -> None:
        self.db.execute(
            """INSERT OR REPLACE INTO projection_conflicts
               (event_id, object_type, object_id, reason) VALUES (?, ?, ?, ?)""",
            (event.event_id, kind, object_id, reason),
        )

    def _rebuild_task(self, task_id: str) -> None:
        events = self._object_events("task", "task_id", task_id)
        self.db.execute(
            "DELETE FROM projection_conflicts WHERE object_type = 'task' AND object_id = ?",
            (task_id,),
        )
        created = [event for event in events if event.event_type == "task.created"]
        if not created:
            return
        origin = created[0]
        title = str(origin.body.get("title", ""))[:500]
        description = str(origin.body.get("description", ""))[:10_000]
        status = "open"
        assignee = None
        version = 1
        updated = origin.event_id
        for duplicate in created[1:]:
            self._conflict(duplicate, "task", task_id, "duplicate creation")
        for event in [item for item in events if item.event_type != "task.created"]:
            expected = int(event.body.get("expected_version", -1))
            if expected != version:
                self._conflict(
                    event, "task", task_id,
                    f"stale version {expected}; deterministic version was {version}"
                )
                continue
            if event.event_type == "task.claimed" and status in {"open", "released"}:
                assignee = str(event.body.get("claimant", event.author))
                status = "claimed"
            elif event.event_type == "task.updated":
                next_status = str(event.body.get("status", status))
                if next_status not in {
                    "open", "claimed", "submitted", "verified", "blocked", "released"
                }:
                    self._conflict(event, "task", task_id, "invalid status")
                    continue
                status = next_status
                if "assignee" in event.body:
                    assignee = event.body["assignee"]
            else:
                self._conflict(event, "task", task_id, "transition not valid from current state")
                continue
            version += 1
            updated = event.event_id
        self.db.execute(
            """INSERT OR REPLACE INTO tasks
               (task_id, collective_id, space_id, title, description, status,
                assignee, version, updated_event_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                task_id, origin.collective_id, origin.space_id, title, description,
                status, assignee, version, updated,
            ),
        )

    def _rebuild_decision(self, decision_id: str) -> None:
        events = self._object_events("decision", "decision_id", decision_id)
        proposed = [event for event in events if event.event_type == "decision.proposed"]
        if not proposed:
            return
        origin = proposed[0]
        options = tuple(str(v) for v in origin.body.get("options", ()))
        threshold = max(1, int(origin.body.get("threshold", 1)))
        votes: dict[str, str] = {}
        updated = origin.event_id
        self.db.execute(
            "DELETE FROM projection_conflicts WHERE object_type = 'decision' AND object_id = ?",
            (decision_id,),
        )
        for duplicate in proposed[1:]:
            self._conflict(duplicate, "decision", decision_id, "duplicate proposal")
        for event in [item for item in events if item.event_type == "decision.voted"]:
            choice = str(event.body.get("choice", ""))
            if choice not in options:
                self._conflict(event, "decision", decision_id, "choice is not an option")
                continue
            votes[event.author] = choice
            updated = event.event_id
        counts = {option: sum(v == option for v in votes.values()) for option in options}
        winners = [option for option, count in counts.items() if count >= threshold]
        resolution = None if not winners else sorted(winners, key=lambda v: (-counts[v], v))[0]
        self.db.execute(
            """INSERT OR REPLACE INTO decisions
               (decision_id, collective_id, space_id, question, options_json,
                threshold, status, resolution, vote_counts_json, updated_event_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                decision_id, origin.collective_id, origin.space_id,
                str(origin.body.get("question", ""))[:2_000],
                canonical_json(list(options)), threshold,
                "decided" if resolution is not None else "open", resolution,
                canonical_json(counts), updated,
            ),
        )

    def _rebuild_commitment(self, commitment_id: str) -> None:
        events = self._object_events("commitment", "commitment_id", commitment_id)
        created = [event for event in events if event.event_type == "commitment.created"]
        if not created:
            return
        origin = created[0]
        description = str(origin.body.get("description", ""))[:10_000]
        owner = str(origin.body.get("owner", origin.author))
        due = origin.body.get("due_at_ms")
        status = "open"
        evidence: list[Any] = []
        version = 1
        updated = origin.event_id
        self.db.execute(
            "DELETE FROM projection_conflicts WHERE object_type = 'commitment' AND object_id = ?",
            (commitment_id,),
        )
        for event in [item for item in events if item.event_type == "commitment.updated"]:
            expected = int(event.body.get("expected_version", -1))
            if expected != version:
                self._conflict(event, "commitment", commitment_id, "stale version")
                continue
            next_status = str(event.body.get("status", status))
            if next_status not in {"open", "in_progress", "fulfilled", "failed", "cancelled"}:
                self._conflict(event, "commitment", commitment_id, "invalid status")
                continue
            status = next_status
            if "evidence" in event.body:
                evidence.append(event.body["evidence"])
            version += 1
            updated = event.event_id
        self.db.execute(
            """INSERT OR REPLACE INTO commitments
               (commitment_id, collective_id, space_id, description, owner, status,
                due_at_ms, evidence_json, version, updated_event_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                commitment_id, origin.collective_id, origin.space_id, description,
                owner, status, due, canonical_json(evidence), version, updated,
            ),
        )

    def tasks(self, collective_id: str | None = None) -> list[dict[str, Any]]:
        if collective_id is None:
            rows = self.db.execute("SELECT * FROM tasks ORDER BY task_id").fetchall()
        else:
            rows = self.db.execute(
                "SELECT * FROM tasks WHERE collective_id = ? ORDER BY task_id",
                (collective_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def decisions(self, collective_id: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM decisions"
        args: tuple[Any, ...] = ()
        if collective_id is not None:
            sql += " WHERE collective_id = ?"
            args = (collective_id,)
        rows = self.db.execute(sql + " ORDER BY decision_id", args).fetchall()
        values = []
        for row in rows:
            value = dict(row)
            value["options"] = parse_json(bytes(value.pop("options_json")))
            value["vote_counts"] = parse_json(bytes(value.pop("vote_counts_json")))
            values.append(value)
        return values

    def commitments(self, collective_id: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM commitments"
        args: tuple[Any, ...] = ()
        if collective_id is not None:
            sql += " WHERE collective_id = ?"
            args = (collective_id,)
        rows = self.db.execute(sql + " ORDER BY commitment_id", args).fetchall()
        values = []
        for row in rows:
            value = dict(row)
            value["evidence"] = parse_json(bytes(value.pop("evidence_json")))
            values.append(value)
        return values

    def _project_artifact(self, event: SignedEvent) -> None:
        body = event.body
        artifact_id = str(body["artifact_id"])
        existing = self.db.execute(
            "SELECT published_event_id FROM artifacts WHERE artifact_id = ?",
            (artifact_id,),
        ).fetchone()
        if existing is not None:
            if existing["published_event_id"] != event.event_id:
                self._conflict(event, "artifact", artifact_id, "duplicate publication")
            return
        self.db.execute(
            """INSERT INTO artifacts
               (artifact_id, collective_id, space_id, name, media_type, byte_size,
                plaintext_sha256, blob_id, key_b64, nonce_b64, published_by,
                published_event_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                artifact_id, event.collective_id, event.space_id,
                str(body.get("name", "artifact"))[:500],
                str(body.get("media_type", "application/octet-stream"))[:200],
                int(body["byte_size"]), str(body["plaintext_sha256"]),
                str(body["blob_id"]), str(body["key"]), str(body["nonce"]),
                event.author, event.event_id,
            ),
        )

    def artifacts(self, collective_id: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM artifacts"
        args: tuple[Any, ...] = ()
        if collective_id is not None:
            sql += " WHERE collective_id = ?"
            args = (collective_id,)
        return [dict(row) for row in self.db.execute(
            sql + " ORDER BY artifact_id", args
        ).fetchall()]

    def _rebuild_governance(self, proposal_id: str) -> None:
        events = self._object_events("governance", "proposal_id", proposal_id)
        proposed = [event for event in events if event.event_type == "governance.proposed"]
        if not proposed:
            return
        origin = proposed[0]
        threshold = max(1, int(origin.body.get("threshold", 1)))
        approvals = {
            event.author
            for event in events
            if event.event_type == "governance.approved"
            and self.get_member_identity(event.collective_id, event.author) is not None
        }
        approvals.add(origin.author)
        existing = self.db.execute(
            "SELECT executed_epoch FROM governance_proposals WHERE proposal_id = ?",
            (proposal_id,),
        ).fetchone()
        executed_epoch = None if existing is None else existing["executed_epoch"]
        status = "executed" if executed_epoch is not None else (
            "authorized" if len(approvals) >= threshold else "open"
        )
        self.db.execute(
            """INSERT OR REPLACE INTO governance_proposals
               (proposal_id, collective_id, operation, target, threshold,
                approvals_json, status, proposed_event_id, executed_epoch)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                proposal_id, origin.collective_id,
                str(origin.body.get("operation", "")),
                str(origin.body.get("target", "")), threshold,
                canonical_json(sorted(approvals)), status, origin.event_id,
                executed_epoch,
            ),
        )

    def governance_proposals(
        self, collective_id: str | None = None
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM governance_proposals"
        args: tuple[Any, ...] = ()
        if collective_id is not None:
            sql += " WHERE collective_id = ?"
            args = (collective_id,)
        values = []
        for row in self.db.execute(sql + " ORDER BY proposal_id", args).fetchall():
            value = dict(row)
            value["approvals"] = parse_json(bytes(value.pop("approvals_json")))
            values.append(value)
        return values

    def mark_proposal_executed(self, proposal_id: str, epoch: int) -> None:
        with self.db:
            cursor = self.db.execute(
                """UPDATE governance_proposals
                   SET status = 'executed', executed_epoch = ?
                   WHERE proposal_id = ? AND status = 'authorized'""",
                (epoch, proposal_id),
            )
            if cursor.rowcount != 1:
                raise ValueError("proposal is not authorized for execution")

    def _project_space(self, event: SignedEvent) -> None:
        space_id = str(event.body["space_id"])
        existing = self.db.execute(
            "SELECT created_event_id FROM spaces WHERE collective_id = ? AND space_id = ?",
            (event.collective_id, space_id),
        ).fetchone()
        if existing is not None:
            self._conflict(event, "space", space_id, "duplicate space identifier")
            return
        self.db.execute(
            """INSERT INTO spaces
               (collective_id, space_id, name, purpose, created_event_id)
               VALUES (?, ?, ?, ?, ?)""",
            (
                event.collective_id, space_id,
                str(event.body.get("name", space_id))[:500],
                str(event.body.get("purpose", ""))[:2_000], event.event_id,
            ),
        )

    def spaces(self, collective_id: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM spaces"
        args: tuple[Any, ...] = ()
        if collective_id is not None:
            sql += " WHERE collective_id = ?"
            args = (collective_id,)
        return [dict(row) for row in self.db.execute(
            sql + " ORDER BY collective_id, space_id", args
        ).fetchall()]

    def _rebuild_document(self, document_id: str) -> None:
        events = self._object_events("document", "document_id", document_id)
        created = [event for event in events if event.event_type == "document.created"]
        if not created:
            return
        origin = created[0]
        self.db.execute(
            """INSERT OR REPLACE INTO documents
               (document_id, collective_id, space_id, title, created_event_id)
               VALUES (?, ?, ?, ?, ?)""",
            (
                document_id, origin.collective_id, origin.space_id,
                str(origin.body.get("title", "Untitled"))[:500], origin.event_id,
            ),
        )
        self.db.execute("DELETE FROM document_fields WHERE document_id = ?", (document_id,))
        winners: dict[str, SignedEvent] = {}
        for event in events:
            if event.event_type != "document.field_set":
                continue
            field = str(event.body.get("field", ""))
            if not field or len(field) > 200:
                self._conflict(event, "document", document_id, "invalid field name")
                continue
            current = winners.get(field)
            stamp = (event.author_seq, event.author, event.event_id)
            if current is None or stamp > (
                current.author_seq, current.author, current.event_id
            ):
                winners[field] = event
        for field, event in winners.items():
            self.db.execute(
                """INSERT INTO document_fields
                   (document_id, field, value_json, winning_event_id)
                   VALUES (?, ?, ?, ?)""",
                (
                    document_id, field, canonical_json(event.body.get("value")),
                    event.event_id,
                ),
            )

    def documents(self, collective_id: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM documents"
        args: tuple[Any, ...] = ()
        if collective_id is not None:
            sql += " WHERE collective_id = ?"
            args = (collective_id,)
        documents = []
        for row in self.db.execute(sql + " ORDER BY document_id", args).fetchall():
            value = dict(row)
            fields = self.db.execute(
                """SELECT field, value_json, winning_event_id FROM document_fields
                   WHERE document_id = ? ORDER BY field""",
                (row["document_id"],),
            ).fetchall()
            value["fields"] = {
                field["field"]: parse_json(bytes(field["value_json"])) for field in fields
            }
            value["field_sources"] = {
                field["field"]: field["winning_event_id"] for field in fields
            }
            documents.append(value)
        return documents

    def _project_checkpoint(self, event: SignedEvent) -> None:
        body = event.body
        confidence = float(body.get("confidence", 0.5))
        if confidence < 0 or confidence > 1:
            self._conflict(event, "checkpoint", str(body["checkpoint_id"]), "invalid confidence")
            return
        self.db.execute(
            """INSERT OR IGNORE INTO checkpoints
               (checkpoint_id, collective_id, space_id, author, summary, confidence,
                source_events_json, event_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                str(body["checkpoint_id"]), event.collective_id, event.space_id,
                event.author, str(body.get("summary", ""))[:20_000], confidence,
                canonical_json(list(body.get("source_events", ()))), event.event_id,
            ),
        )

    def checkpoints(self, collective_id: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM checkpoints"
        args: tuple[Any, ...] = ()
        if collective_id is not None:
            sql += " WHERE collective_id = ?"
            args = (collective_id,)
        values = []
        for row in self.db.execute(sql + " ORDER BY event_id", args).fetchall():
            value = dict(row)
            value["source_events"] = parse_json(bytes(value.pop("source_events_json")))
            values.append(value)
        return values

    def list_events(self) -> list[SignedEvent]:
        rows = self.db.execute(
            "SELECT event_json FROM events ORDER BY created_at_ms, event_id"
        ).fetchall()
        return [SignedEvent.from_dict(parse_json(bytes(row["event_json"]))) for row in rows]

    def mark_inbox(self, envelope_id: str, status: str, reason: str | None = None) -> None:
        with self.db:
            self.db.execute(
                """INSERT OR REPLACE INTO inbox
                   (envelope_id, status, reason, received_at_ms) VALUES (?, ?, ?, ?)""",
                (envelope_id, status, reason, now_ms()),
            )

    def inbox_status(self, envelope_id: str) -> str | None:
        row = self.db.execute(
            "SELECT status FROM inbox WHERE envelope_id = ?", (envelope_id,)
        ).fetchone()
        return None if row is None else str(row["status"])

    def queue_outbox(
        self, envelope: dict[str, Any], peer_id: str, event_id: str | None,
        *, route_id: str, write_token: str
    ) -> None:
        with self.db:
            self.db.execute(
                """INSERT OR IGNORE INTO outbox
                   (envelope_id, peer_id, event_id, status, created_at_ms,
                    route_id, write_token, envelope_json, attempts, last_error)
                   VALUES (?, ?, ?, 'pending', ?, ?, ?, ?, 0, NULL)""",
                (
                    envelope["envelope_id"], peer_id, event_id, now_ms(), route_id,
                    write_token, canonical_json(envelope),
                ),
            )

    def pending_outbox(self, limit: int = 100) -> list[sqlite3.Row]:
        return self.db.execute(
            """SELECT * FROM outbox WHERE status = 'pending'
               ORDER BY created_at_ms, envelope_id LIMIT ?""",
            (limit,),
        ).fetchall()

    def finish_outbox(self, envelope_id: str) -> None:
        with self.db:
            self.db.execute(
                """UPDATE outbox SET status = 'sent', attempts = attempts + 1,
                   last_error = NULL WHERE envelope_id = ?""",
                (envelope_id,),
            )

    def fail_outbox(self, envelope_id: str, error: str) -> None:
        with self.db:
            self.db.execute(
                """UPDATE outbox SET attempts = attempts + 1, last_error = ?
                   WHERE envelope_id = ?""",
                (error[:500], envelope_id),
            )

    def outbox_counts(self) -> dict[str, int]:
        rows = self.db.execute(
            "SELECT status, COUNT(*) AS count FROM outbox GROUP BY status"
        ).fetchall()
        return {str(row["status"]): int(row["count"]) for row in rows}

    def audit(
        self, action: str, actor: str | None, object_id: str | None,
        outcome: str, summary: str, evidence: dict[str, Any]
    ) -> None:
        with self.db:
            self.db.execute(
                """INSERT INTO audit
                   (occurred_at_ms, action, actor, object_id, outcome, summary, evidence_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (now_ms(), action, actor, object_id, outcome, summary, canonical_json(evidence)),
            )

    def audit_rows(self) -> list[sqlite3.Row]:
        return self.db.execute("SELECT * FROM audit ORDER BY audit_id").fetchall()
