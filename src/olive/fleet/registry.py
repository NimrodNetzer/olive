"""Gateway registry — control plane SQLite store (ADR-0024).

Receives heartbeats from N gateway instances, tracks liveness, stores the
commanded mode per gateway, and provides aggregate fleet views.

Follows the ADR-0004 pattern: own aiosqlite connection, schema-first, all
access parameterized. Never writes to any gateway's local audit DB.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

import aiosqlite

_SCHEMA = """
CREATE TABLE IF NOT EXISTS gateway_instances (
    gateway_id      TEXT PRIMARY KEY,
    org_id          TEXT NOT NULL DEFAULT '',
    reported_mode   TEXT NOT NULL DEFAULT 'normal',
    commanded_mode  TEXT NOT NULL DEFAULT 'normal',
    last_heartbeat  TEXT NOT NULL,
    first_seen      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS fleet_events (
    event_id        TEXT PRIMARY KEY,
    gateway_id      TEXT NOT NULL,
    agent_id        TEXT NOT NULL DEFAULT '',
    session_id      TEXT NOT NULL DEFAULT '',
    tool            TEXT NOT NULL DEFAULT '',
    decision        TEXT NOT NULL DEFAULT '',
    policy_rule     TEXT,
    timestamp       TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS fleet_incidents (
    incident_id     TEXT PRIMARY KEY,
    gateway_id      TEXT NOT NULL,
    agent_id        TEXT NOT NULL DEFAULT '',
    attack_type     TEXT NOT NULL DEFAULT 'unknown',
    confidence      REAL,
    decision        TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'open',
    timestamp       TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS fleet_mode_commands (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target      TEXT NOT NULL,
    mode        TEXT NOT NULL,
    issued_by   TEXT NOT NULL,
    issued_at   TEXT NOT NULL
);
"""


class GatewayRegistry:
    def __init__(self, db_path: str | Path) -> None:
        self._db_path = str(db_path)
        self._db: aiosqlite.Connection | None = None

    async def open(self) -> None:
        self._db = await aiosqlite.connect(self._db_path)
        self._db.row_factory = aiosqlite.Row
        await self._db.executescript(_SCHEMA)
        await self._db.commit()

    async def close(self) -> None:
        if self._db is not None:
            await self._db.close()

    async def record_heartbeat(
        self, gateway_id: str, org_id: str, reported_mode: str
    ) -> str:
        """Record a heartbeat and return the commanded_mode for this gateway."""
        now = datetime.now(timezone.utc).isoformat()
        assert self._db is not None
        async with self._db.execute(
            "SELECT commanded_mode FROM gateway_instances WHERE gateway_id = ?",
            (gateway_id,),
        ) as cur:
            row = await cur.fetchone()

        if row is None:
            commanded_mode = "normal"
            await self._db.execute(
                """INSERT INTO gateway_instances
                   (gateway_id, org_id, reported_mode, commanded_mode, last_heartbeat, first_seen)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (gateway_id, org_id, reported_mode, commanded_mode, now, now),
            )
        else:
            commanded_mode = row["commanded_mode"]
            await self._db.execute(
                """UPDATE gateway_instances
                   SET reported_mode = ?, last_heartbeat = ?, org_id = ?
                   WHERE gateway_id = ?""",
                (reported_mode, now, org_id, gateway_id),
            )
        await self._db.commit()
        return commanded_mode

    async def record_events(self, gateway_id: str, events: list[dict]) -> None:
        assert self._db is not None
        for ev in events:
            await self._db.execute(
                """INSERT OR IGNORE INTO fleet_events
                   (event_id, gateway_id, agent_id, session_id, tool,
                    decision, policy_rule, timestamp)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    ev.get("event_id") or str(uuid.uuid4()),
                    gateway_id,
                    ev.get("agent_id", ""),
                    ev.get("session_id", ""),
                    ev.get("tool", ""),
                    ev.get("decision", ""),
                    ev.get("policy_rule"),
                    ev.get("timestamp") or datetime.now(timezone.utc).isoformat(),
                ),
            )
        await self._db.commit()

    async def record_incidents(self, gateway_id: str, incidents: list[dict]) -> None:
        assert self._db is not None
        for inc in incidents:
            await self._db.execute(
                """INSERT OR IGNORE INTO fleet_incidents
                   (incident_id, gateway_id, agent_id, attack_type,
                    confidence, decision, status, timestamp)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    inc.get("incident_id") or str(uuid.uuid4()),
                    gateway_id,
                    inc.get("agent_id", ""),
                    inc.get("attack_type", "unknown"),
                    inc.get("confidence"),
                    inc.get("decision", ""),
                    inc.get("status", "open"),
                    inc.get("timestamp") or datetime.now(timezone.utc).isoformat(),
                ),
            )
        await self._db.commit()

    async def set_fleet_mode(self, mode: str, issued_by: str) -> None:
        """Set commanded_mode for ALL gateways; each picks it up on next heartbeat."""
        assert self._db is not None
        now = datetime.now(timezone.utc).isoformat()
        await self._db.execute(
            "UPDATE gateway_instances SET commanded_mode = ?", (mode,)
        )
        await self._db.execute(
            """INSERT INTO fleet_mode_commands (target, mode, issued_by, issued_at)
               VALUES (?, ?, ?, ?)""",
            ("all", mode, issued_by, now),
        )
        await self._db.commit()

    async def list_gateways(self) -> list[dict]:
        assert self._db is not None
        async with self._db.execute(
            "SELECT * FROM gateway_instances ORDER BY last_heartbeat DESC"
        ) as cur:
            return [dict(row) for row in await cur.fetchall()]

    async def recent_events(self, limit: int = 100) -> list[dict]:
        assert self._db is not None
        async with self._db.execute(
            "SELECT * FROM fleet_events ORDER BY timestamp DESC LIMIT ?", (limit,)
        ) as cur:
            return [dict(row) for row in await cur.fetchall()]

    async def recent_incidents(self, limit: int = 100) -> list[dict]:
        assert self._db is not None
        async with self._db.execute(
            "SELECT * FROM fleet_incidents ORDER BY timestamp DESC LIMIT ?", (limit,)
        ) as cur:
            return [dict(row) for row in await cur.fetchall()]
