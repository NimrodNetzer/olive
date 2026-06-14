"""SQLite audit store - events and incidents (ADR-0004).

Every decision the gateway makes writes an event row; every block/quarantine
also writes an incident. Raw payloads are never stored: arguments arrive
here only as SHA-256 hashes (built into SecurityContext) and evidence is
bounded upstream by the pipeline.

This module is the only place SQL lives. All access is parameterized.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

import aiosqlite

from olive.gateway.context import SecurityContext
from olive.gateway.pipeline import Verdict

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    event_id        TEXT PRIMARY KEY,
    timestamp       TEXT NOT NULL,
    agent_id        TEXT NOT NULL,
    session_id      TEXT NOT NULL,
    organization_id TEXT NOT NULL,
    role            TEXT NOT NULL,
    tool            TEXT NOT NULL,
    direction       TEXT NOT NULL,
    decision        TEXT NOT NULL,
    policy_rule     TEXT,
    arguments_hash  TEXT,
    latency_ms      INTEGER,
    incident_id     TEXT
);
CREATE TABLE IF NOT EXISTS incidents (
    incident_id      TEXT PRIMARY KEY,
    timestamp        TEXT NOT NULL,
    agent_id         TEXT NOT NULL,
    session_id       TEXT NOT NULL,
    attack_type      TEXT NOT NULL,
    evidence         TEXT NOT NULL,
    confidence       REAL,
    detection_method TEXT NOT NULL,
    decision         TEXT NOT NULL,
    status           TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tool_baselines (
    tool_name        TEXT PRIMARY KEY,
    declaration_hash TEXT NOT NULL,
    first_seen       TEXT NOT NULL,
    last_seen        TEXT NOT NULL
);
"""


class BaselineStatus(StrEnum):
    NEW = "new"  # first sighting - baseline recorded (trust on first use)
    UNCHANGED = "unchanged"  # declaration matches the baseline
    CHANGED = "changed"  # declaration differs from baseline (rug-pull signal)


@dataclass(frozen=True, slots=True)
class EventSummary:
    total: int
    allowed: int
    blocked: int
    incidents: int


class EventStore:
    def __init__(self, path: str | Path) -> None:
        self._path = str(path)
        self._db: aiosqlite.Connection | None = None

    async def open(self) -> None:
        self._db = await aiosqlite.connect(self._path)
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.executescript(_SCHEMA)
        await self._db.commit()

    async def close(self) -> None:
        if self._db is not None:
            await self._db.close()
            self._db = None

    @property
    def _conn(self) -> aiosqlite.Connection:
        if self._db is None:
            raise RuntimeError("EventStore is not open")
        return self._db

    async def log_event(
        self,
        ctx: SecurityContext,
        verdict: Verdict,
        latency_ms: int | None = None,
        incident_id: str | None = None,
    ) -> str:
        event_id = f"evt-{uuid.uuid4().hex[:12]}"
        await self._conn.execute(
            "INSERT INTO events (event_id, timestamp, agent_id, session_id, organization_id,"
            " role, tool, direction, decision, policy_rule, arguments_hash, latency_ms,"
            " incident_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                event_id,
                ctx.timestamp,
                ctx.agent_id,
                ctx.session_id,
                ctx.organization_id,
                ctx.role,
                ctx.tool,
                ctx.direction,
                verdict.decision.value,
                verdict.rule,
                ctx.arguments_hash,
                latency_ms,
                incident_id,
            ),
        )
        await self._conn.commit()
        return event_id

    async def create_incident(
        self,
        ctx: SecurityContext,
        verdict: Verdict,
        attack_type: str,
        detection_method: str,
        status: str = "open",
    ) -> str:
        # Single-statement insert: the id is derived inside the INSERT itself,
        # so concurrent incidents cannot race to the same number.
        cursor = await self._conn.execute(
            "INSERT INTO incidents (incident_id, timestamp, agent_id, session_id, attack_type,"
            " evidence, confidence, detection_method, decision, status)"
            " VALUES ((SELECT 'INC-' || printf('%04d', COUNT(*) + 1) FROM incidents),"
            " ?, ?, ?, ?, ?, ?, ?, ?, ?)"
            " RETURNING incident_id",
            (
                ctx.timestamp,
                ctx.agent_id,
                ctx.session_id,
                attack_type,
                verdict.evidence or "",
                verdict.confidence,
                detection_method,
                verdict.decision.value,
                status,
            ),
        )
        row = await cursor.fetchone()
        await self._conn.commit()
        return row[0]

    async def summary(self) -> EventSummary:
        cursor = await self._conn.execute(
            "SELECT COUNT(*),"
            " SUM(CASE WHEN decision = 'allow' THEN 1 ELSE 0 END),"
            " SUM(CASE WHEN decision != 'allow' THEN 1 ELSE 0 END)"
            " FROM events"
        )
        events_row = await cursor.fetchone()
        cursor = await self._conn.execute("SELECT COUNT(*) FROM incidents")
        incidents_row = await cursor.fetchone()
        total, allowed, blocked = (events_row or (0, 0, 0))[:3]
        return EventSummary(
            total=total or 0,
            allowed=allowed or 0,
            blocked=blocked or 0,
            incidents=(incidents_row or (0,))[0] or 0,
        )

    async def observe_tool(self, tool_name: str, declaration_hash: str) -> BaselineStatus:
        """Trust-on-first-use baseline check (ADR-0009). Records a new baseline,
        confirms an unchanged one, or reports a CHANGED declaration. A mismatch
        NEVER overwrites the baseline - the swap must not become the new normal."""
        now = SecurityContext.now()
        cursor = await self._conn.execute(
            "INSERT OR IGNORE INTO tool_baselines"
            " (tool_name, declaration_hash, first_seen, last_seen) VALUES (?, ?, ?, ?)",
            (tool_name, declaration_hash, now, now),
        )
        if cursor.rowcount == 1:
            await self._conn.commit()
            return BaselineStatus.NEW

        cursor = await self._conn.execute(
            "SELECT declaration_hash FROM tool_baselines WHERE tool_name = ?", (tool_name,)
        )
        row = await cursor.fetchone()
        if row is not None and row[0] == declaration_hash:
            await self._conn.execute(
                "UPDATE tool_baselines SET last_seen = ? WHERE tool_name = ?", (now, tool_name)
            )
            await self._conn.commit()
            return BaselineStatus.UNCHANGED

        await self._conn.commit()  # baseline left intact on purpose
        return BaselineStatus.CHANGED

    async def reset_baseline(self, tool_name: str | None = None) -> int:
        """Clear baselines so a legitimate declaration change can be re-accepted
        on the next listing. Returns the number of baselines removed."""
        if tool_name is None:
            cursor = await self._conn.execute("DELETE FROM tool_baselines")
        else:
            cursor = await self._conn.execute(
                "DELETE FROM tool_baselines WHERE tool_name = ?", (tool_name,)
            )
        await self._conn.commit()
        return cursor.rowcount
