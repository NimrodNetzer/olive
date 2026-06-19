"""SQLite audit store - events and incidents (ADR-0004).

Every decision the gateway makes writes an event row; every block/quarantine
also writes an incident. Raw payloads are never stored: arguments arrive
here only as SHA-256 hashes (built into SecurityContext) and evidence is
bounded upstream by the pipeline.

This module is the only place SQL lives. All access is parameterized.
"""

from __future__ import annotations

import hashlib
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
CREATE TABLE IF NOT EXISTS sessions (
    session_key            TEXT PRIMARY KEY,
    block_count            INTEGER NOT NULL DEFAULT 0,
    quarantined            INTEGER NOT NULL DEFAULT 0,
    quarantine_reason      TEXT,
    quarantine_incident_id TEXT,
    persisted_at           TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS runtime_state (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti        TEXT PRIMARY KEY,
    org_id     TEXT NOT NULL,
    agent_id   TEXT NOT NULL,
    revoked_at TEXT NOT NULL,
    reason     TEXT
);
CREATE TABLE IF NOT EXISTS agent_tool_history (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id   TEXT NOT NULL,
    org_id     TEXT NOT NULL,
    session_key TEXT NOT NULL,
    tool       TEXT NOT NULL,
    call_ts    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ath_agent ON agent_tool_history (agent_id, org_id, call_ts DESC);
CREATE TABLE IF NOT EXISTS policy_checksums (
    path        TEXT PRIMARY KEY,
    sha256_hash TEXT NOT NULL,
    recorded_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_chain (
    event_id   TEXT PRIMARY KEY,
    prev_hash  TEXT NOT NULL,
    row_hash   TEXT NOT NULL
);
"""


_CHAIN_GENESIS = "0" * 64  # sentinel prev_hash for the first event in the chain


def _chain_hash(event_id: str, decision: str, timestamp: str, prev_hash: str) -> str:
    """SHA-256 of the four fields that uniquely describe a gateway decision.
    Linking each row to the previous hash makes deletions and modifications
    detectable (ADR-0026 layer 2)."""
    payload = f"{event_id}|{decision}|{timestamp}|{prev_hash}"
    return hashlib.sha256(payload.encode()).hexdigest()


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


@dataclass(frozen=True, slots=True)
class AuditChainStatus:
    ok: bool
    total_events: int
    chained_events: int      # rows that have a chain record
    broken_at_event_id: str | None  # first broken link, None if ok
    detail: str              # human-readable one-liner


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
        # Tamper-evident audit chain (ADR-0026): link this event to the previous one.
        cursor = await self._conn.execute(
            "SELECT row_hash FROM audit_chain ORDER BY rowid DESC LIMIT 1"
        )
        row = await cursor.fetchone()
        prev_hash = row[0] if row else _CHAIN_GENESIS
        row_hash = _chain_hash(event_id, verdict.decision.value, ctx.timestamp, prev_hash)
        await self._conn.execute(
            "INSERT INTO audit_chain (event_id, prev_hash, row_hash) VALUES (?, ?, ?)",
            (event_id, prev_hash, row_hash),
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

    async def persist_session(
        self,
        session_key: str,
        block_count: int,
        quarantined: bool,
        reason: str | None,
        incident_id: str | None,
    ) -> None:
        """Upsert the quarantine state of a session so it survives gateway restarts."""
        now = SecurityContext.now()
        await self._conn.execute(
            "INSERT OR REPLACE INTO sessions"
            " (session_key, block_count, quarantined, quarantine_reason,"
            "  quarantine_incident_id, persisted_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (session_key, block_count, int(quarantined), reason, incident_id, now),
        )
        await self._conn.commit()

    async def load_sessions(self) -> list[dict]:
        """Load all persisted session states for restoration on startup."""
        cursor = await self._conn.execute(
            "SELECT session_key, block_count, quarantined,"
            " quarantine_reason, quarantine_incident_id FROM sessions"
        )
        rows = await cursor.fetchall()
        return [
            {
                "session_key": r[0],
                "block_count": r[1],
                "quarantined": bool(r[2]),
                "quarantine_reason": r[3],
                "quarantine_incident_id": r[4],
            }
            for r in rows
        ]

    async def delete_session(self, session_key: str) -> None:
        """Remove a session from the persistence table (called on human release)."""
        await self._conn.execute(
            "DELETE FROM sessions WHERE session_key = ?", (session_key,)
        )
        await self._conn.commit()

    async def persist_mode(self, mode_value: str) -> None:
        """Persist the current operating mode so it is restored after a restart."""
        now = SecurityContext.now()
        await self._conn.execute(
            "INSERT OR REPLACE INTO runtime_state (key, value, updated_at)"
            " VALUES ('operating_mode', ?, ?)",
            (mode_value, now),
        )
        await self._conn.commit()

    async def load_mode(self) -> str | None:
        """Return the last persisted operating mode string, or None if never set."""
        cursor = await self._conn.execute(
            "SELECT value FROM runtime_state WHERE key = 'operating_mode'"
        )
        row = await cursor.fetchone()
        return row[0] if row else None

    async def revoke_token(
        self, jti: str, org_id: str, agent_id: str, reason: str | None = None
    ) -> None:
        """Add a JWT token ID to the revocation list (M9 — Siege Crisis Response)."""
        now = SecurityContext.now()
        await self._conn.execute(
            "INSERT OR IGNORE INTO revoked_tokens (jti, org_id, agent_id, revoked_at, reason)"
            " VALUES (?, ?, ?, ?, ?)",
            (jti, org_id, agent_id, now, reason),
        )
        await self._conn.commit()

    async def load_revoked_jtis(self) -> list[str]:
        """Load all revoked token JTIs for in-memory cache population on startup."""
        cursor = await self._conn.execute("SELECT jti FROM revoked_tokens")
        rows = await cursor.fetchall()
        return [r[0] for r in rows]

    async def log_allowed_call(
        self, agent_id: str, org_id: str, session_key: str, tool: str
    ) -> None:
        """Append a completed allowed tool call to the cross-session behavioral baseline
        (M10). Used by BehaviorSentinel for multi-session drift detection."""
        now = SecurityContext.now()
        await self._conn.execute(
            "INSERT INTO agent_tool_history (agent_id, org_id, session_key, tool, call_ts)"
            " VALUES (?, ?, ?, ?, ?)",
            (agent_id, org_id, session_key, tool, now),
        )
        await self._conn.commit()

    async def recent_agent_tools(
        self, agent_id: str, org_id: str, n: int = 50
    ) -> list[str]:
        """Return the N most recent tools used by this agent across ALL sessions.
        Used by BehaviorSentinel to detect multi-session slow-burn sequences."""
        cursor = await self._conn.execute(
            "SELECT tool FROM agent_tool_history"
            " WHERE agent_id = ? AND org_id = ?"
            " ORDER BY call_ts DESC LIMIT ?",
            (agent_id, org_id, n),
        )
        rows = await cursor.fetchall()
        return [r[0] for r in rows]

    async def agent_calls_per_session(
        self, agent_id: str, org_id: str, n_sessions: int = 20
    ) -> list[int]:
        """Return per-session call counts for the N most recent completed sessions.
        Used by BehaviorSentinel to compute the agent's historical call-rate
        baseline so an unusually active session raises a drift signal."""
        cursor = await self._conn.execute(
            "SELECT session_key, COUNT(*) AS cnt FROM agent_tool_history"
            " WHERE agent_id = ? AND org_id = ?"
            " GROUP BY session_key ORDER BY MAX(call_ts) DESC LIMIT ?",
            (agent_id, org_id, n_sessions),
        )
        rows = await cursor.fetchall()
        return [r[1] for r in rows]

    async def agent_known_tools(self, agent_id: str, org_id: str) -> set[str]:
        """Return the complete set of tool names this agent has ever used.
        Used by BehaviorSentinel to flag a call to a tool the agent has never
        touched before — a novel-tool signal for sensitive or privileged tools."""
        cursor = await self._conn.execute(
            "SELECT DISTINCT tool FROM agent_tool_history"
            " WHERE agent_id = ? AND org_id = ?",
            (agent_id, org_id),
        )
        rows = await cursor.fetchall()
        return {r[0] for r in rows}

    async def recent_events(self, limit: int = 50) -> list[dict]:
        """Return the last N gateway decisions for UI history replay."""
        cursor = await self._conn.execute(
            "SELECT event_id, timestamp, agent_id, session_id, tool, direction,"
            " decision, policy_rule, latency_ms, incident_id"
            " FROM events ORDER BY timestamp DESC LIMIT ?",
            (min(limit, 200),),
        )
        rows = await cursor.fetchall()
        return [
            {
                "event_id": r[0], "timestamp": r[1], "agent_id": r[2],
                "session_id": r[3], "tool": r[4], "direction": r[5],
                "decision": r[6], "rule": r[7], "latency_ms": r[8],
                "incident_id": r[9],
            }
            for r in rows
        ]

    async def recent_incidents(self, limit: int = 20) -> list[dict]:
        """Return the last N incidents for the UI incidents panel."""
        cursor = await self._conn.execute(
            "SELECT incident_id, timestamp, agent_id, session_id, attack_type,"
            " evidence, confidence, detection_method, decision, status"
            " FROM incidents ORDER BY timestamp DESC LIMIT ?",
            (min(limit, 100),),
        )
        rows = await cursor.fetchall()
        return [
            {
                "incident_id": r[0], "timestamp": r[1], "agent_id": r[2],
                "session_id": r[3], "attack_type": r[4], "evidence": r[5],
                "confidence": r[6], "detection_method": r[7],
                "decision": r[8], "status": r[9],
            }
            for r in rows
        ]

    async def quarantined_session_count(self) -> int:
        """Number of currently persisted quarantined sessions."""
        cursor = await self._conn.execute(
            "SELECT COUNT(*) FROM sessions WHERE quarantined = 1"
        )
        row = await cursor.fetchone()
        return (row[0] or 0) if row else 0

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

    # ── Policy file integrity (ADR-0026 layer 1) ─────────────────────────────

    async def record_policy_hash(self, path: str, sha256_hash: str) -> None:
        """Upsert the policy file hash. Called at gateway startup."""
        now = SecurityContext.now()
        await self._conn.execute(
            "INSERT OR REPLACE INTO policy_checksums (path, sha256_hash, recorded_at)"
            " VALUES (?, ?, ?)",
            (path, sha256_hash, now),
        )
        await self._conn.commit()

    async def check_policy_hash(self, path: str, current_hash: str) -> tuple[str, str | None]:
        """Compare *current_hash* to the stored hash for *path*.

        Returns ``(status, stored_hash)`` where status is one of:
        - ``"new"``       — no stored hash; caller should call record_policy_hash.
        - ``"unchanged"`` — hashes match; policy untouched.
        - ``"changed"``   — hashes differ; policy was modified since last run.
        """
        cursor = await self._conn.execute(
            "SELECT sha256_hash FROM policy_checksums WHERE path = ?", (path,)
        )
        row = await cursor.fetchone()
        if row is None:
            return "new", None
        stored = row[0]
        if stored == current_hash:
            return "unchanged", stored
        return "changed", stored

    # ── Audit chain verification (ADR-0026 layer 2) ──────────────────────────

    async def verify_audit_chain(self) -> AuditChainStatus:
        """Walk the entire audit chain and verify every hash link.

        Detects deleted rows (missing prev_hash links), modified rows (hash
        mismatch), and inserted-out-of-order rows (wrong prev_hash value).
        O(n) in the number of events; for post-mortem / operator use only.
        """
        cursor = await self._conn.execute(
            "SELECT ac.event_id, ac.prev_hash, ac.row_hash,"
            "       e.decision, e.timestamp"
            " FROM audit_chain ac"
            " JOIN events e USING (event_id)"
            " ORDER BY ac.rowid"
        )
        rows = await cursor.fetchall()
        chained = len(rows)

        total_cursor = await self._conn.execute("SELECT COUNT(*) FROM events")
        total_row = await total_cursor.fetchone()
        total = (total_row[0] or 0) if total_row else 0

        if chained == 0:
            return AuditChainStatus(
                ok=True, total_events=total, chained_events=0,
                broken_at_event_id=None, detail="no events in chain"
            )

        expected_prev = _CHAIN_GENESIS
        for event_id, prev_hash, stored_row_hash, decision, timestamp in rows:
            if prev_hash != expected_prev:
                return AuditChainStatus(
                    ok=False, total_events=total, chained_events=chained,
                    broken_at_event_id=event_id,
                    detail=(
                        f"prev_hash mismatch at {event_id}: "
                        f"expected {expected_prev[:16]}…, got {prev_hash[:16]}…"
                    ),
                )
            expected = _chain_hash(event_id, decision, timestamp, prev_hash)
            if expected != stored_row_hash:
                return AuditChainStatus(
                    ok=False, total_events=total, chained_events=chained,
                    broken_at_event_id=event_id,
                    detail=(
                        f"row_hash mismatch at {event_id}: "
                        f"expected {expected[:16]}…, got {stored_row_hash[:16]}…"
                    ),
                )
            expected_prev = stored_row_hash

        return AuditChainStatus(
            ok=True, total_events=total, chained_events=chained,
            broken_at_event_id=None,
            detail=f"all {chained} chain links verified",
        )
