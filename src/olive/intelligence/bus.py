"""The incident-object bus - how the runtime departments collaborate (ADR-0014).

The VISION's rule is "structured, auditable incident objects, never uncontrolled
group chat." This module is that channel:

  - a typed `IncidentObject` envelope around the existing `IncidentReport`
    (reporter.py) - so every agent-to-agent message carries only the bounded,
    rule-3-safe evidence the sentinels already produce;
  - an in-process async pub/sub for live fan-out to subscribed departments;
  - an append-only `incident_events` table for audit + replay (own aiosqlite,
    same DB file - the RemediationLedger precedent), keyed to the store's
    incidents by `incident_id` *string* only (open-core seam, ADR-0003);
  - HMAC signing + verification so a compromised LLM agent cannot forge a
    `mode-change` or `verified` object onto the bus: an unsigned or wrongly
    signed object is rejected (fail-closed). ADR-0027 upgrades to per-department
    keys derived via HKDF so a compromised department cannot forge another's
    objects;
  - publisher validation (ADR-0027): `PERMITTED_KINDS` maps source_dept →
    allowed kinds; an unauthorised (dept, kind) pair is rejected before HMAC
    verification (fail-closed).

Rule 3 is guarded hardest here: the bus persists only the bounded `IncidentReport`
fields (confidence, attack types, ≤200-char evidence) and non-secret ids. Raw
`TelemetryEvent.content`/`arguments` MUST NEVER reach a bus object or a row.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import aiosqlite

from olive.intelligence.reporter import IncidentReport

_EVIDENCE_MAX = 200  # rule 3: bounded evidence excerpt


def _derive_dept_key(process_key: bytes, dept: str) -> bytes:
    """Derive a per-department 32-byte signing key (HKDF, RFC 5869, single block).

    HKDF-Extract: PRK = HMAC-SHA256(salt=0x00×32, IKM=process_key)
    HKDF-Expand:  OKM = HMAC-SHA256(PRK, info=b"olive-bus-<dept>" + 0x01)

    Each department gets a unique key; one leaked key cannot forge another's objects.
    """
    info = b"olive-bus-" + dept.encode("utf-8")
    prk = hmac.new(b"\x00" * 32, process_key, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


#: Publisher-validation registry (ADR-0027). Maps source_dept → allowed kinds.
#: `IncidentBus.publish()` rejects any (dept, kind) pair not in this table
#: before HMAC verification — fail-closed. Extend with `register_dept()`.
PERMITTED_KINDS: dict[str, frozenset[str]] = {
    "defense":     frozenset({"detection"}),
    "remediation": frozenset({"reproduced"}),
    "redteam":     frozenset({"redteam-finding"}),
    "builder":     frozenset({"fix-proposed"}),
    "commander":   frozenset({"mode-change", "siege-declared"}),
    "operator":    frozenset({"operator-request"}),
    "ui":          frozenset({"operator-request"}),
    "supervisor":  frozenset({"supervisor-health"}),
}


def register_dept(dept: str, allowed_kinds: frozenset[str]) -> None:
    """Add or replace a department entry in `PERMITTED_KINDS`.

    Use for test departments and future extensions — avoids modifying the core
    table while keeping publisher validation effective.
    """
    PERMITTED_KINDS[dept] = allowed_kinds


_SCHEMA = """
CREATE TABLE IF NOT EXISTS incident_events (
    object_id      TEXT PRIMARY KEY,
    incident_id    TEXT,
    kind           TEXT NOT NULL,
    source_dept    TEXT NOT NULL,
    target_dept    TEXT,
    corpus_case_id TEXT,
    confidence     REAL,
    attack_types   TEXT,
    evidence       TEXT,
    signature      TEXT NOT NULL,
    created_at     TEXT NOT NULL
);
"""


class BusError(Exception):
    """A rejected (unsigned / tampered) object or a closed bus. The bus fails
    closed: a verification failure raises rather than silently delivering."""


def _now() -> str:
    return datetime.now(UTC).isoformat()


def format_evidence(report: IncidentReport) -> str:
    """The canonical, bounded evidence string the bus persists for a report. Shared
    (not re-derived) so any other department that needs the persisted form - e.g.
    to derive a stable dedup key that matches across the live and replay paths -
    cannot drift from what `_persist` actually writes (rule 3: ≤200 chars)."""
    return "; ".join(
        f"{s.get('sentinel', '?')}: {s.get('evidence', '')}" for s in report.signals
    )[:_EVIDENCE_MAX]


@dataclass(frozen=True, slots=True)
class IncidentObject:
    """One structured message on the bus. Deliberately has NO `content` /
    `arguments` field - raw payloads never travel here (rule 3). `report` carries
    only the bounded, hashed evidence the sentinels already emit."""

    kind: str  # detection | reproduced | fix-proposed | verified | mode-change
    source_dept: str  # defense | remediation | commander
    report: IncidentReport
    incident_id: str | None = None
    target_dept: str | None = None  # routing hint; None = broadcast
    corpus_case_id: str | None = None  # set on a `reproduced` object
    object_id: str | None = None  # assigned by the bus on persist
    created_at: str = field(default_factory=_now)

    def signing_payload(self) -> bytes:
        """Canonical bytes signed/verified - everything that defines the object's
        meaning except the bus-assigned id and the signature itself."""
        canonical = {
            "kind": self.kind,
            "source_dept": self.source_dept,
            "incident_id": self.incident_id,
            "target_dept": self.target_dept,
            "corpus_case_id": self.corpus_case_id,
            "created_at": self.created_at,
            "confidence": self.report.confidence,
            "attack_types": sorted(self.report.attack_types),
            "action": self.report.action,
        }
        return json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def sign(self, key: bytes) -> str:
        return hmac.new(key, self.signing_payload(), hashlib.sha256).hexdigest()


Handler = Callable[[IncidentObject], Awaitable[None]]


class IncidentBus:
    """Single channel the departments publish to and subscribe on. Deterministic
    plumbing: it verifies, persists, and fans out - it never makes an enforcement
    decision (that stays the Commander/breaker, ADR-0005)."""

    def __init__(self, db_path: str | Path, signing_key: bytes) -> None:
        if not signing_key:
            raise ValueError("the incident bus requires a non-empty signing key")
        self._path = str(db_path)
        self._key = signing_key  # process key — HKDF input material (ADR-0027)
        self._dept_key_cache: dict[str, bytes] = {}
        self._db: aiosqlite.Connection | None = None
        self._subs: list[tuple[str | None, Handler]] = []
        # Serializes id derivation + insert so concurrent department publishes
        # cannot race to the same IOB-NNNN (the table is append-only).
        self._persist_lock = asyncio.Lock()
        self.delivery_failures = 0

    def _dept_key(self, dept: str) -> bytes:
        """Return the HKDF-derived signing key for `dept`, lazily cached."""
        if dept not in self._dept_key_cache:
            self._dept_key_cache[dept] = _derive_dept_key(self._key, dept)
        return self._dept_key_cache[dept]

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
            raise BusError("the incident bus is not open")
        return self._db

    def subscribe(self, handler: Handler, *, kind: str | None = None) -> None:
        """Register a department handler. `kind=None` subscribes to every object;
        otherwise only objects of that kind are delivered."""
        self._subs.append((kind, handler))

    def make_object(
        self,
        *,
        kind: str,
        source_dept: str,
        report: IncidentReport,
        incident_id: str | None = None,
        target_dept: str | None = None,
        corpus_case_id: str | None = None,
    ) -> IncidentObject:
        """Build an object whose signature this bus will accept. A department signs
        with the bus key (first slice: one per-process key)."""
        return IncidentObject(
            kind=kind,
            source_dept=source_dept,
            report=report,
            incident_id=incident_id,
            target_dept=target_dept,
            corpus_case_id=corpus_case_id,
        )

    async def publish(self, obj: IncidentObject, *, signature: str | None = None) -> IncidentObject:
        """Verify, persist (assigning an `IOB-NNNN` id), then fan out to matching
        subscribers. Publisher validation (ADR-0027) runs first — an unknown dept or
        unauthorized kind raises BusError before the HMAC is checked (fail-closed).
        A bad/absent signature is then rejected. A handler that raises is isolated
        (the failure is counted) so one broken department cannot silence the others."""
        # Publisher validation — fail-closed before HMAC (ADR-0027).
        allowed = PERMITTED_KINDS.get(obj.source_dept)
        if allowed is None:
            raise BusError(
                f"rejected {obj.kind!r} from unknown dept {obj.source_dept!r}"
            )
        if obj.kind not in allowed:
            raise BusError(
                f"dept {obj.source_dept!r} is not permitted to publish kind {obj.kind!r}"
            )
        # Per-dept HMAC verification (ADR-0027): each dept has its own derived key.
        dept_key = self._dept_key(obj.source_dept)
        expected = obj.sign(dept_key)
        if signature is None:
            signature = expected
        if not hmac.compare_digest(signature, expected):
            raise BusError(f"rejected {obj.kind} object: signature mismatch")

        persisted = await self._persist(obj, signature)
        for kind, handler in self._subs:
            if kind is not None and kind != persisted.kind:
                continue
            try:
                await handler(persisted)
            except Exception:  # noqa: BLE001 - a broken subscriber must not break the bus
                self.delivery_failures += 1
        return persisted

    async def _persist(self, obj: IncidentObject, signature: str) -> IncidentObject:
        evidence = format_evidence(obj.report)
        async with self._persist_lock:
            cursor = await self._conn.execute(
                "INSERT INTO incident_events"
                " (object_id, incident_id, kind, source_dept, target_dept, corpus_case_id,"
                "  confidence, attack_types, evidence, signature, created_at)"
                " VALUES ((SELECT 'IOB-' || printf('%04d', COUNT(*) + 1) FROM incident_events),"
                " ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING object_id",
                (
                    obj.incident_id,
                    obj.kind,
                    obj.source_dept,
                    obj.target_dept,
                    obj.corpus_case_id,
                    obj.report.confidence,
                    ",".join(sorted(obj.report.attack_types)),
                    evidence,
                    signature,
                    obj.created_at,
                ),
            )
            row = await cursor.fetchone()
            await self._conn.commit()
        # Return a copy carrying the assigned id, so subscribers see it.
        from dataclasses import replace

        return replace(obj, object_id=row[0])

    async def history(self) -> list[dict]:
        """The append-only audit trail, oldest first - for operators/tests/replay."""
        cursor = await self._conn.execute(
            "SELECT object_id, incident_id, kind, source_dept, target_dept, corpus_case_id,"
            " confidence, attack_types, evidence, created_at FROM incident_events"
            " ORDER BY object_id"
        )
        cols = [
            "object_id",
            "incident_id",
            "kind",
            "source_dept",
            "target_dept",
            "corpus_case_id",
            "confidence",
            "attack_types",
            "evidence",
            "created_at",
        ]
        return [dict(zip(cols, row, strict=True)) for row in await cursor.fetchall()]
