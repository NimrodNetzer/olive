"""The runtime Builder department (ADR-0018).

VISION department 3 as a runtime component: it reacts to CONFIRMED weaknesses on
the incident bus and turns each novel one into a bounded, auditable *fix-proposal*
artifact, then publishes a `fix-proposed` object so the org (and the UI) are
aware. It closes the gap between ADR-0016 (red-team finds a bypass) and ADR-0013
(a human drives `olive cycle` to ship a fix) — without granting any LLM authority.

THE SAFETY GUARANTEE IS STRUCTURAL (ADR-0018 §2). This module PROPOSES; it never
APPLIES. It deliberately does not import `gateway.proxy`, `gateway.upstreams`,
`gateway.breaker`, or `mcp.ClientSession`, and never calls `breaker.trip` /
`set_mode` / `olive cycle` / a baseline update. Its only outputs are a
`builder_proposals` row and a `fix-proposed` bus object. A test asserts that
import set. Adding autonomy (unattended reaction) adds reach to PROPOSE, never to
ENFORCE.

The actual diff is authored by the build-time `.claude/agents/builder.md`
(ADR-0013); at runtime no diff is written (`patch_hash` is null) and no LLM output
is interpolated into an enforcement artifact (ADR-0005). A proposal is inert data
until a human walks the fix through `olive cycle` (the gate is unchanged).

No feedback loop (ADR-0018 §6): the department subscribes to `redteam-finding` and
`reproduced` ONLY — never to `fix-proposed` — so a proposal can never re-trigger
the department. `fix-proposed` carries confidence 0.0 and the Commander reads only
`detection`, so a proposal can never move the operating mode. Spam is bounded by
novelty: `finding_key` is UNIQUE, so a steady state publishes nothing.
"""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import aiosqlite

from olive.intelligence.bus import IncidentBus, IncidentObject
from olive.intelligence.reporter import IncidentReport

_SUMMARY_MAX = 200  # rule 3: bounded evidence excerpt

# The two confirmed-weakness kinds the Builder reacts to. A bare `detection` has no
# committed corpus case yet, so a proposal for it would be vague (ADR-0018 §1); it
# reaches the Builder only once reproduced.
_TRIGGER_KINDS = ("redteam-finding", "reproduced")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS builder_proposals (
    proposal_id     TEXT PRIMARY KEY,
    object_id       TEXT,
    incident_id     TEXT,
    corpus_case_id  TEXT,
    finding_key     TEXT NOT NULL UNIQUE,
    patch_hash      TEXT,
    summary         TEXT NOT NULL,
    status          TEXT NOT NULL,
    created_at      TEXT NOT NULL
);
"""


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _persisted_evidence(report: IncidentReport) -> str:
    """The evidence string exactly as the bus persists it (bus._persist). Computing
    a finding's key from THIS form makes the live path and the history-replay path
    derive identical keys, so dedup holds across both."""
    return "; ".join(
        f"{s.get('sentinel', '?')}: {s.get('evidence', '')}" for s in report.signals
    )[:_SUMMARY_MAX]


def _finding_key(*, corpus_case_id: str | None, incident_id: str | None, evidence: str) -> str:
    """A stable per-weakness dedup key derived only from persisted-stable fields.
    Prefer a concrete handle (corpus case, then incident); else hash the bounded
    evidence. Never includes a raw payload (evidence is already rule-3 bounded)."""
    if corpus_case_id:
        return f"case:{corpus_case_id}"
    if incident_id:
        return f"incident:{incident_id}"
    return "ev:" + hashlib.sha256(evidence.encode("utf-8")).hexdigest()[:16]


def _proposal_report(summary: str, attack_types: list[str]) -> IncidentReport:
    """A rule-3 envelope for a fix-proposal: the bounded summary only, never a diff
    or payload. confidence 0.0 - a proposal is not a threat signal and must never
    move the operating mode (ADR-0018 §6)."""
    return IncidentReport(
        session_key="",
        agent_id="builder",
        organization_id="",
        confidence=0.0,
        attack_types=attack_types,
        action="fix-proposed",
        signals=[{"sentinel": "builder", "confidence": 0.0, "evidence": summary[:_SUMMARY_MAX]}],
        incident_id=None,
    )


@dataclass(frozen=True, slots=True)
class Proposal:
    proposal_id: str
    object_id: str | None
    incident_id: str | None
    corpus_case_id: str | None
    finding_key: str
    patch_hash: str | None
    summary: str
    status: str
    created_at: str


class ProposalLedger:
    """Single authority over the `builder_proposals` table (own aiosqlite, same DB
    file - the RemediationLedger precedent). Append-only here: a runtime proposal is
    created in 'proposed' and stays there; promotion is the human `olive cycle`."""

    def __init__(self, path: str | Path) -> None:
        self._path = str(path)
        self._db: aiosqlite.Connection | None = None
        # Serializes id derivation + insert so concurrent proposes cannot race to
        # the same PRP-NNNN (the on-demand replay may run beside the live path).
        self._lock = asyncio.Lock()

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
            raise RuntimeError("ProposalLedger is not open")
        return self._db

    async def record_if_novel(
        self,
        *,
        finding_key: str,
        summary: str,
        object_id: str | None = None,
        incident_id: str | None = None,
        corpus_case_id: str | None = None,
    ) -> Proposal | None:
        """Create a 'proposed' row for a NOVEL weakness; return it. If a proposal
        for this `finding_key` already exists, insert nothing and return None (the
        dedup that bounds proposal-spam, ADR-0018 §6). `patch_hash` is null: the
        runtime department authors no diff (ADR-0018 §3)."""
        async with self._lock:
            cursor = await self._conn.execute(
                "INSERT OR IGNORE INTO builder_proposals"
                " (proposal_id, object_id, incident_id, corpus_case_id, finding_key,"
                "  patch_hash, summary, status, created_at)"
                " VALUES ((SELECT 'PRP-' || printf('%04d', COUNT(*) + 1) FROM builder_proposals),"
                " ?, ?, ?, ?, NULL, ?, 'proposed', ?) RETURNING proposal_id",
                (
                    object_id,
                    incident_id,
                    corpus_case_id,
                    finding_key,
                    summary[:_SUMMARY_MAX],
                    _now(),
                ),
            )
            row = await cursor.fetchone()
            await self._conn.commit()
        if row is None:
            return None  # UNIQUE(finding_key) conflict - already proposed
        return await self.get(row[0])

    async def get(self, proposal_id: str) -> Proposal:
        cursor = await self._conn.execute(
            "SELECT proposal_id, object_id, incident_id, corpus_case_id, finding_key,"
            " patch_hash, summary, status, created_at FROM builder_proposals"
            " WHERE proposal_id = ?",
            (proposal_id,),
        )
        row = await cursor.fetchone()
        if row is None:
            raise RuntimeError(f"unknown proposal {proposal_id}")
        return Proposal(*row)

    async def list_proposals(self) -> list[Proposal]:
        cursor = await self._conn.execute(
            "SELECT proposal_id FROM builder_proposals ORDER BY proposal_id"
        )
        return [await self.get(r[0]) for r in await cursor.fetchall()]


class BuilderDepartment:
    """Reacts to confirmed weaknesses and emits bounded fix-proposals. PUBLISHES
    `fix-proposed`; subscribes ONLY to `redteam-finding`/`reproduced` (never to its
    own output - the feedback loop is structurally absent, ADR-0018 §6)."""

    def __init__(self, bus: IncidentBus, ledger: ProposalLedger) -> None:
        self._bus = bus
        self._ledger = ledger
        self._running = False  # single-flight guard for the on-demand replay
        self.proposals_published = 0

    def subscribe(self) -> None:
        """Wire the live path: one handler per confirmed-weakness kind. NEVER
        subscribes to `fix-proposed` (no self-trigger)."""
        for kind in _TRIGGER_KINDS:
            self._bus.subscribe(self.handle, kind=kind)

    async def handle(self, obj: IncidentObject) -> None:
        """Live bus handler: propose for this weakness if novel."""
        await self._propose(
            kind=obj.kind,
            object_id=obj.object_id,
            incident_id=obj.incident_id,
            corpus_case_id=obj.corpus_case_id,
            attack_types=list(obj.report.attack_types),
            evidence=_persisted_evidence(obj.report),
        )

    async def run_once(self) -> int | None:
        """On-demand (operator/CI) trigger: replay the bus history and propose for
        every NOVEL confirmed weakness. Returns the count published, or None if a
        replay is already in flight (single-flight). Idempotent: dedup makes a
        re-run a no-op."""
        if self._running:
            return None
        self._running = True
        try:
            published = 0
            for row in await self._bus.history():
                if row["kind"] not in _TRIGGER_KINDS:
                    continue
                attack_types = row["attack_types"].split(",") if row["attack_types"] else []
                proposal = await self._propose(
                    kind=row["kind"],
                    object_id=row["object_id"],
                    incident_id=row["incident_id"],
                    corpus_case_id=row["corpus_case_id"],
                    attack_types=attack_types,
                    evidence=row["evidence"] or "",
                )
                if proposal is not None:
                    published += 1
            return published
        finally:
            self._running = False

    async def _propose(
        self,
        *,
        kind: str,
        object_id: str | None,
        incident_id: str | None,
        corpus_case_id: str | None,
        attack_types: list[str],
        evidence: str,
    ) -> Proposal | None:
        """Record a novel proposal and publish a `fix-proposed` object. Returns the
        proposal, or None if this weakness was already proposed (dedup). No
        enforcement happens here (ADR-0018 §2): the only writes are the ledger row
        and the bus object."""
        key = _finding_key(
            corpus_case_id=corpus_case_id, incident_id=incident_id, evidence=evidence
        )
        summary = f"fix needed for {kind} [{key}]: {evidence}"[:_SUMMARY_MAX]
        proposal = await self._ledger.record_if_novel(
            finding_key=key,
            summary=summary,
            object_id=object_id,
            incident_id=incident_id,
            corpus_case_id=corpus_case_id,
        )
        if proposal is None:
            return None
        obj = self._bus.make_object(
            kind="fix-proposed",
            source_dept="builder",
            report=_proposal_report(summary, attack_types),
            incident_id=incident_id,
            corpus_case_id=corpus_case_id,
        )
        await self._bus.publish(obj)
        self.proposals_published += 1
        return proposal
