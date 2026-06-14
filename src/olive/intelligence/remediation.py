"""Remediation cycle ledger - the first department loop (ADR-0013).

Walks a single incident through the back half of the VISION security cycle:

    reproduced -> fix-proposed -> verified -> approved -> learned
                              \\-> rejected (gate failed or human declined)

The ledger is a deterministic, auditable state machine. Its two consequential
transitions cannot be reached by an LLM:

  - VERIFY is writable only from a recorded gate result (the CLI runs the real
    `evals/run_evals.py` gate; there is no path to inject a passing result).
  - APPROVE is human-and-capability-gated; LEARN refuses unless an approval is
    already recorded. This extends ADR-0005 (agents advise, deterministic code
    and humans enforce) to the remediation loop.

Open-core seam (ADR-0003): this module lives on the intelligence side and owns
its own aiosqlite access to the same DB file. It references the incident by its
`incident_id` string only - it never imports the gateway/store enforcement code
into a dependency cycle, and the gateway core never imports this module. The CLI
(`olive cycle ...`), the composition root, wires it in with a local import.

Rule 3: only hashes + bounded text are persisted. The proposed diff lives in
version control; the ledger stores its SHA-256 and a bounded one-line summary -
never the diff body, never a raw payload.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

import aiosqlite

_SUMMARY_MAX = 200  # rule 3: bounded evidence excerpt

_SCHEMA = """
CREATE TABLE IF NOT EXISTS remediation_cycles (
    cycle_id        TEXT PRIMARY KEY,
    incident_id     TEXT NOT NULL,
    corpus_case_id  TEXT NOT NULL,
    state           TEXT NOT NULL,
    patch_hash      TEXT,
    patch_summary   TEXT,
    gate_detected   INTEGER,
    gate_false_pos  INTEGER,
    gate_passed     INTEGER,
    approved_by     TEXT,
    approved_at     TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);
"""


class RemediationState(StrEnum):
    REPRODUCED = "reproduced"  # incident reproduced as a known-miss corpus case
    FIX_PROPOSED = "fix-proposed"  # builder proposed a patch (hash recorded)
    VERIFIED = "verified"  # the deterministic eval gate passed on the fix
    APPROVED = "approved"  # a human with olive:remediate approved the fix
    LEARNED = "learned"  # baseline locked the win in (terminal)
    REJECTED = "rejected"  # gate failed or a human declined (terminal)


_TERMINAL = {RemediationState.LEARNED, RemediationState.REJECTED}


class RemediationError(Exception):
    """An invalid transition or unknown cycle. The CLI maps this to a non-zero
    exit - the loop fails closed (CLAUDE.md rule 4), it never silently advances."""


def hash_patch(patch_path: str | Path) -> str:
    """SHA-256 of the proposed diff file. The diff body is never stored; only
    this fingerprint, so an approver can confirm the exact patch that shipped."""
    return hashlib.sha256(Path(patch_path).read_bytes()).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(frozen=True, slots=True)
class RemediationCycle:
    cycle_id: str
    incident_id: str
    corpus_case_id: str
    state: RemediationState
    patch_hash: str | None
    patch_summary: str | None
    gate_detected: int | None
    gate_false_pos: int | None
    gate_passed: int | None
    approved_by: str | None
    approved_at: str | None
    created_at: str
    updated_at: str

    def render(self) -> str:
        lines = [
            f"[cycle] {self.cycle_id} state={self.state} "
            f"incident={self.incident_id} case={self.corpus_case_id}",
        ]
        if self.patch_hash:
            lines.append(f"  patch={self.patch_hash[:16]}... summary={self.patch_summary}")
        if self.gate_passed is not None:
            lines.append(
                f"  gate: passed={bool(self.gate_passed)} "
                f"detected={self.gate_detected} false_pos={self.gate_false_pos}"
            )
        if self.approved_by:
            lines.append(f"  approved_by={self.approved_by} at={self.approved_at}")
        return "\n".join(lines)


class RemediationLedger:
    """Single authority over the `remediation_cycles` table. Every method is a
    guarded transition: it reads the current state, refuses an illegal move
    (RemediationError), and writes the next state with a fresh `updated_at`."""

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
            raise RuntimeError("RemediationLedger is not open")
        return self._db

    async def open_cycle(self, incident_id: str, corpus_case_id: str) -> RemediationCycle:
        """Start a cycle in REPRODUCED: the red-team agent has turned the incident
        into a known-miss corpus case. The cycle id is derived inside the INSERT so
        concurrent opens cannot race to the same number (mirrors incidents)."""
        if not incident_id or not corpus_case_id:
            raise RemediationError("open requires both an incident id and a corpus case id")
        now = _now()
        cursor = await self._conn.execute(
            "INSERT INTO remediation_cycles"
            " (cycle_id, incident_id, corpus_case_id, state, created_at, updated_at)"
            " VALUES ((SELECT 'CYC-' || printf('%04d', COUNT(*) + 1) FROM remediation_cycles),"
            " ?, ?, ?, ?, ?) RETURNING cycle_id",
            (incident_id, corpus_case_id, RemediationState.REPRODUCED, now, now),
        )
        row = await cursor.fetchone()
        await self._conn.commit()
        return await self.get(row[0])

    async def propose_fix(
        self, cycle_id: str, *, patch_hash: str, patch_summary: str
    ) -> RemediationCycle:
        """REPRODUCED -> FIX_PROPOSED. Records the patch fingerprint + a bounded
        summary. No enforcement happens here; the builder only proposes."""
        cycle = await self._require(cycle_id, RemediationState.REPRODUCED)
        await self._advance(
            cycle.cycle_id,
            RemediationState.FIX_PROPOSED,
            patch_hash=patch_hash,
            patch_summary=patch_summary[:_SUMMARY_MAX],
        )
        return await self.get(cycle_id)

    async def record_verification(
        self, cycle_id: str, *, gate_passed: bool, detected: int, false_positives: int
    ) -> RemediationCycle:
        """FIX_PROPOSED -> VERIFIED (gate passed) or -> REJECTED (gate failed).

        This is the only path to VERIFIED. The CLI calls it with the *real* exit
        code and counts from the deterministic eval gate; there is no flag to
        forge a pass, and no agent can reach this transition (ADR-0013)."""
        cycle = await self._require(cycle_id, RemediationState.FIX_PROPOSED)
        next_state = RemediationState.VERIFIED if gate_passed else RemediationState.REJECTED
        await self._advance(
            cycle.cycle_id,
            next_state,
            gate_detected=detected,
            gate_false_pos=false_positives,
            gate_passed=int(gate_passed),
        )
        return await self.get(cycle_id)

    async def approve(self, cycle_id: str, *, approved_by: str) -> RemediationCycle:
        """VERIFIED -> APPROVED. The capability check (olive:remediate) is enforced
        by the caller against a verified token; `approved_by` is the verified
        identity. No LLM may reach this state (ADR-0005)."""
        if not approved_by:
            raise RemediationError("approval requires a verified approver identity")
        cycle = await self._require(cycle_id, RemediationState.VERIFIED)
        await self._advance(
            cycle.cycle_id,
            RemediationState.APPROVED,
            approved_by=approved_by,
            approved_at=_now(),
        )
        return await self.get(cycle_id)

    async def learn(self, cycle_id: str) -> RemediationCycle:
        """APPROVED -> LEARNED. Refuses unless an approval is recorded - this is
        the mandatory human gate before the baseline is locked in. The caller runs
        `--update-baseline` only after this transition succeeds."""
        cycle = await self._require(cycle_id, RemediationState.APPROVED)
        if not cycle.approved_by:
            # Defence in depth: APPROVED should always carry an approver, but never
            # lock a baseline win in without one.
            raise RemediationError("cannot learn: no recorded approval")
        await self._advance(cycle.cycle_id, RemediationState.LEARNED)
        return await self.get(cycle_id)

    async def reject(self, cycle_id: str) -> RemediationCycle:
        """Human decline from FIX_PROPOSED or VERIFIED -> REJECTED (terminal)."""
        cycle = await self.get(cycle_id)
        if cycle.state in _TERMINAL:
            raise RemediationError(f"{cycle_id} is already {cycle.state}; cannot reject")
        if cycle.state not in (RemediationState.FIX_PROPOSED, RemediationState.VERIFIED):
            raise RemediationError(
                f"{cycle_id} is {cycle.state}; only a proposed or verified cycle can be rejected"
            )
        await self._advance(cycle.cycle_id, RemediationState.REJECTED)
        return await self.get(cycle_id)

    async def get(self, cycle_id: str) -> RemediationCycle:
        cursor = await self._conn.execute(
            "SELECT cycle_id, incident_id, corpus_case_id, state, patch_hash, patch_summary,"
            " gate_detected, gate_false_pos, gate_passed, approved_by, approved_at,"
            " created_at, updated_at FROM remediation_cycles WHERE cycle_id = ?",
            (cycle_id,),
        )
        row = await cursor.fetchone()
        if row is None:
            raise RemediationError(f"unknown cycle {cycle_id}")
        return RemediationCycle(
            cycle_id=row[0],
            incident_id=row[1],
            corpus_case_id=row[2],
            state=RemediationState(row[3]),
            patch_hash=row[4],
            patch_summary=row[5],
            gate_detected=row[6],
            gate_false_pos=row[7],
            gate_passed=row[8],
            approved_by=row[9],
            approved_at=row[10],
            created_at=row[11],
            updated_at=row[12],
        )

    async def list_cycles(self) -> list[RemediationCycle]:
        cursor = await self._conn.execute(
            "SELECT cycle_id FROM remediation_cycles ORDER BY cycle_id"
        )
        rows = await cursor.fetchall()
        return [await self.get(r[0]) for r in rows]

    async def _require(self, cycle_id: str, expected: RemediationState) -> RemediationCycle:
        cycle = await self.get(cycle_id)
        if cycle.state is not expected:
            raise RemediationError(f"{cycle_id} is {cycle.state}; this step requires {expected}")
        return cycle

    async def _advance(self, cycle_id: str, state: RemediationState, **fields: object) -> None:
        sets = ["state = ?", "updated_at = ?"]
        params: list[object] = [state, _now()]
        for col, val in fields.items():
            sets.append(f"{col} = ?")
            params.append(val)
        params.append(cycle_id)
        await self._conn.execute(
            f"UPDATE remediation_cycles SET {', '.join(sets)} WHERE cycle_id = ?", params
        )
        await self._conn.commit()
