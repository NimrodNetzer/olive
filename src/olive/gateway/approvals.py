"""Approval registry - deterministic human-in-the-loop release of held calls
(ADR-0010).

A `hold` verdict pauses a specific call (this session, this tool, these exact
arguments). The registry records that pending hold under a stable key and hands
back an operator-referenceable approval id. An operator with the `olive:approve`
capability marks it approved; the next matching call consumes the approval
(one-shot) and proceeds. Like the circuit breaker, this is the single authority
over its in-memory state, guarded by one lock - and it is pure deterministic
code: no LLM may approve (ADR-0005), and approval can only release a hold the
deterministic rules already produced, never grant a call those rules denied.

No store/intelligence imports (ADR-0003): the registry returns plain values and
the proxy does the logging. State is in-memory/per-process for now; a durable
`pending_approvals` table is a later increment if cross-restart approval is
needed.
"""

from __future__ import annotations

import asyncio
import hashlib
import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from time import monotonic


def approval_key(session_key: str, tool: str, arguments_hash: str) -> str:
    """Stable identity of one held call: the (session, tool, exact-arguments)
    triple. Approving is therefore specific to one concrete call, not a blanket
    pass for the tool - a different argument set re-holds."""
    raw = f"{session_key}\x1f{tool}\x1f{arguments_hash}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"


@dataclass(slots=True)
class PendingApproval:
    approval_id: str
    key: str
    session_key: str
    tool: str
    arguments_hash: str
    rule: str | None
    status: ApprovalStatus = ApprovalStatus.PENDING
    created_at: float = field(default_factory=monotonic)


class ApprovalRegistry:
    def __init__(self) -> None:
        self._by_key: dict[str, PendingApproval] = {}
        self._by_id: dict[str, PendingApproval] = {}
        self._lock = asyncio.Lock()

    async def register(
        self, key: str, session_key: str, tool: str, arguments_hash: str, rule: str | None
    ) -> str:
        """Record a held call as pending (idempotent per key) and return its
        approval id. A repeat hold of the same call returns the existing id, so
        an operator never chases a moving target."""
        async with self._lock:
            existing = self._by_key.get(key)
            if existing is not None:
                return existing.approval_id
            approval_id = f"APR-{uuid.uuid4().hex[:8]}"
            entry = PendingApproval(
                approval_id=approval_id,
                key=key,
                session_key=session_key,
                tool=tool,
                arguments_hash=arguments_hash,
                rule=rule,
            )
            self._by_key[key] = entry
            self._by_id[approval_id] = entry
            return approval_id

    async def approve(self, approval_id: str) -> bool:
        """Mark a pending hold approved. Returns False for an unknown id. The
        capability check (`olive:approve`) is enforced by the caller (the admin
        surface), mirroring session release."""
        async with self._lock:
            entry = self._by_id.get(approval_id)
            if entry is None:
                return False
            entry.status = ApprovalStatus.APPROVED
            return True

    async def consume(self, key: str) -> bool:
        """One-shot: if this exact call has been approved, remove the record and
        return True so it may proceed once. A pending (un-approved) hold returns
        False and is left in place."""
        async with self._lock:
            entry = self._by_key.get(key)
            if entry is None or entry.status is not ApprovalStatus.APPROVED:
                return False
            del self._by_key[key]
            del self._by_id[entry.approval_id]
            return True

    def pending(self) -> list[PendingApproval]:
        """Read-only snapshot for operators/tests. Not an enforcement path."""
        return list(self._by_id.values())
