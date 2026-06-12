"""Inspector pipeline - the deterministic fast path.

Inspectors are pure plugins. The pipeline runs the ones matching the message
direction in order; the first non-allow verdict short-circuits. Any inspector
exception yields a BLOCK verdict (fail closed, CLAUDE.md rule 4) - content
must never pass uninspected because a component broke.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable

from olive.gateway.context import Direction, SecurityContext

EVIDENCE_LIMIT = 200


class Decision(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    HOLD = "hold"
    QUARANTINE = "quarantine"


def bound_evidence(text: str, limit: int = EVIDENCE_LIMIT) -> str:
    """Clamp evidence excerpts so payloads/secrets can't leak through logs."""
    return text if len(text) <= limit else text[:limit] + "..."


@dataclass(frozen=True, slots=True)
class Verdict:
    decision: Decision
    rule: str | None = None
    evidence: str | None = None
    confidence: float = 1.0

    @property
    def allowed(self) -> bool:
        return self.decision is Decision.ALLOW


ALLOW = Verdict(Decision.ALLOW)


@runtime_checkable
class Inspector(Protocol):
    """An inspector examines one message and returns a verdict.

    `content` is the textual payload for inbound messages (tool response
    text); outbound inspectors typically reason over the context alone.
    """

    name: str
    directions: frozenset[Direction]

    async def inspect(self, ctx: SecurityContext, content: str | None) -> Verdict: ...


class InspectorPipeline:
    def __init__(self, inspectors: list[Inspector]) -> None:
        self._inspectors = list(inspectors)

    async def run(self, ctx: SecurityContext, content: str | None = None) -> Verdict:
        for inspector in self._inspectors:
            if ctx.direction not in inspector.directions:
                continue
            try:
                verdict = await inspector.inspect(ctx, content)
            except Exception as exc:  # noqa: BLE001 - fail closed on anything
                return Verdict(
                    decision=Decision.BLOCK,
                    rule=f"{inspector.name}.error",
                    evidence=bound_evidence(f"inspector failed: {type(exc).__name__}: {exc}"),
                )
            if not verdict.allowed:
                return verdict
        return ALLOW
