"""Sentinel signals - advisory evidence, never an enforcement decision.

A `Signal` is the *only* thing a sentinel may produce (ADR-0005). The
SentinelRunner aggregates signals and the deterministic breaker decides whether
to quarantine. A signal carries a bounded evidence excerpt (rule 3), never a raw
payload.
"""

from __future__ import annotations

from dataclasses import dataclass

EVIDENCE_LIMIT = 200


def bound(text: str, limit: int = EVIDENCE_LIMIT) -> str:
    return text if len(text) <= limit else text[:limit] + "..."


@dataclass(frozen=True, slots=True)
class Signal:
    sentinel: str
    detected: bool
    confidence: float
    evidence: str = ""
    attack_type: str = "unknown"

    @classmethod
    def none(cls, sentinel: str) -> Signal:
        """The 'nothing to report' signal - the fail-safe a sentinel returns when
        it has no evidence, errors, or its analyzer is unavailable."""
        return cls(sentinel=sentinel, detected=False, confidence=0.0)

    @classmethod
    def fire(
        cls, sentinel: str, confidence: float, evidence: str, attack_type: str
    ) -> Signal:
        # Confidence is clamped defensively: an LLM-sourced number must never
        # escape [0, 1] and skew the runner's threshold (ADR-0005).
        clamped = min(1.0, max(0.0, confidence))
        return cls(
            sentinel=sentinel,
            detected=True,
            confidence=clamped,
            evidence=bound(evidence),
            attack_type=attack_type,
        )
