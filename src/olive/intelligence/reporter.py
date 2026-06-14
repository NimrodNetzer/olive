"""Incident reporter - turns aggregated sentinel signals into a structured,
human-readable incident object (the VISION's incident timeline, in miniature).

It records hashes + bounded evidence only (rule 3) and never the raw payload.
The report is a description of *why* the deterministic breaker acted on the
sentinels' advice - the audit trail ADR-0005 requires.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field

from olive.intelligence.signals import Signal


@dataclass(frozen=True, slots=True)
class IncidentReport:
    session_key: str
    agent_id: str
    organization_id: str
    confidence: float
    attack_types: list[str]
    action: str  # "quarantine" | "observed"
    signals: list[dict] = field(default_factory=list)
    incident_id: str | None = None

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True)

    def render(self) -> str:
        lines = [
            f"[Olive incident] {self.incident_id or '(unrecorded)'} "
            f"action={self.action} confidence={self.confidence:.2f}",
            f"  session={self.session_key} agent={self.agent_id} org={self.organization_id}",
            f"  attack_types={', '.join(self.attack_types) or 'none'}",
        ]
        for sig in self.signals:
            lines.append(
                f"  - {sig['sentinel']}: confidence={sig['confidence']:.2f} "
                f"evidence={sig['evidence']}"
            )
        return "\n".join(lines)


def build_report(
    *,
    session_key: str,
    agent_id: str,
    organization_id: str,
    signals: list[Signal],
    action: str,
    incident_id: str | None = None,
) -> IncidentReport:
    fired = [s for s in signals if s.detected]
    confidence = max((s.confidence for s in fired), default=0.0)
    attack_types = sorted({s.attack_type for s in fired})
    return IncidentReport(
        session_key=session_key,
        agent_id=agent_id,
        organization_id=organization_id,
        confidence=confidence,
        attack_types=attack_types,
        action=action,
        signals=[
            {"sentinel": s.sentinel, "confidence": s.confidence, "evidence": s.evidence}
            for s in fired
        ],
        incident_id=incident_id,
    )
