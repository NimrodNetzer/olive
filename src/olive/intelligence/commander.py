"""The Security Commander - deterministic command & coordination (ADR-0014).

The runtime org's coordinator. It is **pure deterministic code, not an LLM**:
its only authorities are (a) deciding the fleet-wide operating mode and (b)
routing incident objects between departments. It never runs inline on a request,
never asks an LLM to decide, and never calls `breaker.trip` (that stays the
SentinelRunner's sole authority). The Commander being deterministic is the moat:
command authority in a security org must not be an injectable LLM (ADR-0005).

Two state machines, one writer each:
  - SentinelRunner -> `breaker.trip`   (contain one session)
  - Commander      -> `breaker.set_mode` (reshape fleet-wide inline posture)

The Commander subscribes to the incident bus, escalates the mode from the
deterministic detection stream (or on a capability-gated human order), audits
every change as a signed `mode-change` object on the bus, and routes confirmed
incidents to the registered departments (e.g. Remediation).
"""

from __future__ import annotations

from olive.gateway.breaker import CircuitBreaker
from olive.gateway.mode import OperatingMode
from olive.identity.tokens import RevokedTokenCache
from olive.intelligence.bus import IncidentBus, IncidentObject
from olive.intelligence.reporter import IncidentReport

# Capability a human token must carry to force a mode change (ADR-0014). Distinct
# scope; capabilities never imply one another (ADR-0007/0013 precedent).
COMMAND_SCOPE = "olive:command"


class CommanderError(Exception):
    """A refused command (e.g. a human order without the olive:command
    capability). Fails closed - the mode is never changed on a refusal."""


def target_mode(current: OperatingMode, quarantines: int, max_confidence: float) -> OperatingMode:
    """Pure, deterministic escalation policy: the mode is a function of how many
    sessions have been contained and the strongest detection seen. Monotonic
    upward - the Commander never *de*-escalates automatically (that is a human
    decision, like releasing a quarantine). Testable in isolation."""
    if quarantines >= 3 or max_confidence >= 0.99:
        proposed = OperatingMode.SIEGE
    elif quarantines >= 1 or max_confidence >= 0.9:
        proposed = OperatingMode.SUSPICIOUS
    else:
        proposed = OperatingMode.NORMAL
    # Never step down here; escalation only.
    order = {OperatingMode.NORMAL: 0, OperatingMode.SUSPICIOUS: 1, OperatingMode.SIEGE: 2}
    return proposed if order[proposed] > order[current] else current


class SecurityCommander:
    def __init__(
        self,
        breaker: CircuitBreaker,
        bus: IncidentBus,
        store=None,
        revocations: RevokedTokenCache | None = None,
    ) -> None:
        self._breaker = breaker
        self._bus = bus
        self._store = store  # EventStore | None — optional persistence (ADR-0003 seam)
        self._revocations = revocations  # RevokedTokenCache | None — M11 Siege token freeze
        self._quarantines = 0
        self._max_confidence = 0.0

    def subscribe(self) -> None:
        """Listen for detection objects on the bus. The Commander reacts only to
        the deterministic detection stream, never to its own mode-change objects
        (so there is no feedback loop)."""
        self._bus.subscribe(self._on_detection, kind="detection")

    async def _on_detection(self, obj: IncidentObject) -> None:
        if obj.report.action == "quarantine":
            self._quarantines += 1
        self._max_confidence = max(self._max_confidence, obj.report.confidence)
        current = await self._breaker.mode()
        proposed = target_mode(current, self._quarantines, self._max_confidence)
        if proposed is not current:
            await self._apply_mode(
                proposed,
                reason=(
                    f"escalated from {current} on {self._quarantines} quarantine(s), "
                    f"max confidence {self._max_confidence:.2f}"
                ),
                incident_id=obj.incident_id,
            )

    async def force_mode(self, mode: OperatingMode, *, capabilities: tuple[str, ...]) -> bool:
        """Human-forced mode change, gated on the olive:command capability. This is
        the only way to *de*-escalate (e.g. Siege -> Normal once an attack passes),
        mirroring the human release of a quarantine. Returns True if the mode
        changed. Refusal fails closed (CommanderError) and changes nothing."""
        if COMMAND_SCOPE not in capabilities:
            raise CommanderError(f"a mode change requires the '{COMMAND_SCOPE}' capability")
        return await self._apply_mode(mode, reason="human-forced mode change", incident_id=None)

    async def force_mode_fleet(self, mode: OperatingMode, *, gateway_id: str) -> bool:
        """Fleet control-plane mode instruction, received via heartbeat (ADR-0024).

        Authentication already happened at the fleet client boundary (olive:fleet
        token verified by the control plane); no capability check here. The audit
        reason names the source so the `mode-change` bus object is traceable.
        Returns True if the mode changed (monotonic rule in _apply_mode still
        holds — the Commander never de-escalates automatically)."""
        return await self._apply_mode(
            mode,
            reason=f"fleet-control-plane instruction (gateway={gateway_id})",
            incident_id=None,
        )

    async def _revoke_quarantined_tokens(self) -> None:
        """Bulk-revoke the live JWT of every quarantined session on SIEGE (M11).
        Errors are swallowed so a revocation failure never blocks the mode change
        (fail-safe: mode propagates even if persistence hiccups)."""
        if self._revocations is None and self._store is None:
            return
        jti_map = self._breaker.quarantined_jtis()
        for jti in jti_map.values():
            try:
                if self._revocations is not None:
                    self._revocations.revoke(jti)
                if self._store is not None:
                    await self._store.revoke_token(  # type: ignore[attr-defined]
                        jti, org_id="", agent_id="", reason="siege-declared"
                    )
            except Exception:  # noqa: BLE001 - revocation must not block the mode change
                pass

    async def _apply_mode(
        self, mode: OperatingMode, *, reason: str, incident_id: str | None
    ) -> bool:
        """The single place the Commander moves the mode: the deterministic
        `breaker.set_mode` call, then an audited `mode-change` object on the bus.
        No raw payloads (rule 3) - the report carries only the bounded reason."""
        changed = await self._breaker.set_mode(mode, reason, incident_id)
        if changed and self._store is not None:
            try:
                await self._store.persist_mode(mode.value)  # type: ignore[attr-defined]
            except Exception:  # noqa: BLE001 - persistence must not block the mode change
                pass
        if changed:
            report = IncidentReport(
                session_key="",
                agent_id="commander",
                organization_id="",
                confidence=self._max_confidence,
                attack_types=[],
                action="mode-change",
                signals=[{"sentinel": "commander", "confidence": 0.0, "evidence": reason[:200]}],
                incident_id=incident_id,
            )
            obj = self._bus.make_object(
                kind="mode-change",
                source_dept="commander",
                report=report,
                incident_id=incident_id,
            )
            await self._bus.publish(obj)
            # Siege-specific crisis announcement (M9 / M11): publish a typed
            # siege-declared object AND bulk-revoke every quarantined session's
            # live token so a compromised agent cannot re-authenticate on a new
            # session to escape the siege perimeter.
            if mode is OperatingMode.SIEGE:
                await self._revoke_quarantined_tokens()
                frozen = self._breaker.quarantined_count()
                siege_report = IncidentReport(
                    session_key="",
                    agent_id="commander",
                    organization_id="",
                    confidence=self._max_confidence,
                    attack_types=["siege-declared"],
                    action="siege-declared",
                    signals=[{
                        "sentinel": "commander",
                        "confidence": self._max_confidence,
                        "evidence": f"SIEGE declared: {frozen} session(s) frozen; {reason}"[:200],
                    }],
                    incident_id=incident_id,
                )
                siege_obj = self._bus.make_object(
                    kind="siege-declared",
                    source_dept="commander",
                    report=siege_report,
                    incident_id=incident_id,
                )
                await self._bus.publish(siege_obj)
        return changed
