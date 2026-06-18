"""The runtime agent company (ADR-0014): the incident bus, the deterministic
Security Commander, and the two departments collaborating through structured,
signed objects. The properties under test are the security-relevant ones:

  - the bus fails closed on a forged/tampered object (an LLM agent cannot forge
    a mode-change or verified object);
  - rule 3: no raw payload field ever exists on a bus object or row;
  - the Commander is the sole `set_mode` authority and escalates deterministically;
  - departments collaborate end-to-end (Defense -> bus -> Commander + Remediation).
"""

from __future__ import annotations

import asyncio
import dataclasses

import pytest

from olive.gateway.breaker import CircuitBreaker
from olive.gateway.mode import OperatingMode
from olive.gateway.session import SessionStatus
from olive.identity.tokens import RevokedTokenCache
from olive.intelligence.bus import BusError, IncidentBus, IncidentObject
from olive.intelligence.commander import (
    COMMAND_SCOPE,
    CommanderError,
    SecurityCommander,
    target_mode,
)
from olive.intelligence.departments import build_runtime_org
from olive.intelligence.remediation import RemediationLedger, RemediationState
from olive.intelligence.reporter import IncidentReport

_KEY = b"test-process-key"


def _report(*, action="quarantine", confidence=0.95, incident_id="INC-0001", attack="injection"):
    return IncidentReport(
        session_key="org\x1fagent\x1fsess",
        agent_id="agent",
        organization_id="org",
        confidence=confidence,
        attack_types=[attack],
        action=action,
        signals=[{"sentinel": "prompt-injection", "confidence": confidence, "evidence": "ev"}],
        incident_id=incident_id,
    )


@pytest.fixture
async def bus(tmp_path):
    b = IncidentBus(tmp_path / "audit.db", _KEY)
    await b.open()
    try:
        yield b
    finally:
        await b.close()


# ---- the bus: signing + audit + rule 3 ---------------------------------------


async def test_bus_persists_and_assigns_ids(bus):
    received: list[IncidentObject] = []

    async def sub(obj):
        received.append(obj)

    bus.subscribe(sub, kind="detection")
    obj = bus.make_object(kind="detection", source_dept="defense", report=_report())
    persisted = await bus.publish(obj)
    assert persisted.object_id == "IOB-0001"
    assert received and received[0].object_id == "IOB-0001"
    hist = await bus.history()
    assert len(hist) == 1 and hist[0]["kind"] == "detection"


async def test_bus_rejects_tampered_signature(bus):
    obj = bus.make_object(kind="mode-change", source_dept="commander", report=_report())
    with pytest.raises(BusError, match="signature mismatch"):
        await bus.publish(obj, signature="deadbeef")


async def test_bus_rejects_object_signed_with_wrong_key(bus):
    obj = bus.make_object(kind="detection", source_dept="defense", report=_report())
    forged = obj.sign(b"attacker-key")
    with pytest.raises(BusError):
        await bus.publish(obj, signature=forged)


async def test_incident_object_has_no_raw_payload_field():
    # rule 3 guard: the envelope must never carry content/arguments.
    fields = {f.name for f in dataclasses.fields(IncidentObject)}
    assert "content" not in fields
    assert "arguments" not in fields


async def test_bus_isolates_a_broken_subscriber(bus):
    async def broken(_obj):
        raise RuntimeError("boom")

    good: list[IncidentObject] = []

    async def ok(obj):
        good.append(obj)

    bus.subscribe(broken, kind="detection")
    bus.subscribe(ok, kind="detection")
    await bus.publish(bus.make_object(kind="detection", source_dept="defense", report=_report()))
    assert bus.delivery_failures == 1
    assert len(good) == 1  # the healthy subscriber still received it


async def test_defense_publish_failure_is_observable(bus):
    # A fire-and-forget on_report publish that raises must be counted, not lost.
    from olive.intelligence.departments import DefenseDepartment

    defense = DefenseDepartment(bus)
    await bus.close()  # next publish will raise BusError (bus not open)
    defense.on_report(_report())
    for _ in range(5):  # let the scheduled task run and its done-callback fire
        await asyncio.sleep(0)
    assert defense.publish_failures == 1


# ---- the Commander: deterministic escalation + capability gate ---------------


def test_target_mode_is_monotonic_and_deterministic():
    n, s, g = OperatingMode.NORMAL, OperatingMode.SUSPICIOUS, OperatingMode.SIEGE
    assert target_mode(n, 0, 0.5) is n
    assert target_mode(n, 1, 0.5) is s
    assert target_mode(n, 0, 0.9) is s
    assert target_mode(n, 3, 0.5) is g
    assert target_mode(n, 0, 0.99) is g
    # never steps down
    assert target_mode(g, 0, 0.0) is g


async def test_commander_escalates_on_detections(bus):
    breaker = CircuitBreaker()
    commander = SecurityCommander(breaker, bus)
    commander.subscribe()
    # first quarantine detection -> suspicious
    await bus.publish(bus.make_object(kind="detection", source_dept="defense", report=_report()))
    assert await breaker.mode() is OperatingMode.SUSPICIOUS
    # two more -> siege
    await bus.publish(bus.make_object(kind="detection", source_dept="defense", report=_report()))
    await bus.publish(bus.make_object(kind="detection", source_dept="defense", report=_report()))
    assert await breaker.mode() is OperatingMode.SIEGE


async def test_commander_audits_mode_change_on_the_bus(bus):
    breaker = CircuitBreaker()
    commander = SecurityCommander(breaker, bus)
    commander.subscribe()
    await bus.publish(bus.make_object(kind="detection", source_dept="defense", report=_report()))
    hist = await bus.history()
    kinds = [h["kind"] for h in hist]
    assert "detection" in kinds and "mode-change" in kinds  # the change is audited


async def test_force_mode_requires_capability(bus):
    breaker = CircuitBreaker()
    commander = SecurityCommander(breaker, bus)
    with pytest.raises(CommanderError, match=COMMAND_SCOPE):
        await commander.force_mode(OperatingMode.SIEGE, capabilities=("olive:release",))
    assert await breaker.mode() is OperatingMode.NORMAL  # unchanged on refusal


async def test_force_mode_can_deescalate_with_capability(bus):
    breaker = CircuitBreaker()
    commander = SecurityCommander(breaker, bus)
    await breaker.set_mode(OperatingMode.SIEGE, "attack")
    changed = await commander.force_mode(OperatingMode.NORMAL, capabilities=(COMMAND_SCOPE,))
    assert changed is True
    assert await breaker.mode() is OperatingMode.NORMAL


# ---- M11 Slice B: Commander bulk-revokes tokens on SIEGE --------------------


async def test_commander_revokes_quarantined_tokens_on_siege(bus):
    """When the Commander escalates to SIEGE every quarantined session's JTI
    is revoked so the agent cannot re-authenticate to escape containment."""
    breaker = CircuitBreaker(max_blocks=1)
    revocations = RevokedTokenCache()
    commander = SecurityCommander(breaker, bus, revocations=revocations)
    commander.subscribe()

    # Quarantine two sessions that have live JTIs
    await breaker.record_jti("sess-a", "jti-a")
    await breaker.record_block("sess-a", "INC-0001")
    await breaker.record_jti("sess-b", "jti-b")
    await breaker.record_block("sess-b", "INC-0002")
    # Session without a JTI (stdio)
    await breaker.record_block("sess-nojti", "INC-0003")

    # Escalate to SIEGE via three quarantine detections
    for iid in ("INC-0001", "INC-0002", "INC-0003"):
        await bus.publish(bus.make_object(
            kind="detection", source_dept="defense",
            report=_report(incident_id=iid),
        ))

    assert await breaker.mode() is OperatingMode.SIEGE
    assert revocations.is_revoked("jti-a"), "quarantined session JTI must be revoked"
    assert revocations.is_revoked("jti-b"), "quarantined session JTI must be revoked"


async def test_commander_siege_revocation_noop_without_revocations(bus):
    """Commander without a RevokedTokenCache still escalates cleanly."""
    breaker = CircuitBreaker(max_blocks=1)
    commander = SecurityCommander(breaker, bus)  # no revocations
    commander.subscribe()
    await breaker.record_jti("sess-x", "jti-x")
    await breaker.record_block("sess-x", "INC-0001")
    for _ in range(3):
        await bus.publish(bus.make_object(
            kind="detection", source_dept="defense",
            report=_report(incident_id="INC-0001"),
        ))
    assert await breaker.mode() is OperatingMode.SIEGE  # escalation still works


# ---- end-to-end: the departments collaborate through the bus -----------------


async def test_runtime_org_defense_to_commander_and_remediation(bus, tmp_path):
    breaker = CircuitBreaker()
    ledger = RemediationLedger(tmp_path / "audit.db")
    await ledger.open()
    try:
        org = build_runtime_org(
            breaker=breaker, bus=bus, ledger=ledger, queue=asyncio.Queue(), sentinels=[]
        )
        # Defense publishes a detection (the SentinelRunner.on_report path).
        await org.defense.publish_report(_report(incident_id="INC-0042"))
        # Commander escalated the fleet mode...
        assert await breaker.mode() is OperatingMode.SUSPICIOUS
        # ...and Remediation captured the incident as an intent awaiting reproduction.
        assert org.remediation.intents == ["INC-0042"]

        # A reproduced object (red-team step) opens a real ledger cycle.
        await bus.publish(
            bus.make_object(
                kind="reproduced",
                source_dept="remediation",
                report=_report(action="observed", incident_id="INC-0042"),
                incident_id="INC-0042",
                corpus_case_id="inj-9001",
            )
        )
        cycles = await ledger.list_cycles()
        assert len(cycles) == 1
        assert cycles[0].state is RemediationState.REPRODUCED
        assert cycles[0].incident_id == "INC-0042"
    finally:
        await ledger.close()
