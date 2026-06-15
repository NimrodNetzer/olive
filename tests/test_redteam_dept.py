"""The runtime Red-Team department (ADR-0016). The properties under test are the
safety-critical ones:

  - sandbox-only BY CONSTRUCTION: the module cannot import the proxy/upstream/
    ClientSession/live breaker, so it cannot reach live traffic;
  - a drill (`redteam-finding`) NEVER escalates the operating mode or trips
    containment (distinct bus kind; no trip/set_mode);
  - a finding can never re-trigger a campaign (the dept subscribes to nothing);
  - rule-3 envelope (no payload); novel-only + dedup; Remediation records a
    finding as an intent (never auto-opens a cycle).
"""

from __future__ import annotations

import ast
import dataclasses
from pathlib import Path

import pytest

import olive.intelligence.redteam_dept as rtd
from olive.gateway.breaker import CircuitBreaker
from olive.gateway.mode import OperatingMode
from olive.intelligence.bus import IncidentBus, IncidentObject
from olive.intelligence.commander import SecurityCommander
from olive.intelligence.departments import RemediationDepartment, build_runtime_org
from olive.intelligence.redteam_dept import RedTeamDepartment
from olive.intelligence.remediation import RemediationLedger

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "evals" / "corpus"
_KEY = b"test-process-key"


@pytest.fixture
async def bus(tmp_path):
    b = IncidentBus(tmp_path / "audit.db", _KEY)
    await b.open()
    try:
        yield b
    finally:
        await b.close()


# ---- the structural sandbox guarantee (ADR-0016 §1) --------------------------


def test_module_cannot_reach_live_traffic():
    """By construction: redteam_dept must not import the proxy, upstreams, a
    ClientSession, or the live breaker. A thing it cannot import, it cannot do."""
    tree = ast.parse(Path(rtd.__file__).read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(n.name for n in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
    forbidden = (
        "olive.gateway.proxy",
        "olive.gateway.upstreams",
        "olive.gateway.breaker",
        "mcp",
    )
    leaks = [imp for imp in imported for f in forbidden if imp == f or imp.startswith(f + ".")]
    assert not leaks, f"redteam_dept must not import live-traffic modules: {leaks}"


# ---- a drill never escalates / trips (ADR-0016 §3, §4) -----------------------


async def test_drill_never_moves_the_mode(bus):
    breaker = CircuitBreaker()
    commander = SecurityCommander(breaker, bus)
    commander.subscribe()  # subscribes to "detection" only
    dept = RedTeamDepartment(bus, corpus_dir=CORPUS)
    published = await dept.run_once()
    assert published >= 1  # findings were published
    # ...but the Commander never saw them as detections, so the fleet stays Normal.
    assert await breaker.mode() is OperatingMode.NORMAL


async def test_finding_never_retriggers_a_campaign(bus):
    # The dept publishes but subscribes to nothing - no feedback loop.
    dept = RedTeamDepartment(bus, corpus_dir=CORPUS)
    await dept.run_once()
    ran = dept.campaigns_run
    # publish another redteam-finding directly; the dept must not react.
    obj = bus.make_object(
        kind="redteam-finding",
        source_dept="redteam",
        report=_finding_stub(),
    )
    await bus.publish(obj)
    assert dept.campaigns_run == ran  # unchanged - no re-trigger


# ---- rule 3 + dedup ----------------------------------------------------------


def test_finding_object_has_no_raw_payload_field():
    fields = {f.name for f in dataclasses.fields(IncidentObject)}
    assert "content" not in fields and "arguments" not in fields


async def test_publishes_only_novel_findings(bus):
    # With every bypass key already filed, a campaign publishes nothing new.
    from olive.intelligence.redteam_dept import _finding_report
    from olive.redteam.engine import run_campaign

    all_keys = {b.key for b in (await run_campaign(known_keys=set())).bypasses}
    report = await run_campaign(known_keys=all_keys)
    assert report.novel == []  # nothing novel when everything is known
    # and publishing that empty novel set yields zero bus traffic
    for b in report.novel:  # (empty)
        await bus.publish(
            bus.make_object(
                kind="redteam-finding", source_dept="redteam", report=_finding_report(b)
            )
        )
    assert all(row["kind"] != "redteam-finding" for row in await bus.history())


async def test_corpus_dedup_reduces_findings(bus):
    # The 4 backfilled redteam_keys mean the live corpus run publishes only the
    # genuinely novel system-override variants, not all 7 bypasses.
    dept = RedTeamDepartment(bus, corpus_dir=CORPUS)
    published = await dept.run_once()
    assert 1 <= published < 7


# ---- Remediation records a finding as an intent (ADR-0016 §5) -----------------


async def test_remediation_records_finding_as_intent(bus, tmp_path):
    ledger = RemediationLedger(tmp_path / "led.db")
    await ledger.open()
    try:
        remediation = RemediationDepartment(ledger)
        remediation.subscribe(bus)
        dept = RedTeamDepartment(bus, corpus_dir=CORPUS)
        await dept.run_once()
        assert remediation.redteam_intents  # findings captured as intents
        assert any("system-override" in ev for ev in remediation.redteam_intents)
        # ...and no ledger cycle was auto-opened (a finding has no committed case).
        assert await ledger.list_cycles() == []
    finally:
        await ledger.close()


# ---- scheduler lifecycle + anti-DoS bounds -----------------------------------


def test_interval_is_clamped_to_floor(bus):
    dept = RedTeamDepartment(bus, interval=1.0)  # below the floor
    assert dept._interval == rtd._MIN_INTERVAL_SECONDS


def test_unscheduled_start_is_noop(bus):
    dept = RedTeamDepartment(bus)  # interval None -> not scheduled
    dept.start()
    assert dept._task is None


async def test_scheduled_start_stop(bus):
    dept = RedTeamDepartment(bus, corpus_dir=CORPUS, interval=30.0)
    dept.start()
    assert dept._task is not None
    await dept.stop()
    assert dept._task is None


async def test_single_flight_skip_returns_none_not_zero(bus):
    # A skip (campaign already in flight) is None - distinct from 0, which means a
    # campaign ran and found nothing novel. An operator must be able to tell them
    # apart, so the two outcomes do not share a return value.
    dept = RedTeamDepartment(bus, corpus_dir=CORPUS)
    dept._running = True  # simulate an in-flight campaign
    assert await dept.run_once() is None
    assert dept.campaigns_run == 0  # the skipped call ran no campaign


async def test_scheduled_campaign_failure_is_counted_and_logged(bus, monkeypatch, caplog):
    # A silently-failing scheduled drill must be detectable: the failure is counted
    # AND surfaced via a log warning, else an operator believes drills run when every
    # one is throwing. The error must not kill the scheduler loop.
    dept = RedTeamDepartment(bus, corpus_dir=CORPUS, interval=30.0)

    async def boom(self):
        raise RuntimeError("campaign exploded")

    monkeypatch.setattr(RedTeamDepartment, "run_once", boom)
    with caplog.at_level("WARNING", logger="olive.intelligence.redteam_dept"):
        # drive one scheduler iteration directly (no real 30s sleep)
        monkeypatch.setattr(rtd.asyncio, "sleep", _raise_after_first_call())
        with pytest.raises(_StopLoop):
            await dept._loop()
    assert dept.campaign_failures == 1
    assert any("scheduled campaign failed" in r.message for r in caplog.records)


class _StopLoop(Exception):
    pass


def _raise_after_first_call():
    state = {"calls": 0}

    async def _sleep(_seconds):
        state["calls"] += 1
        if state["calls"] >= 2:
            raise _StopLoop  # let exactly one failing iteration complete, then bail
        return None

    return _sleep


async def test_build_runtime_org_includes_redteam_default_off(bus, tmp_path):
    ledger = RemediationLedger(tmp_path / "led.db")
    await ledger.open()
    try:
        import asyncio

        org = build_runtime_org(
            breaker=CircuitBreaker(),
            bus=bus,
            ledger=ledger,
            queue=asyncio.Queue(),
            sentinels=[],
        )
        assert org.redteam._interval is None  # default: not scheduled
        org.start()  # must not spawn a red-team loop
        assert org.redteam._task is None
        await org.stop()
    finally:
        await ledger.close()


def _finding_stub():
    from olive.intelligence.reporter import IncidentReport

    return IncidentReport(
        session_key="",
        agent_id="redteam",
        organization_id="",
        confidence=0.0,
        attack_types=["injection.encoded"],
        action="redteam-finding",
        signals=[{"sentinel": "redteam", "confidence": 0.0, "evidence": "x:y"}],
        incident_id=None,
    )
