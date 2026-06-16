"""The runtime Builder department (ADR-0018). The properties under test are the
safety-critical ones:

  - propose-only BY CONSTRUCTION: the module cannot import the proxy/upstream/
    breaker/ClientSession, so it cannot reach an enforcement path;
  - a `fix-proposed` object NEVER escalates the operating mode (confidence 0.0;
    distinct kind the Commander does not read);
  - a proposal can never re-trigger the department (it subscribes only to
    confirmed-weakness kinds, never to its own `fix-proposed`);
  - novelty dedup bounds proposal-spam (one proposal per weakness);
  - rule-3 envelope (no payload, no diff body); promotion stays the human
    `olive cycle` (the Builder never opens a ledger cycle).
"""

from __future__ import annotations

import ast
import dataclasses
from pathlib import Path

import pytest

import olive.intelligence.builder_dept as bd
from olive.gateway.breaker import CircuitBreaker
from olive.gateway.mode import OperatingMode
from olive.intelligence.builder_dept import BuilderDepartment, ProposalLedger
from olive.intelligence.bus import IncidentBus
from olive.intelligence.commander import SecurityCommander
from olive.intelligence.departments import build_runtime_org
from olive.intelligence.redteam_dept import RedTeamDepartment
from olive.intelligence.remediation import RemediationLedger
from olive.intelligence.reporter import IncidentReport

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


@pytest.fixture
async def proposals(tmp_path):
    led = ProposalLedger(tmp_path / "audit.db")
    await led.open()
    try:
        yield led
    finally:
        await led.close()


def _finding_obj(bus_, *, evidence="seed:strat: note", attack="injection.encoded"):
    """A redteam-finding-shaped object, signed by the bus."""
    return bus_.make_object(
        kind="redteam-finding",
        source_dept="redteam",
        report=IncidentReport(
            session_key="",
            agent_id="redteam",
            organization_id="",
            confidence=0.0,
            attack_types=[attack],
            action="redteam-finding",
            signals=[{"sentinel": "redteam", "confidence": 0.0, "evidence": evidence}],
            incident_id=None,
        ),
    )


# ---- the structural propose-only guarantee (ADR-0018 §2) ---------------------


def test_module_cannot_reach_an_enforcement_path():
    """By construction: builder_dept must not import the proxy, upstreams, the
    live breaker, or a ClientSession. A thing it cannot import, it cannot do."""
    tree = ast.parse(Path(bd.__file__).read_text(encoding="utf-8"))
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
    assert not leaks, f"builder_dept must not import enforcement modules: {leaks}"


def test_module_never_calls_an_enforcement_method():
    """Defence in depth beyond imports: no attribute access in the code names an
    enforcement transition - the Builder proposes, it never enforces. AST-based so
    the prose in the module docstring (which explains what it must NOT do) is
    ignored; only real `x.trip`/`x.set_mode`/... references would fail."""
    tree = ast.parse(Path(bd.__file__).read_text(encoding="utf-8"))
    forbidden = {"trip", "set_mode", "update_baseline", "open_cycle", "record_verification"}
    named = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    leaks = forbidden & named
    assert not leaks, f"builder_dept must not call enforcement methods: {leaks}"


# ---- a proposal never escalates / never re-triggers (ADR-0018 §6) ------------


async def test_proposal_never_moves_the_mode(bus, proposals):
    breaker = CircuitBreaker()
    commander = SecurityCommander(breaker, bus)
    commander.subscribe()  # subscribes to "detection" only
    builder = BuilderDepartment(bus, proposals)
    builder.subscribe()
    await bus.publish(_finding_obj(bus))
    # a fix-proposed was published...
    assert any(r["kind"] == "fix-proposed" for r in await bus.history())
    # ...but the Commander never saw it as a detection, so the fleet stays Normal.
    assert await breaker.mode() is OperatingMode.NORMAL


async def test_proposal_never_retriggers_the_department(bus, proposals):
    builder = BuilderDepartment(bus, proposals)
    builder.subscribe()
    await bus.publish(_finding_obj(bus))
    count = builder.proposals_published
    assert count == 1
    # publish a fix-proposed directly; the dept must not react to its own kind.
    echo = bus.make_object(
        kind="fix-proposed",
        source_dept="builder",
        report=_proposal_stub(),
    )
    await bus.publish(echo)
    assert builder.proposals_published == count  # unchanged - no self-trigger


# ---- novelty dedup bounds spam (ADR-0018 §6) ---------------------------------


async def test_duplicate_weakness_is_proposed_once(bus, proposals):
    builder = BuilderDepartment(bus, proposals)
    builder.subscribe()
    await bus.publish(_finding_obj(bus, evidence="seed:strat: note"))
    await bus.publish(_finding_obj(bus, evidence="seed:strat: note"))  # identical weakness
    assert builder.proposals_published == 1
    assert len(await proposals.list_proposals()) == 1


async def test_distinct_weaknesses_each_get_a_proposal(bus, proposals):
    builder = BuilderDepartment(bus, proposals)
    builder.subscribe()
    await bus.publish(_finding_obj(bus, evidence="seedA:s: note"))
    await bus.publish(_finding_obj(bus, evidence="seedB:s: note"))
    assert builder.proposals_published == 2


async def test_only_confirmed_weakness_kinds_trigger(bus, proposals):
    # A bare `detection` is NOT a Builder trigger (ADR-0018 §1) - it has no
    # committed case to fix yet; it reaches the Builder only once reproduced.
    builder = BuilderDepartment(bus, proposals)
    builder.subscribe()
    detection = bus.make_object(
        kind="detection", source_dept="defense", report=_proposal_stub(), incident_id="INC-1"
    )
    await bus.publish(detection)
    assert builder.proposals_published == 0


async def test_reproduced_object_triggers_a_proposal(bus, proposals):
    builder = BuilderDepartment(bus, proposals)
    builder.subscribe()
    reproduced = bus.make_object(
        kind="reproduced",
        source_dept="remediation",
        report=_proposal_stub(),
        incident_id="INC-7",
        corpus_case_id="inj-0099",
    )
    await bus.publish(reproduced)
    [proposal] = await proposals.list_proposals()
    assert proposal.corpus_case_id == "inj-0099"
    assert proposal.finding_key == "case:inj-0099"


# ---- rule 3: no payload, no diff body ----------------------------------------


def test_proposal_dataclass_has_no_raw_payload_field():
    fields = {f.name for f in dataclasses.fields(bd.Proposal)}
    assert "content" not in fields and "arguments" not in fields


async def test_runtime_proposal_records_no_diff(bus, proposals):
    # The runtime department authors no diff (ADR-0018 §3); patch_hash stays null.
    builder = BuilderDepartment(bus, proposals)
    builder.subscribe()
    await bus.publish(_finding_obj(bus))
    [proposal] = await proposals.list_proposals()
    assert proposal.patch_hash is None
    assert proposal.status == "proposed"
    assert len(proposal.summary) <= 200


# ---- on-demand replay (the `olive builder-dept run` surface) -----------------


async def test_run_once_replays_history_for_novel_weaknesses(bus, proposals):
    # Findings published with NO live builder subscribed...
    await bus.publish(_finding_obj(bus, evidence="seedA:s: a"))
    await bus.publish(_finding_obj(bus, evidence="seedB:s: b"))
    builder = BuilderDepartment(bus, proposals)  # not subscribed
    published = await builder.run_once()
    assert published == 2


async def test_run_once_is_idempotent(bus, proposals):
    await bus.publish(_finding_obj(bus, evidence="seedA:s: a"))
    builder = BuilderDepartment(bus, proposals)
    assert await builder.run_once() == 1
    assert await builder.run_once() == 0  # dedup: nothing new the second time


async def test_live_and_replay_dedup_are_consistent(bus, proposals):
    # A weakness proposed live must NOT be re-proposed by a later history replay
    # (the keys derived on each path must match).
    builder = BuilderDepartment(bus, proposals)
    builder.subscribe()
    await bus.publish(_finding_obj(bus, evidence="seed:strat: note"))
    assert builder.proposals_published == 1
    replayed = await builder.run_once()
    assert replayed == 0  # the live proposal already covered it


async def test_run_once_single_flight_returns_none(bus, proposals):
    builder = BuilderDepartment(bus, proposals)
    builder._running = True  # simulate a replay already in flight
    assert await builder.run_once() is None


# ---- wiring: optional, default off (ADR-0018 §8) -----------------------------


async def test_build_runtime_org_builder_off_by_default(bus, tmp_path):
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
        assert org.builder is None  # default: not wired
    finally:
        await ledger.close()


async def test_build_runtime_org_wires_builder_when_ledger_supplied(bus, proposals, tmp_path):
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
            proposal_ledger=proposals,
        )
        assert org.builder is not None
        # it is live: a confirmed weakness now yields a proposal
        await bus.publish(_finding_obj(bus))
        assert org.builder.proposals_published == 1
    finally:
        await ledger.close()


# ---- end-to-end: a red-team drill flows into a fix-proposal ------------------


async def test_redteam_finding_flows_into_a_builder_proposal(bus, proposals):
    builder = BuilderDepartment(bus, proposals)
    builder.subscribe()
    dept = RedTeamDepartment(bus, corpus_dir=CORPUS)
    findings = await dept.run_once()
    assert findings >= 1
    # every novel finding became exactly one proposal
    assert builder.proposals_published == findings
    assert len(await proposals.list_proposals()) == findings


def _proposal_stub() -> IncidentReport:
    return IncidentReport(
        session_key="",
        agent_id="builder",
        organization_id="",
        confidence=0.0,
        attack_types=["injection.encoded"],
        action="fix-proposed",
        signals=[{"sentinel": "builder", "confidence": 0.0, "evidence": "x:y"}],
        incident_id=None,
    )
