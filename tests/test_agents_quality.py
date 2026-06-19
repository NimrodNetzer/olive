"""Plan B — Company of Agents Quality (ADR-0027).

Four security properties under test:

1. Bus publisher validation — unauthorized (dept, kind) pairs are rejected before
   HMAC verification (fail-closed); unknown departments are also rejected.

2. Per-department HKDF keys — each dept's signing key is derived independently;
   dept-A's key cannot verify a dept-B object.

3. Supervisor tier — DefenseSupervisor detects a silent Defense department and
   publishes a degraded supervisor-health object; healthy dept → healthy status.

4. Runtime import guard — _assert_sandbox raises RuntimeError when a dept module
   has a reference whose __module__ is in the forbidden set.
"""

from __future__ import annotations

import ast
import asyncio
from pathlib import Path

import pytest

import olive.intelligence.supervisor as _sup_module
from olive.intelligence.bus import (
    PERMITTED_KINDS,
    BusError,
    IncidentBus,
    IncidentObject,
    _derive_dept_key,
    register_dept,
)
from olive.intelligence.departments import (
    DefenseDepartment,
    _assert_sandbox,
    build_runtime_org,
)
from olive.intelligence.remediation import RemediationLedger
from olive.intelligence.reporter import IncidentReport
from olive.intelligence.supervisor import DefenseSupervisor, SupervisorHealth
from olive.gateway.breaker import CircuitBreaker

_KEY = b"test-process-key"


def _report(*, action: str = "quarantine", confidence: float = 0.95) -> IncidentReport:
    return IncidentReport(
        session_key="org\x1fagent\x1fsess",
        agent_id="agent",
        organization_id="org",
        confidence=confidence,
        attack_types=["injection"],
        action=action,
        signals=[{"sentinel": "prompt-injection", "confidence": confidence, "evidence": "ev"}],
        incident_id="INC-0001",
    )


@pytest.fixture
async def bus(tmp_path):
    b = IncidentBus(tmp_path / "audit.db", _KEY)
    await b.open()
    try:
        yield b
    finally:
        await b.close()


# ── 1. Bus publisher validation ───────────────────────────────────────────────


async def test_permitted_kinds_table_is_complete():
    """Every known source_dept has at least one permitted kind."""
    for dept, kinds in PERMITTED_KINDS.items():
        assert kinds, f"dept {dept!r} has an empty PERMITTED_KINDS entry"


async def test_publish_valid_kind_succeeds(bus):
    obj = bus.make_object(kind="detection", source_dept="defense", report=_report())
    persisted = await bus.publish(obj)
    assert persisted.object_id is not None


async def test_publish_wrong_kind_for_dept_raises(bus):
    """defense is only allowed to publish 'detection', not 'mode-change'."""
    obj = bus.make_object(kind="mode-change", source_dept="defense", report=_report())
    with pytest.raises(BusError, match="not permitted"):
        await bus.publish(obj)


async def test_publish_unknown_dept_raises(bus):
    """A department not in PERMITTED_KINDS is rejected fail-closed."""
    obj = bus.make_object(kind="detection", source_dept="unknown-dept", report=_report())
    with pytest.raises(BusError, match="unknown dept"):
        await bus.publish(obj)


async def test_register_dept_allows_custom_dept(bus):
    """register_dept() lets tests add entries without touching core."""
    register_dept("test-dept", frozenset({"test-kind"}))
    try:
        obj = bus.make_object(kind="test-kind", source_dept="test-dept", report=_report())
        persisted = await bus.publish(obj)
        assert persisted.object_id is not None
    finally:
        del PERMITTED_KINDS["test-dept"]


async def test_publisher_validation_fires_before_hmac(bus):
    """Even with a valid signature, a wrong (dept, kind) pair is caught first."""
    obj = bus.make_object(kind="redteam-finding", source_dept="defense", report=_report())
    valid_sig = obj.sign(bus._dept_key("defense"))
    with pytest.raises(BusError, match="not permitted"):
        await bus.publish(obj, signature=valid_sig)


# ── 2. Per-department HKDF key isolation ─────────────────────────────────────


def test_dept_keys_differ():
    """Different departments get different keys from the same process key."""
    k1 = _derive_dept_key(b"proc-key", "defense")
    k2 = _derive_dept_key(b"proc-key", "commander")
    k3 = _derive_dept_key(b"proc-key", "redteam")
    assert k1 != k2 != k3 != k1


def test_dept_key_is_deterministic():
    """The same (process_key, dept) always produces the same derived key."""
    k1 = _derive_dept_key(b"proc-key", "defense")
    k2 = _derive_dept_key(b"proc-key", "defense")
    assert k1 == k2


def test_process_key_change_changes_dept_key():
    k1 = _derive_dept_key(b"key-a", "defense")
    k2 = _derive_dept_key(b"key-b", "defense")
    assert k1 != k2


async def test_object_signed_with_wrong_dept_key_is_rejected(bus):
    """An object signed with dept-A's key cannot be verified as dept-B."""
    obj = bus.make_object(kind="detection", source_dept="defense", report=_report())
    # Sign with the commander's key instead of defense's key.
    commander_key = bus._dept_key("commander")
    wrong_sig = obj.sign(commander_key)
    with pytest.raises(BusError):
        await bus.publish(obj, signature=wrong_sig)


async def test_dept_a_cannot_forge_dept_b_object(bus):
    """defense cannot craft a valid 'redteam-finding' — different key + kind blocked."""
    # Kind-level block fires first (publisher validation).
    obj = bus.make_object(kind="redteam-finding", source_dept="defense", report=_report())
    with pytest.raises(BusError):
        await bus.publish(obj)


async def test_correct_dept_key_accepted(bus):
    """Auto-sign path uses the correct dept key and verifies cleanly."""
    obj = bus.make_object(kind="commander", source_dept="commander", report=_report())
    # Publish a real commander kind (mode-change).
    mc = bus.make_object(kind="mode-change", source_dept="commander", report=_report())
    persisted = await bus.publish(mc)
    assert persisted.object_id is not None


# ── 3. Supervisor tier ────────────────────────────────────────────────────────


class _FakeDefense:
    """Minimal monitorable compatible with DefenseSupervisor."""

    def __init__(self, *, failures: int = 0, last_time: float | None = None) -> None:
        self.publish_failures = failures
        self.last_report_time = last_time


async def test_supervisor_healthy_when_recent_activity(bus):
    now = asyncio.get_event_loop().time()
    defense = _FakeDefense(last_time=now)
    sup = DefenseSupervisor(defense, bus, silence_threshold=60.0)
    snap = await sup.health()
    assert snap.status == "healthy"
    assert snap.alert is None


async def test_supervisor_degraded_when_silent(bus):
    defense = _FakeDefense(last_time=0.0)  # loop time 0 → very old
    sup = DefenseSupervisor(defense, bus, silence_threshold=1.0)
    snap = await sup.health()
    assert snap.status == "degraded"
    assert snap.alert is not None and "silent" in snap.alert


async def test_supervisor_degraded_on_publish_failures(bus):
    defense = _FakeDefense(failures=3, last_time=asyncio.get_event_loop().time())
    sup = DefenseSupervisor(defense, bus, silence_threshold=120.0)
    snap = await sup.health()
    assert snap.status == "degraded"
    assert "failure" in (snap.alert or "")


async def test_supervisor_publishes_health_object(bus):
    received: list[IncidentObject] = []

    async def sub(obj: IncidentObject) -> None:
        received.append(obj)

    bus.subscribe(sub, kind="supervisor-health")
    defense = _FakeDefense(last_time=0.0)
    sup = DefenseSupervisor(defense, bus, silence_threshold=1.0)
    await sup._poll()
    assert len(received) == 1
    assert received[0].kind == "supervisor-health"
    assert received[0].source_dept == "supervisor"


async def test_supervisor_healthy_status_published(bus):
    received: list[IncidentObject] = []

    async def sub(obj: IncidentObject) -> None:
        received.append(obj)

    bus.subscribe(sub, kind="supervisor-health")
    now = asyncio.get_event_loop().time()
    defense = _FakeDefense(last_time=now)
    sup = DefenseSupervisor(defense, bus, silence_threshold=120.0)
    await sup._poll()
    assert received[0].source_dept == "supervisor"
    # Healthy status is still published (operators need the heartbeat).
    assert received[0].object_id is not None


async def test_supervisor_in_runtime_org(tmp_path):
    """build_runtime_org(include_supervisor=True) wires a supervisor."""
    bus = IncidentBus(tmp_path / "audit.db", _KEY)
    await bus.open()
    ledger = RemediationLedger(tmp_path / "audit.db")
    await ledger.open()
    try:
        org = build_runtime_org(
            breaker=CircuitBreaker(),
            bus=bus,
            ledger=ledger,
            queue=asyncio.Queue(),
            sentinels=[],
            include_supervisor=True,
            supervisor_poll_interval=60.0,
        )
        assert org.supervisor is not None
        assert isinstance(org.supervisor, DefenseSupervisor)
    finally:
        await ledger.close()
        await bus.close()


async def test_supervisor_absent_by_default(tmp_path):
    bus = IncidentBus(tmp_path / "audit.db", _KEY)
    await bus.open()
    ledger = RemediationLedger(tmp_path / "audit.db")
    await ledger.open()
    try:
        org = build_runtime_org(
            breaker=CircuitBreaker(),
            bus=bus,
            ledger=ledger,
            queue=asyncio.Queue(),
            sentinels=[],
        )
        assert org.supervisor is None
    finally:
        await ledger.close()
        await bus.close()


# ── 4. Runtime import guard ───────────────────────────────────────────────────


def test_assert_sandbox_passes_on_clean_module():
    """redteam_dept has no forbidden references in its namespace."""
    _assert_sandbox(
        "olive.intelligence.redteam_dept",
        ("olive.gateway.proxy", "olive.gateway.upstreams"),
    )  # must not raise


def test_assert_sandbox_raises_on_forbidden_reference():
    """Injecting a fake reference from a forbidden module triggers RuntimeError."""
    import olive.intelligence.redteam_dept as rtd

    class _FakeProxy:
        __module__ = "olive.gateway.proxy"

    original = vars(rtd).get("_test_forbidden_canary")
    try:
        rtd._test_forbidden_canary = _FakeProxy()
        with pytest.raises(RuntimeError, match="forbidden"):
            _assert_sandbox("olive.intelligence.redteam_dept", ("olive.gateway.proxy",))
    finally:
        # Clean up the injected canary
        if original is None:
            try:
                delattr(rtd, "_test_forbidden_canary")
            except AttributeError:
                pass
        else:
            rtd._test_forbidden_canary = original  # type: ignore[assignment]


def test_assert_sandbox_unknown_module_is_noop():
    """A not-yet-imported module is silently skipped (nothing to check)."""
    _assert_sandbox("olive.nonexistent.module", ("olive.gateway.proxy",))  # must not raise


def test_assert_sandbox_submodule_prefix_matched():
    """A reference from a sub-path of a forbidden module is also caught."""
    import olive.intelligence.redteam_dept as rtd

    class _FakeUpstream:
        __module__ = "olive.gateway.upstreams.http"

    original = vars(rtd).get("_test_sub_canary")
    try:
        rtd._test_sub_canary = _FakeUpstream()
        with pytest.raises(RuntimeError, match="forbidden"):
            _assert_sandbox("olive.intelligence.redteam_dept", ("olive.gateway.upstreams",))
    finally:
        if original is None:
            try:
                delattr(rtd, "_test_sub_canary")
            except AttributeError:
                pass
        else:
            rtd._test_sub_canary = original  # type: ignore[assignment]


# ── Supervisor import-set AST test ────────────────────────────────────────────


def test_supervisor_module_cannot_reach_live_traffic():
    """supervisor.py must not statically import the forbidden gateway modules."""
    tree = ast.parse(Path(_sup_module.__file__).read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(n.name for n in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
    forbidden = {
        "olive.gateway.proxy",
        "olive.gateway.upstreams",
        "olive.gateway.breaker",
        "mcp.client.session",
    }
    violations = forbidden & imported
    assert not violations, f"supervisor.py imports forbidden modules: {violations}"


# ── Defense department last_report_time tracking ─────────────────────────────


async def test_defense_dept_records_last_report_time(bus):
    """on_report() stamps last_report_time so the supervisor can detect silence."""
    defense = DefenseDepartment(bus)
    assert defense.last_report_time is None
    defense.on_report(_report())
    # Drain the scheduled task.
    for _ in range(5):
        await asyncio.sleep(0)
    assert defense.last_report_time is not None
