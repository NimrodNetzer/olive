"""Runtime departments on the incident bus (ADR-0014, first slice).

Two departments collaborate through structured objects, never group chat:

  - **Defense** = the existing SentinelRunner + sentinels. When the runner acts
    it builds an `IncidentReport`; the Defense adapter turns that into a
    `detection` object and publishes it onto the bus (the runner's `on_report`
    hook is the integration point). The runner's `trip` authority is unchanged.
  - **Remediation** = the existing RemediationLedger, subscribed to the bus. A
    `reproduced` object (carrying a real corpus case id - the red-team step)
    opens a ledger cycle; a bare `detection` object is recorded as a remediation
    *intent* awaiting reproduction (runtime auto-reproduction is deferred, so the
    ledger is never opened with a fake case id).

`build_runtime_org` is the composition helper (used by the composition root and
the integration tests) that wires breaker + bus + Commander + the two departments
+ the SentinelRunner into one runnable unit, sharing a single breaker.
"""

from __future__ import annotations

import asyncio
import logging
import sys
import types
from dataclasses import dataclass, field

from olive.gateway.breaker import CircuitBreaker
from olive.intelligence.builder_dept import BuilderDepartment, ProposalLedger
from olive.intelligence.bus import IncidentBus, IncidentObject
from olive.intelligence.commander import SecurityCommander
from olive.intelligence.redteam_dept import RedTeamDepartment
from olive.intelligence.remediation import RemediationLedger
from olive.intelligence.reporter import IncidentReport
from olive.intelligence.runner import SentinelRunner
from olive.intelligence.sentinels import (
    BehaviorSentinel,
    DataLeakSentinel,
    PromptInjectionSentinel,
)

_log = logging.getLogger(__name__)


def _assert_sandbox(module_name: str, forbidden: tuple[str, ...]) -> None:
    """Runtime complement to AST import tests (ADR-0027).

    Scans the live module namespace for attributes whose `__module__` origin
    is a forbidden namespace. Raises RuntimeError (fail-closed) if any are
    found, aborting wiring before a compromised department is connected.
    """
    mod = sys.modules.get(module_name)
    if mod is None:
        return
    for attr, obj in vars(mod).items():
        try:
            origin: str = getattr(obj, "__module__", "") or ""
        except Exception:  # noqa: BLE001
            continue
        for f in forbidden:
            if origin == f or origin.startswith(f + "."):
                raise RuntimeError(
                    f"department {module_name!r}: attribute {attr!r} originates "
                    f"from forbidden module {f!r} — wiring aborted (fail-closed)"
                )


def build_sentinels(config, store=None) -> list:
    """The three advisory sentinels, constructed from policy (ADR-0012). All three
    are deterministic-capable: PromptInjection is deterministic-first (re-runs the
    trigger matcher before any LLM call), DataLeak/Behavior are pure regex/sequence.
    So `olive serve --ui` produces real detections with NO `ANTHROPIC_API_KEY`; the
    semantic path simply adds nothing without a key (ADR-0020 §7).

    When `store` is provided (M10/M11), BehaviorSentinel receives three cross-session
    callbacks for: sequence detection, call-rate anomaly, and novel-tool detection."""
    cross_session_fn = None
    rate_baseline_fn = None
    known_tools_fn = None
    if store is not None:
        async def cross_session_fn(agent_id: str, org_id: str) -> list[str]:
            return await store.recent_agent_tools(agent_id, org_id)  # type: ignore[attr-defined]

        async def rate_baseline_fn(agent_id: str, org_id: str) -> list[int]:
            return await store.agent_calls_per_session(agent_id, org_id)  # type: ignore[attr-defined]

        async def known_tools_fn(agent_id: str, org_id: str) -> set[str]:
            return await store.agent_known_tools(agent_id, org_id)  # type: ignore[attr-defined]

    return [
        PromptInjectionSentinel(config.injection_patterns),
        DataLeakSentinel(),
        BehaviorSentinel(
            cross_session_fn=cross_session_fn,
            rate_baseline_fn=rate_baseline_fn,
            known_tools_fn=known_tools_fn,
        ),
    ]


class DefenseDepartment:
    """Publishes the SentinelRunner's incident reports onto the bus as `detection`
    objects. `publish_report` is awaitable (the integration path/tests use it);
    `on_report` is the sync hook the runner calls and schedules a publish."""

    def __init__(self, bus: IncidentBus) -> None:
        self._bus = bus
        self._tasks: set[asyncio.Task] = set()
        self.publish_failures = 0  # observable: a swallowed publish is counted
        self.last_report_time: float | None = None  # asyncio loop time; used by DefenseSupervisor

    async def publish_report(self, report: IncidentReport) -> IncidentObject:
        obj = self._bus.make_object(
            kind="detection",
            source_dept="defense",
            report=report,
            incident_id=report.incident_id,
        )
        return await self._bus.publish(obj)

    def on_report(self, report: IncidentReport) -> None:
        """Sync hook for SentinelRunner.on_report. Schedules the publish on the
        running loop and keeps a reference so the task is not GC'd mid-flight."""
        try:
            self.last_report_time = asyncio.get_running_loop().time()
        except RuntimeError:
            pass  # called outside an async context (tests); skip timestamp
        task = asyncio.ensure_future(self.publish_report(report))
        self._tasks.add(task)
        task.add_done_callback(self._on_publish_done)

    def _on_publish_done(self, task: asyncio.Task) -> None:
        """A fire-and-forget publish that raised (e.g. a closed bus) must not
        vanish silently: count it so the suppression is observable, never a fail
        that looks like a clear (CLAUDE.md rule 4 spirit)."""
        self._tasks.discard(task)
        if not task.cancelled() and task.exception() is not None:
            self.publish_failures += 1


class RemediationDepartment:
    """Bus subscriber that turns confirmed incidents into remediation work. A
    `reproduced` object (with a real corpus case id) opens a ledger cycle; a bare
    `detection` is recorded as an intent awaiting the red-team reproduction step."""

    def __init__(self, ledger: RemediationLedger) -> None:
        self._ledger = ledger
        self.intents: list[str] = []  # incident ids captured, awaiting reproduction
        self.redteam_intents: list[str] = []  # red-team findings awaiting reproduction

    async def handle(self, obj: IncidentObject) -> None:
        if obj.kind == "reproduced" and obj.incident_id and obj.corpus_case_id:
            await self._ledger.open_cycle(obj.incident_id, obj.corpus_case_id)
        elif obj.kind == "detection" and obj.incident_id:
            self.intents.append(obj.incident_id)
        elif obj.kind == "redteam-finding":
            # A drill finding (ADR-0016): record it as an intent awaiting human
            # reproduction - NEVER auto-open a cycle (it has no committed case id).
            # The evidence carries the bypass key + bounded note (rule 3).
            evidence = obj.report.signals[0]["evidence"] if obj.report.signals else "redteam"
            self.redteam_intents.append(evidence)

    def subscribe(self, bus: IncidentBus) -> None:
        bus.subscribe(self.handle, kind="detection")
        bus.subscribe(self.handle, kind="reproduced")
        bus.subscribe(self.handle, kind="redteam-finding")


class OperatorBridge:
    """Turns a UI `operator-request` into the one sanctioned on-demand action: a
    sandbox red-team drill (ADR-0017 §5 / ADR-0020 §6). Subscribes ONLY to
    `operator-request` (never to `redteam-finding`/`fix-proposed`), so a drill it
    triggers can never re-trigger it - no feedback loop. It calls
    `RedTeamDepartment.run_once()` (single-flight guarded); it has NO enforcement
    path: `force-mode-request` stays announce-only (a human with `olive:command`
    must act), and unknown/other actions are ignored (the request object is already
    on the audit trail).

    A per-process COOLDOWN bounds the rate: `POST /operator` is unauthenticated
    (ADR-0020 §5), so without a floor a client could fire back-to-back campaigns and
    compete with `/mcp` enforcement on the shared event loop. A request inside the
    cooldown is counted and dropped, never queued."""

    def __init__(
        self,
        bus: IncidentBus,
        redteam: RedTeamDepartment,
        *,
        cooldown: float = 10.0,
        injection_sentinel: PromptInjectionSentinel | None = None,
    ):
        self._bus = bus
        self._redteam = redteam
        self._cooldown = cooldown
        self._last_drill = float("-inf")  # loop time of the last accepted drill
        self._injection_sentinel = injection_sentinel
        self.campaigns_triggered = 0
        self.campaigns_throttled = 0

    @property
    def llm_enabled(self) -> bool:
        return self._injection_sentinel.llm_enabled if self._injection_sentinel else False

    @property
    def llm_available(self) -> bool:
        return self._injection_sentinel.llm_available if self._injection_sentinel else False

    @property
    def llm_provider(self) -> str | None:
        if self._injection_sentinel is None:
            return None
        return self._injection_sentinel._analyzer.provider

    async def handle(self, obj: IncidentObject) -> None:
        action = obj.report.action
        if action == "toggle-llm-request":
            if self._injection_sentinel is not None:
                self._injection_sentinel.llm_enabled = not self._injection_sentinel.llm_enabled
                _log.info("llm-toggle: llm_enabled=%s", self._injection_sentinel.llm_enabled)
            return
        if action != "run-campaign-request":
            return
        now = asyncio.get_running_loop().time()
        if now - self._last_drill < self._cooldown:
            self.campaigns_throttled += 1  # observable: rate-limited, not silently lost
            return
        self._last_drill = now
        try:
            await self._redteam.run_once()
            self.campaigns_triggered += 1
        except Exception:  # noqa: BLE001 - a drill failure must not break bus fan-out
            # Log it: a swallowed drill failure on the dashboard button would look
            # like a silent no-op to the operator (CLAUDE.md rule 5).
            _log.warning("operator-triggered red-team drill failed", exc_info=True)

    def subscribe(self) -> None:
        self._bus.subscribe(self.handle, kind="operator-request")


@dataclass(slots=True)
class RuntimeOrg:
    """The wired runtime organization. `start`/`stop` drive the SentinelRunner's
    drain loop, the (optional) red-team scheduler, the (optional) fleet heartbeat
    loop, and the (optional) supervisor; everything else reacts through the bus."""

    breaker: CircuitBreaker
    bus: IncidentBus
    commander: SecurityCommander
    defense: DefenseDepartment
    remediation: RemediationDepartment
    runner: SentinelRunner
    redteam: RedTeamDepartment
    builder: BuilderDepartment | None = None  # optional (ADR-0018); off unless wired
    operator_bridge: OperatorBridge | None = None  # optional (ADR-0020); on-demand drills
    heartbeat: object | None = None  # HeartbeatLoop | None (ADR-0024); off unless configured
    supervisor: object | None = None  # DepartmentSupervisor | None (ADR-0027); off by default

    def start(self) -> None:
        self.runner.start()
        self.redteam.start()  # no-op unless a scheduling interval was configured
        if self.heartbeat is not None:
            self.heartbeat.start()  # type: ignore[union-attr]
        if self.supervisor is not None:
            asyncio.ensure_future(self.supervisor.start())  # type: ignore[union-attr]

    async def stop(self) -> None:
        await self.runner.stop()
        await self.redteam.stop()
        if self.heartbeat is not None:
            await self.heartbeat.stop()  # type: ignore[union-attr]
        if self.supervisor is not None:
            await self.supervisor.stop()  # type: ignore[union-attr]


_DEPT_FORBIDDEN = (
    "olive.gateway.proxy",
    "olive.gateway.upstreams",
    "mcp.client.session",
)

# Runtime sandbox checks (ADR-0027): called before each dept is wired.
_SANDBOX_CHECKS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("olive.intelligence.redteam_dept", _DEPT_FORBIDDEN + ("olive.gateway.breaker",)),
    ("olive.intelligence.builder_dept", _DEPT_FORBIDDEN + ("olive.gateway.breaker",)),
    ("olive.intelligence.supervisor",   _DEPT_FORBIDDEN),
)


def build_runtime_org(
    *,
    breaker: CircuitBreaker,
    bus: IncidentBus,
    ledger: RemediationLedger,
    queue,
    sentinels,
    store=None,
    revocations=None,
    threshold: float = 0.8,
    redteam_policy: str = "default.yaml",
    redteam_corpus_dir=None,
    redteam_interval: float | None = None,
    proposal_ledger: ProposalLedger | None = None,
    operator_bridge: bool = False,
    heartbeat_loop=None,  # HeartbeatLoop | None (ADR-0024); wired by cli.py
    include_supervisor: bool = False,  # ADR-0027; off by default
    supervisor_silence_threshold: float = 120.0,
    supervisor_poll_interval: float = 30.0,
) -> RuntimeOrg:
    """Wire one runtime org sharing a single breaker. The Defense adapter is
    installed as the runner's `on_report` hook; the Commander and Remediation
    subscribe to the bus. The red-team department is constructed always but only
    *schedules* autonomous campaigns when `redteam_interval` is set (default off,
    additive - ADR-0016). The Builder department is wired only when an opened
    `proposal_ledger` is supplied (default off, additive - ADR-0018); it then
    subscribes to confirmed weaknesses and publishes `fix-proposed` objects. The
    supervisor is wired only when `include_supervisor=True` (default off, additive
    - ADR-0027). The bus (and any supplied ledger) must already be open.

    Runtime sandbox checks (ADR-0027) run before restricted departments are wired;
    a forbidden import reference in the live module namespace raises RuntimeError."""
    # Runtime import guard — fail-closed before wiring (ADR-0027).
    for module_name, forbidden in _SANDBOX_CHECKS:
        _assert_sandbox(module_name, forbidden)

    defense = DefenseDepartment(bus)
    remediation = RemediationDepartment(ledger)
    commander = SecurityCommander(breaker, bus, store=store, revocations=revocations)
    commander.subscribe()
    remediation.subscribe(bus)
    runner = SentinelRunner(
        queue, breaker, sentinels, threshold=threshold, store=store, on_report=defense.on_report
    )
    redteam = RedTeamDepartment(
        bus, policy=redteam_policy, corpus_dir=redteam_corpus_dir, interval=redteam_interval
    )
    builder: BuilderDepartment | None = None
    if proposal_ledger is not None:
        builder = BuilderDepartment(bus, proposal_ledger)
        builder.subscribe()
    bridge: OperatorBridge | None = None
    if operator_bridge:
        inj_sentinel = next(
            (s for s in sentinels if isinstance(s, PromptInjectionSentinel)), None
        )
        bridge = OperatorBridge(bus, redteam, injection_sentinel=inj_sentinel)
        bridge.subscribe()
    sup = None
    if include_supervisor:
        from olive.intelligence.supervisor import DefenseSupervisor
        sup = DefenseSupervisor(
            defense,
            bus,
            silence_threshold=supervisor_silence_threshold,
            poll_interval=supervisor_poll_interval,
        )
    return RuntimeOrg(
        breaker=breaker,
        bus=bus,
        commander=commander,
        defense=defense,
        remediation=remediation,
        redteam=redteam,
        runner=runner,
        builder=builder,
        operator_bridge=bridge,
        heartbeat=heartbeat_loop,
        supervisor=sup,
    )
