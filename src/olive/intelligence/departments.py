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
from dataclasses import dataclass

from olive.gateway.breaker import CircuitBreaker
from olive.intelligence.bus import IncidentBus, IncidentObject
from olive.intelligence.commander import SecurityCommander
from olive.intelligence.redteam_dept import RedTeamDepartment
from olive.intelligence.remediation import RemediationLedger
from olive.intelligence.reporter import IncidentReport
from olive.intelligence.runner import SentinelRunner


class DefenseDepartment:
    """Publishes the SentinelRunner's incident reports onto the bus as `detection`
    objects. `publish_report` is awaitable (the integration path/tests use it);
    `on_report` is the sync hook the runner calls and schedules a publish."""

    def __init__(self, bus: IncidentBus) -> None:
        self._bus = bus
        self._tasks: set[asyncio.Task] = set()
        self.publish_failures = 0  # observable: a swallowed publish is counted

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


@dataclass(slots=True)
class RuntimeOrg:
    """The wired runtime organization. `start`/`stop` drive the SentinelRunner's
    drain loop and the (optional) red-team scheduler; everything else reacts
    through the bus."""

    breaker: CircuitBreaker
    bus: IncidentBus
    commander: SecurityCommander
    defense: DefenseDepartment
    remediation: RemediationDepartment
    runner: SentinelRunner
    redteam: RedTeamDepartment

    def start(self) -> None:
        self.runner.start()
        self.redteam.start()  # no-op unless a scheduling interval was configured

    async def stop(self) -> None:
        await self.runner.stop()
        await self.redteam.stop()


def build_runtime_org(
    *,
    breaker: CircuitBreaker,
    bus: IncidentBus,
    ledger: RemediationLedger,
    queue,
    sentinels,
    store=None,
    threshold: float = 0.8,
    redteam_policy: str = "default.yaml",
    redteam_corpus_dir=None,
    redteam_interval: float | None = None,
) -> RuntimeOrg:
    """Wire one runtime org sharing a single breaker. The Defense adapter is
    installed as the runner's `on_report` hook; the Commander and Remediation
    subscribe to the bus. The red-team department is constructed always but only
    *schedules* autonomous campaigns when `redteam_interval` is set (default off,
    additive - ADR-0016). The bus must already be open."""
    defense = DefenseDepartment(bus)
    remediation = RemediationDepartment(ledger)
    commander = SecurityCommander(breaker, bus)
    commander.subscribe()
    remediation.subscribe(bus)
    runner = SentinelRunner(
        queue, breaker, sentinels, threshold=threshold, store=store, on_report=defense.on_report
    )
    redteam = RedTeamDepartment(
        bus, policy=redteam_policy, corpus_dir=redteam_corpus_dir, interval=redteam_interval
    )
    return RuntimeOrg(
        breaker=breaker,
        bus=bus,
        commander=commander,
        defense=defense,
        remediation=remediation,
        redteam=redteam,
        runner=runner,
    )
