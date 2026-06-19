"""Supervisor tier skeleton — ADR-0027.

The VISION's Command & Coordination hierarchy: Commander → department supervisors
→ department specialists. This module is the first concrete supervisor slice.

`DefenseSupervisor` monitors the Defense department's health (last-report
timestamp, publish-failure count) on a polling interval and publishes
`supervisor-health` bus objects (advisory only, never moves mode). When the
department has been silent longer than the configured threshold the status is
`degraded` and an alert is logged so an operator or the Commander can act.

Import constraints (enforced by a test + `_assert_sandbox` at wiring time):
this module MUST NOT import `gateway.proxy`, `gateway.upstreams`,
`gateway.breaker`, or `mcp.client.session`. It holds no enforcement authority.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Literal, Protocol

if TYPE_CHECKING:
    from olive.intelligence.departments import DefenseDepartment

from olive.intelligence.bus import IncidentBus
from olive.intelligence.reporter import IncidentReport

_log = logging.getLogger(__name__)

_DEFAULT_SILENCE_THRESHOLD = 120.0  # seconds before a dept is flagged degraded
_DEFAULT_POLL_INTERVAL = 30.0       # how often the supervisor checks health


class _Monitorable(Protocol):
    """Duck-typed interface the supervisor requires from a department."""

    publish_failures: int
    last_report_time: float | None  # asyncio loop time of last on_report call


@dataclass(slots=True)
class SupervisorHealth:
    """One health snapshot for a department."""

    department: str
    status: Literal["healthy", "degraded"]
    last_activity: datetime | None = None
    alert: str | None = None


class DepartmentSupervisor:
    """Abstract base for a supervisor: polls health, publishes bus objects."""

    async def health(self) -> SupervisorHealth:
        raise NotImplementedError

    async def start(self) -> None:
        raise NotImplementedError

    async def stop(self) -> None:
        raise NotImplementedError


class DefenseSupervisor(DepartmentSupervisor):
    """Monitors the Defense department and publishes `supervisor-health` objects.

    A silent Defense department means no detections reach the bus — which could
    be genuine quiet or a broken pipeline. The supervisor surfaces the distinction
    so operators don't confuse "no attacks" with "broken detector."
    """

    def __init__(
        self,
        defense: _Monitorable,
        bus: IncidentBus,
        *,
        silence_threshold: float = _DEFAULT_SILENCE_THRESHOLD,
        poll_interval: float = _DEFAULT_POLL_INTERVAL,
    ) -> None:
        self._defense = defense
        self._bus = bus
        self._silence_threshold = silence_threshold
        self._poll_interval = poll_interval
        self._task: asyncio.Task | None = None
        self._prev_failures = 0
        self.polls_run = 0
        self.degraded_alerts = 0

    async def health(self) -> SupervisorHealth:
        """Snapshot of the Defense department's current health."""
        try:
            loop = asyncio.get_running_loop()
            now = loop.time()
        except RuntimeError:
            now = 0.0

        last_t = self._defense.last_report_time
        new_failures = self._defense.publish_failures - self._prev_failures

        if new_failures > 0:
            status: Literal["healthy", "degraded"] = "degraded"
            alert = f"{new_failures} publish failure(s) since last check"
        elif last_t is None:
            status = "healthy"
            alert = None
        elif now - last_t > self._silence_threshold:
            status = "degraded"
            elapsed = int(now - last_t)
            alert = f"defense silent for {elapsed}s (threshold {int(self._silence_threshold)}s)"
        else:
            status = "healthy"
            alert = None

        last_activity: datetime | None = None
        if last_t is not None:
            last_activity = datetime.now(UTC)  # wall-clock approximation for the snapshot

        return SupervisorHealth(
            department="defense",
            status=status,
            last_activity=last_activity,
            alert=alert,
        )

    async def _publish_health(self, snap: SupervisorHealth) -> None:
        evidence = snap.alert or f"defense status: {snap.status}"
        report = IncidentReport(
            session_key="",
            agent_id="supervisor",
            organization_id="",
            confidence=0.0,
            attack_types=[],
            action="supervisor-health",
            signals=[{"sentinel": "supervisor", "confidence": 0.0, "evidence": evidence[:200]}],
            incident_id=None,
        )
        obj = self._bus.make_object(
            kind="supervisor-health",
            source_dept="supervisor",
            report=report,
        )
        await self._bus.publish(obj)

    async def _poll(self) -> None:
        snap = await self.health()
        self.polls_run += 1
        self._prev_failures = self._defense.publish_failures
        if snap.status == "degraded":
            self.degraded_alerts += 1
            _log.warning(
                "DefenseSupervisor: department degraded — %s", snap.alert or "unknown reason"
            )
        try:
            await self._publish_health(snap)
        except Exception:  # noqa: BLE001 — a publish failure must not crash the poll loop
            _log.warning("DefenseSupervisor: failed to publish health snapshot", exc_info=True)

    async def _loop(self) -> None:
        while True:
            await asyncio.sleep(self._poll_interval)
            try:
                await self._poll()
            except Exception:  # noqa: BLE001 — a poll error must not kill the supervisor
                _log.warning("DefenseSupervisor: poll error", exc_info=True)

    async def start(self) -> None:
        if self._task is not None:
            return
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
