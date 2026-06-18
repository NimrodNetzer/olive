"""Heartbeat loop — periodic mode-piggyback with three-failure escalation (ADR-0024).

Every `interval` seconds (default 10, minimum 5) the gateway:
  1. POSTs /fleet/heartbeat carrying its current operating mode.
  2. If the response carries a different `commanded_mode`, applies it through
     the SecurityCommander's `force_mode_fleet` (respecting the single-writer
     rule — ADR-0006; the Commander remains the sole `set_mode` caller).
  3. Counts consecutive failures. At three failures, escalates locally to
     SUSPICIOUS (never downgrade; only upward escalation, ADR-0014).

Fail-closed contract (ADR-0024 §2):
  - A heartbeat failure never causes a mode downgrade. The gateway retains its
    current mode on error.
  - Only three *consecutive* failures cause an *upward* escalation (to
    SUSPICIOUS) to account for the control plane being unreachable due to an
    attack. A single failure is transient noise.
  - The escalation is audited by the Commander's `_apply_mode` (a `mode-change`
    object is published on the bus with source=fleet-control-plane).
"""

from __future__ import annotations

import asyncio
import logging

from olive.gateway.breaker import CircuitBreaker
from olive.gateway.mode import OperatingMode
from olive.intelligence.commander import SecurityCommander

from olive.fleet.client import FleetClient

_log = logging.getLogger(__name__)

_MIN_INTERVAL = 5.0
_FAILURE_ESCALATION_COUNT = 3
_FAILURE_ESCALATION_MODE = OperatingMode.SUSPICIOUS


class HeartbeatLoop:
    """Runs `start`/`stop` in the ASGI lifespan (like RedTeamDepartment)."""

    def __init__(
        self,
        client: FleetClient,
        commander: SecurityCommander,
        breaker: CircuitBreaker,
        interval: float = 10.0,
    ) -> None:
        self._client = client
        self._commander = commander
        self._breaker = breaker
        self._interval = max(interval, _MIN_INTERVAL)
        self._task: asyncio.Task | None = None
        self.consecutive_failures = 0  # observable

    def start(self) -> None:
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _run(self) -> None:
        while True:
            await asyncio.sleep(self._interval)
            current_mode = (await self._breaker.mode()).value
            try:
                commanded = await self._client.heartbeat(current_mode)
                self.consecutive_failures = 0
                if commanded is not None:
                    try:
                        mode = OperatingMode(commanded)
                    except ValueError:
                        _log.warning(
                            "control plane sent unknown mode %r — ignored", commanded
                        )
                        continue
                    await self._commander.force_mode_fleet(
                        mode, gateway_id=self._client.gateway_id
                    )
            except Exception:  # noqa: BLE001 - already logged in FleetClient.heartbeat
                self.consecutive_failures += 1
                _log.warning(
                    "fleet heartbeat failure %d of %d",
                    self.consecutive_failures, _FAILURE_ESCALATION_COUNT,
                )
                if self.consecutive_failures == _FAILURE_ESCALATION_COUNT:
                    _log.error(
                        "three consecutive heartbeat failures — escalating to SUSPICIOUS "
                        "(possible attack on or outage of the control plane)"
                    )
                    await self._commander.force_mode_fleet(
                        _FAILURE_ESCALATION_MODE,
                        gateway_id="<unreachable-control-plane>",
                    )
