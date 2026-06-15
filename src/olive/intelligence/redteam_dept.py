"""The runtime Red-Team department (ADR-0016).

VISION department 2 as a runtime component: on a trigger (on-demand or on a
schedule) it runs the deterministic red-team engine and publishes its bypass
findings onto the incident bus, so they flow into the loop (Remediation records
them; the org is aware via the audit trail). Humans still gate every promotion.

THE SAFETY GUARANTEE IS STRUCTURAL (ADR-0016 §1). This module's ONLY attack
primitive is `redteam.engine.run_campaign`, which targets a sandbox pipeline built
from policy files - it can never reach a live agent session, an upstream tool, or
the live circuit breaker. Accordingly this module DELIBERATELY does not import
`gateway.proxy`, `gateway.upstreams`, `mcp.ClientSession`, or the live
`CircuitBreaker`, and is handed none of them. A test asserts that import set.
Adding scheduling + a bus publish adds autonomy, never new reach.

It is advisory-only (ADR-0005): it publishes findings, never calls `breaker.trip`
or `set_mode`, never writes an enforcement artifact (ADR-0015 anti-cheat carries
over). A finding is a DISTINCT bus kind (`redteam-finding`, not `detection`) so a
routine drill can never escalate the operating mode (ADR-0016 §4).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from pathlib import Path

from olive.intelligence.bus import IncidentBus
from olive.intelligence.reporter import IncidentReport
from olive.redteam.engine import Bypass, load_known_keys, run_campaign

# A misconfigured short interval would be a self-DoS; clamp to this hard floor.
_MIN_INTERVAL_SECONDS = 30.0

_log = logging.getLogger(__name__)


def _finding_report(bypass: Bypass) -> IncidentReport:
    """A rule-3 envelope for a bypass: only the bounded key + note, never the
    obfuscated payload. confidence is 0.0 - a drill is not a live threat signal."""
    return IncidentReport(
        session_key="",
        agent_id="redteam",
        organization_id="",
        confidence=0.0,
        attack_types=[bypass.category],
        action="redteam-finding",
        signals=[
            {
                "sentinel": "redteam",
                "confidence": 0.0,
                "evidence": f"{bypass.key}: {bypass.note}"[:200],
            }
        ],
        incident_id=None,
    )


class RedTeamDepartment:
    """Trigger-and-publish wrapper around the offline engine. Publishes
    `redteam-finding` objects; subscribes to NOTHING (so a finding can never
    re-trigger a campaign - the feedback loop is structurally absent)."""

    def __init__(
        self,
        bus: IncidentBus,
        *,
        policy: str = "default.yaml",
        corpus_dir: str | Path | None = None,
        interval: float | None = None,
    ) -> None:
        self._bus = bus
        self._policy = policy
        self._corpus_dir = corpus_dir
        # Clamp a configured interval up to the floor; None = not scheduled.
        self._interval = max(interval, _MIN_INTERVAL_SECONDS) if interval else None
        self._task: asyncio.Task | None = None
        self._running = False  # single-flight: no overlapping campaigns
        self.campaigns_run = 0
        self.findings_published = 0
        self.campaign_failures = 0

    async def run_once(self) -> int | None:
        """Run one sandbox campaign and publish only the NOVEL bypasses (deduped
        against the corpus) as `redteam-finding` objects. Returns the count
        published, or None if skipped because a campaign was already in flight
        (single-flight) - distinct from 0, which means a campaign ran and found
        nothing novel."""
        if self._running:
            return None
        self._running = True
        try:
            known = load_known_keys(self._corpus_dir) if self._corpus_dir else set()
            report = await run_campaign(policy=self._policy, known_keys=known)
            self.campaigns_run += 1
            published = 0
            for bypass in report.novel:
                obj = self._bus.make_object(
                    kind="redteam-finding",
                    source_dept="redteam",
                    report=_finding_report(bypass),
                )
                await self._bus.publish(obj)
                published += 1
            self.findings_published += published
            return published
        finally:
            self._running = False

    def start(self) -> None:
        """Spawn the scheduler loop (no-op if not scheduled). Mirrors
        SentinelRunner.start - the composition root calls this once the loop runs."""
        if self._interval is None or self._task is not None:
            return
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None

    async def _loop(self) -> None:
        while True:
            await asyncio.sleep(self._interval)
            try:
                await self.run_once()
            except Exception:  # noqa: BLE001 - a campaign error must not kill the scheduler
                self.campaign_failures += 1
                # Surface it: a silently-failing scheduled drill must be detectable,
                # else an operator believes drills run when every one is throwing.
                _log.warning(
                    "red-team scheduled campaign failed (%d total failure(s))",
                    self.campaign_failures,
                    exc_info=True,
                )
