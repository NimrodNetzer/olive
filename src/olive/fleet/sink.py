"""Fleet telemetry sink — pushes event summaries to the control plane (ADR-0024).

Implements TelemetrySink so it can be composed into a MultiSink alongside the
QueueSink and UIBroker in the composition root. The gateway core never imports
this module (ADR-0003); it is wired in cli.py at the composition root.

Rule 3 is enforced here: the summary pushed to the control plane contains only
hashes and metadata — never raw content or arguments. The FleetClient's queue
provides the same drop-on-full guarantee as QueueSink, so a slow control plane
never backpressures the fast path.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from olive.gateway.telemetry import TelemetryEvent

from olive.fleet.client import FleetClient


class FleetSink:
    """TelemetrySink that enqueues bounded event summaries to the FleetClient."""

    def __init__(self, client: FleetClient) -> None:
        self._client = client

    async def publish(self, event: TelemetryEvent) -> None:
        ctx = event.ctx
        summary = {
            "event_id": str(uuid.uuid4()),
            "agent_id": ctx.agent_id,
            "session_id": ctx.session_id,
            "org_id": getattr(ctx, "organization_id", ""),
            "tool": ctx.tool,
            "direction": ctx.direction.value,
            "decision": event.verdict.decision.value,
            "policy_rule": event.verdict.rule,
            "arguments_hash": ctx.arguments_hash,  # already SHA-256, never raw
            "timestamp": datetime.now(timezone.utc).isoformat(),
            # content and arguments are NEVER included (rule 3)
        }
        self._client.enqueue_event(summary)
