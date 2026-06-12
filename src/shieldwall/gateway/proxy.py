"""The Shield Wall gateway - a transparent, bidirectional MCP proxy.

Presents an MCP server to the agent's client; holds an MCP ClientSession to
the real upstream tool server. Every tools/call is inspected outbound before
the upstream is contacted, and its result is inspected inbound before
anything reaches the agent.

Security notes (reviewed against THREAT_MODEL.md):
- Blocked results sent back to the agent NEVER include evidence excerpts:
  echoing the matched content would deliver the injection we just blocked.
  Evidence lives only in the audit store.
- All textual surfaces of an upstream result are inspected: every text
  content block, embedded text resources, resource link metadata, and the
  JSON serialization of structuredContent.
- Upstream failures fail closed: the agent gets a sanitized error, never a
  partially-inspected result.
- In stdio mode stdout is the MCP transport; nothing here may print to stdout.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from time import perf_counter

import mcp.types as types
from mcp.client.session import ClientSession
from mcp.server.lowlevel import Server

from shieldwall.config import GatewayConfig
from shieldwall.gateway.context import Direction, SecurityContext, hash_arguments
from shieldwall.gateway.pipeline import ALLOW, Decision, InspectorPipeline, Verdict
from shieldwall.store.events import EventStore

_ATTACK_TYPE_BY_RULE_PREFIX = {
    "policy.": "privilege-escalation",
    "patterns.": "prompt-injection",
}


def _attack_type(verdict: Verdict) -> str:
    rule = verdict.rule or ""
    for prefix, attack_type in _ATTACK_TYPE_BY_RULE_PREFIX.items():
        if rule.startswith(prefix):
            return attack_type
    return "unknown"


def extract_inspectable_text(result: types.CallToolResult) -> str:
    """Collect every textual surface of a tool result for inspection.

    Missing a surface here is an inspection bypass, so unknown block types
    are serialized wholesale rather than skipped.
    """
    parts: list[str] = []
    for block in result.content:
        if isinstance(block, types.TextContent):
            parts.append(block.text)
        elif isinstance(block, types.EmbeddedResource):
            resource = block.resource
            if isinstance(resource, types.TextResourceContents):
                parts.append(resource.text)
            else:
                parts.append(resource.model_dump_json())
        elif isinstance(block, types.ResourceLink):
            parts.append(block.model_dump_json())
        elif isinstance(block, types.ImageContent | types.AudioContent):
            # Binary payloads are out of scope for text inspection (M1);
            # their metadata still gets serialized.
            parts.append(block.model_dump_json(exclude={"data"}))
        else:
            parts.append(block.model_dump_json())
    if result.structuredContent is not None:
        parts.append(json.dumps(result.structuredContent, default=str))
    return "\n".join(parts)


def _blocked_result(
    direction: Direction, verdict: Verdict, incident_id: str
) -> types.CallToolResult:
    # Sanitized on purpose: rule + incident id only, never evidence.
    message = (
        f"[Shield Wall] {direction} message blocked by rule '{verdict.rule}'. "
        f"Incident {incident_id} has been logged."
    )
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=message)],
        isError=True,
    )


class ShieldWallGateway:
    def __init__(
        self, config: GatewayConfig, store: EventStore, pipeline: InspectorPipeline
    ) -> None:
        self._config = config
        self._store = store
        self._pipeline = pipeline
        self._session_id = f"sess-{uuid.uuid4().hex[:8]}"
        # Session counters are shared across concurrently-dispatched requests;
        # the lock keeps call numbers unique and history snapshots consistent.
        self._state_lock = asyncio.Lock()
        self._call_number = 0
        self._tool_history: list[str] = []

    @property
    def session_id(self) -> str:
        return self._session_id

    def _build_context(
        self,
        tool: str,
        arguments: dict | None,
        direction: Direction,
        call_number: int,
        history: tuple[str, ...],
    ) -> SecurityContext:
        return SecurityContext(
            agent_id=self._config.agent_id,
            session_id=self._session_id,
            organization_id=self._config.organization_id,
            role=self._config.role,
            declared_goal=self._config.declared_goal,
            tool=tool,
            arguments_hash=hash_arguments(arguments),
            direction=direction,
            call_number=call_number,
            session_tool_history=history,
            source_trust=self._config.upstream_trust,
            timestamp=SecurityContext.now(),
        )

    async def _record(
        self, ctx: SecurityContext, verdict: Verdict, started: float, detection_method: str
    ) -> str | None:
        latency_ms = int((perf_counter() - started) * 1000)
        incident_id: str | None = None
        if not verdict.allowed:
            incident_id = await self._store.create_incident(
                ctx, verdict, attack_type=_attack_type(verdict), detection_method=detection_method
            )
        await self._store.log_event(ctx, verdict, latency_ms, incident_id)
        return incident_id

    async def handle_call_tool(
        self, upstream: ClientSession, name: str, arguments: dict | None
    ) -> types.CallToolResult:
        started = perf_counter()
        async with self._state_lock:
            self._call_number += 1
            call_number = self._call_number
            history = tuple(self._tool_history)

        # Outbound: authorize before the upstream ever sees the call.
        out_ctx = self._build_context(name, arguments, "outbound", call_number, history)
        out_verdict = await self._pipeline.run(out_ctx, content=None)
        if not out_verdict.allowed:
            incident_id = await self._record(out_ctx, out_verdict, started, "deterministic")
            return _blocked_result("outbound", out_verdict, incident_id or "unrecorded")
        await self._record(out_ctx, out_verdict, started, "deterministic")
        async with self._state_lock:
            self._tool_history.append(name)
            history = tuple(self._tool_history)

        # Forward. An upstream failure fails closed.
        try:
            result = await upstream.call_tool(name, arguments)
        except Exception as exc:  # noqa: BLE001
            in_ctx = self._build_context(name, arguments, "inbound", call_number, history)
            verdict = Verdict(
                decision=Decision.BLOCK,
                rule="gateway.upstream_error",
                evidence=f"upstream call failed: {type(exc).__name__}",
            )
            incident_id = await self._record(in_ctx, verdict, started, "deterministic")
            return _blocked_result("inbound", verdict, incident_id or "unrecorded")

        # Inbound: inspect the full result before it reaches the agent.
        in_ctx = self._build_context(name, arguments, "inbound", call_number, history)
        in_verdict = await self._pipeline.run(in_ctx, content=extract_inspectable_text(result))
        if not in_verdict.allowed:
            incident_id = await self._record(in_ctx, in_verdict, started, "pattern")
            return _blocked_result("inbound", in_verdict, incident_id or "unrecorded")
        await self._record(in_ctx, in_verdict, started, "pattern")
        return result

    def build_server(self, upstream: ClientSession) -> Server:
        server: Server = Server("shieldwall")

        @server.list_tools()
        async def list_tools() -> list[types.Tool]:
            started = perf_counter()
            upstream_tools = await upstream.list_tools()
            # Tool descriptions reach the agent's context and are NOT yet
            # content-inspected (M4 gap, THREAT_MODEL.md). Audit them anyway:
            # the hash of names+descriptions makes rug-pull swaps detectable
            # in the event trail today.
            descriptions = {t.name: t.description or "" for t in upstream_tools.tools}
            ctx = self._build_context("tools/list", descriptions, "inbound", 0, ())
            await self._record(ctx, ALLOW, started, "none")
            return upstream_tools.tools

        # validate_input=False: the gateway is transparent; schema validation
        # belongs to the upstream. Re-validating here would also desync if
        # the upstream evolves mid-session.
        @server.call_tool(validate_input=False)
        async def call_tool(name: str, arguments: dict | None) -> types.CallToolResult:
            return await self.handle_call_tool(upstream, name, arguments)

        return server
