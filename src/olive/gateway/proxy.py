"""The Olive gateway - a transparent, bidirectional MCP proxy.

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

import json
from collections.abc import Callable
from time import perf_counter

import mcp.types as types
from mcp.client.session import ClientSession
from mcp.server.lowlevel import Server

from olive.config import GatewayConfig
from olive.gateway.breaker import CircuitBreaker
from olive.gateway.context import Direction, SecurityContext, hash_arguments
from olive.gateway.pipeline import ALLOW, Decision, InspectorPipeline, Verdict
from olive.gateway.ratelimit import RateLimiter
from olive.identity.claims import IdentityClaims, unverified_from_config
from olive.store.events import EventStore

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
        f"[Olive] {direction} message blocked by rule '{verdict.rule}'. "
        f"Incident {incident_id} has been logged."
    )
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=message)],
        isError=True,
    )


def _quarantined_result(incident_id: str) -> types.CallToolResult:
    # The session, not just this call, is contained. No rule/evidence echoed.
    message = (
        "[Olive] session quarantined; this call was denied without execution. "
        f"See incident {incident_id}. A human release is required to resume."
    )
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=message)],
        isError=True,
    )


def _throttled_result() -> types.CallToolResult:
    # A throttle, not a security block: tell the agent to slow down, no incident.
    message = "[Olive] rate limit exceeded for this session; call denied. Retry shortly."
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=message)],
        isError=True,
    )


class OliveGateway:
    def __init__(
        self,
        config: GatewayConfig,
        store: EventStore,
        pipeline: InspectorPipeline,
        breaker: CircuitBreaker | None = None,
        rate_limiter: RateLimiter | None = None,
        identity: IdentityClaims | None = None,
    ) -> None:
        self._config = config
        self._store = store
        self._pipeline = pipeline
        # Identity is the verified (or, for stdio fallback, config-derived)
        # subject the gateway enforces as. Role comes from here, not config, so
        # it cannot be self-asserted once tokens are required (ADR-0007).
        self._identity = identity or unverified_from_config(
            agent_id=config.agent_id,
            organization=config.organization_id,
            role=config.role,
        )
        self._session_id = self._identity.session_id
        # The breaker is the single concurrency authority over session state:
        # it sequences call numbers, snapshots history, and contains sessions.
        self._breaker = breaker or CircuitBreaker(
            max_blocks=config.max_blocks_before_quarantine
        )
        # The limit is resolved per call from the request identity's role
        # (multi-tenant safe); the limiter itself is just a keyed window.
        self._rate_limiter = rate_limiter or RateLimiter()

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def identity(self) -> IdentityClaims:
        return self._identity

    @property
    def breaker(self) -> CircuitBreaker:
        return self._breaker

    async def release_session(self, session_id: str | None = None) -> bool:
        """Reversible human release of a quarantined session (ADR-0006).
        A cross-process admin surface for this lands with HTTP transport."""
        return await self._breaker.release(session_id or self._session_id)

    def _build_context(
        self,
        identity: IdentityClaims,
        tool: str,
        arguments: dict | None,
        direction: Direction,
        call_number: int,
        history: tuple[str, ...],
    ) -> SecurityContext:
        return SecurityContext(
            agent_id=identity.agent_id,
            session_id=identity.session_id,
            organization_id=identity.organization,
            role=identity.role,
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

    async def _log_quarantined(
        self, ctx: SecurityContext, started: float, incident_id: str | None
    ) -> None:
        # A quarantined session's denied calls are audited as `quarantine`
        # events referencing the incident that tripped the breaker - no new
        # incident per call (ADR-0006), but never a silent decision (rule 5).
        latency_ms = int((perf_counter() - started) * 1000)
        verdict = Verdict(decision=Decision.QUARANTINE, rule="breaker.quarantined")
        await self._store.log_event(ctx, verdict, latency_ms, incident_id)

    async def _log_throttled(self, ctx: SecurityContext, started: float) -> None:
        # A throttle is audited as a block event but mints no incident and does
        # not count toward quarantine (it is not an attack).
        latency_ms = int((perf_counter() - started) * 1000)
        verdict = Verdict(decision=Decision.BLOCK, rule="ratelimit.exceeded")
        await self._store.log_event(ctx, verdict, latency_ms, None)

    def _rate_limit_for(self, role: str) -> int | None:
        policy = self._config.roles.get(role)
        return policy.max_calls_per_minute if policy else None

    async def handle_call_tool(
        self,
        upstream: ClientSession,
        name: str,
        arguments: dict | None,
        identity: IdentityClaims | None = None,
    ) -> types.CallToolResult:
        # Identity is resolved per call: HTTP passes the request's verified
        # identity; stdio falls back to the gateway's construction identity.
        # The breaker and rate limiter key on this session, so containment is
        # per-agent even when one gateway fronts many.
        identity = identity or self._identity
        sid = identity.session_id
        started = perf_counter()
        ticket = await self._breaker.begin_call(sid)

        # Containment first: a quarantined session is denied before any
        # inspector runs and before the upstream is ever contacted.
        if ticket.quarantined:
            ctx = self._build_context(
                identity, name, arguments, "outbound", ticket.call_number, ticket.history
            )
            await self._log_quarantined(ctx, started, ticket.incident_id)
            return _quarantined_result(ticket.incident_id or "unrecorded")

        call_number, history = ticket.call_number, ticket.history

        # Outbound authorization FIRST: a forbidden call must always be recorded
        # as the security block it is (incident + breaker), regardless of
        # rate-limit state - otherwise a flood could mask a forbidden attempt
        # behind a throttle and dodge containment.
        out_ctx = self._build_context(identity, name, arguments, "outbound", call_number, history)
        out_verdict = await self._pipeline.run(out_ctx, content=None)
        if not out_verdict.allowed:
            incident_id = await self._record(out_ctx, out_verdict, started, "deterministic")
            await self._breaker.record_block(sid, incident_id)
            return _blocked_result("outbound", out_verdict, incident_id or "unrecorded")

        # Throttle policy-allowed calls before the (expensive) upstream contact.
        # The limit is the identity's role limit. Not a security block - audited,
        # but no incident and no trip.
        limit = self._rate_limit_for(identity.role)
        if not await self._rate_limiter.check_and_record(sid, limit):
            await self._log_throttled(out_ctx, started)
            return _throttled_result()

        await self._record(out_ctx, out_verdict, started, "deterministic")
        await self._breaker.record_allowed_call(sid, name)
        history = (*history, name)

        # Forward. An upstream failure fails closed but is an operational
        # error, not an attack: it is audited yet does NOT count toward
        # containment (a flaky tool must not quarantine the session).
        try:
            result = await upstream.call_tool(name, arguments)
        except Exception as exc:  # noqa: BLE001
            in_ctx = self._build_context(
                identity, name, arguments, "inbound", call_number, history
            )
            verdict = Verdict(
                decision=Decision.BLOCK,
                rule="gateway.upstream_error",
                evidence=f"upstream call failed: {type(exc).__name__}",
            )
            incident_id = await self._record(in_ctx, verdict, started, "deterministic")
            return _blocked_result("inbound", verdict, incident_id or "unrecorded")

        # Inbound: inspect the full result before it reaches the agent.
        in_ctx = self._build_context(identity, name, arguments, "inbound", call_number, history)
        in_verdict = await self._pipeline.run(in_ctx, content=extract_inspectable_text(result))
        if not in_verdict.allowed:
            incident_id = await self._record(in_ctx, in_verdict, started, "pattern")
            await self._breaker.record_block(sid, incident_id)
            return _blocked_result("inbound", in_verdict, incident_id or "unrecorded")
        await self._record(in_ctx, in_verdict, started, "pattern")
        return result

    def build_server(
        self,
        upstream: ClientSession,
        identity_resolver: Callable[[], IdentityClaims | None] | None = None,
    ) -> Server:
        # identity_resolver lets the transport supply the request's verified
        # identity (HTTP reads the bearer token); when it returns None - or no
        # resolver is given (stdio) - the construction identity is used.
        server: Server = Server("olive")

        @server.list_tools()
        async def list_tools() -> list[types.Tool]:
            started = perf_counter()
            upstream_tools = await upstream.list_tools()
            # Tool descriptions reach the agent's context and are NOT yet
            # content-inspected (M4 gap, THREAT_MODEL.md). Audit them anyway:
            # the hash of names+descriptions makes rug-pull swaps detectable
            # in the event trail today.
            descriptions = {t.name: t.description or "" for t in upstream_tools.tools}
            ctx = self._build_context(
                self._identity, "tools/list", descriptions, "inbound", 0, ()
            )
            await self._record(ctx, ALLOW, started, "none")
            return upstream_tools.tools

        # validate_input=False: the gateway is transparent; schema validation
        # belongs to the upstream. Re-validating here would also desync if
        # the upstream evolves mid-session.
        @server.call_tool(validate_input=False)
        async def call_tool(name: str, arguments: dict | None) -> types.CallToolResult:
            identity = identity_resolver() if identity_resolver else None
            return await self.handle_call_tool(upstream, name, arguments, identity=identity)

        return server
