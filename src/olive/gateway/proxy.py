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
from hashlib import sha256
from time import perf_counter

import mcp.types as types
from mcp.client.session import ClientSession
from mcp.server.lowlevel import Server

from olive.config import GatewayConfig
from olive.gateway.approvals import ApprovalRegistry, approval_key
from olive.gateway.breaker import CircuitBreaker
from olive.gateway.context import Direction, SecurityContext, hash_arguments
from olive.gateway.pipeline import ALLOW, Decision, InspectorPipeline, Verdict, bound_evidence
from olive.gateway.ratelimit import RateLimiter
from olive.gateway.resources import extract_resource
from olive.gateway.telemetry import NullSink, TelemetryEvent, TelemetrySink
from olive.identity.claims import IdentityClaims, unverified_from_config
from olive.store.events import BaselineStatus, EventStore

_ATTACK_TYPE_BY_RULE_PREFIX = {
    "policy.": "privilege-escalation",
    "patterns.": "prompt-injection",
    "decode.": "prompt-injection",
    "context.": "authorization-violation",
}


def _attack_type(verdict: Verdict) -> str:
    rule = verdict.rule or ""
    for prefix, attack_type in _ATTACK_TYPE_BY_RULE_PREFIX.items():
        if rule.startswith(prefix):
            return attack_type
    return "unknown"


def _inspectable_tool_text(tool: types.Tool) -> str:
    """Every textual surface of a tool declaration the agent's context ingests:
    name, description, and input schema (a poisoned parameter description is an
    injection vector too). Serialize the whole declaration so nothing is missed."""
    return tool.model_dump_json()


def _resource_contents_text(result: types.ReadResourceResult) -> str:
    """Text surfaces of a resource read. Binary blobs are out of scope for text
    inspection; their metadata is still serialized (mirrors tool results)."""
    parts: list[str] = []
    for item in result.contents:
        if isinstance(item, types.TextResourceContents):
            parts.append(item.text)
        else:  # BlobResourceContents - never inspect/echo the blob bytes
            parts.append(item.model_dump_json(exclude={"blob"}))
    return "\n".join(parts)


def _prompt_messages_text(result: types.GetPromptResult) -> str:
    """Text surfaces of a rendered prompt - the messages injected into context."""
    parts: list[str] = []
    if result.description:
        parts.append(result.description)
    for message in result.messages:
        content = message.content
        if isinstance(content, types.TextContent):
            parts.append(content.text)
        elif isinstance(content, types.ImageContent | types.AudioContent):
            parts.append(content.model_dump_json(exclude={"data"}))
        else:
            parts.append(content.model_dump_json())
    return "\n".join(parts)


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


def _held_result(verdict: Verdict, approval_id: str) -> types.CallToolResult:
    # A governance pause (ADR-0010), not an attack: the call is not executed and
    # awaits operator approval. Rule + approval id only, never evidence. The
    # operator approves this id; the agent may then retry the same call.
    message = (
        f"[Olive] action held for approval by rule '{verdict.rule}'. "
        f"Approval {approval_id} is pending; an operator must approve before "
        "this call can proceed, then retry."
    )
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=message)],
        isError=True,
    )


def _blocked_resource(uri, incident_id: str) -> types.ServerResult:
    # Sanitized: the poisoned resource content is replaced, never delivered.
    message = f"[Olive] resource blocked by content inspection. Incident {incident_id} logged."
    return types.ServerResult(
        types.ReadResourceResult(
            contents=[types.TextResourceContents(uri=uri, text=message, mimeType="text/plain")]
        )
    )


def _blocked_prompt(incident_id: str) -> types.ServerResult:
    # Sanitized: the poisoned prompt messages are replaced, never delivered.
    message = f"[Olive] prompt blocked by content inspection. Incident {incident_id} logged."
    return types.ServerResult(
        types.GetPromptResult(
            description="blocked by Olive",
            messages=[
                types.PromptMessage(
                    role="user", content=types.TextContent(type="text", text=message)
                )
            ],
        )
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
        approvals: ApprovalRegistry | None = None,
        telemetry: TelemetrySink | None = None,
    ) -> None:
        self._config = config
        self._store = store
        self._pipeline = pipeline
        # The one outbound channel to the advisory parallel path (ADR-0012). The
        # default no-op sink means the gateway enforces identically with the
        # intelligence layer absent (ADR-0003 open-core seam).
        self._telemetry = telemetry or NullSink()
        # The single authority over pending-hold approvals (ADR-0010). Consulted
        # only when a HOLD verdict fires; an operator approval releases one
        # specific held call.
        self._approvals = approvals or ApprovalRegistry()
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
        self._breaker = breaker or CircuitBreaker(max_blocks=config.max_blocks_before_quarantine)
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

    async def release_session(self, key: str | None = None) -> bool:
        """Reversible human release of a quarantined session (ADR-0006). `key`
        is the namespaced session key (see IdentityClaims.session_key); defaults
        to this gateway's own identity for the stdio case."""
        resolved = key or self._identity.session_key
        released = await self._breaker.release(resolved)
        if released:
            await self._store.delete_session(resolved)
        return released

    @property
    def approvals(self) -> ApprovalRegistry:
        return self._approvals

    async def approve_hold(self, approval_id: str) -> bool:
        """Operator approval of one held call (ADR-0010). Returns True if a
        pending hold was marked approved. The capability check (`olive:approve`)
        is enforced by the admin surface, mirroring session release. No LLM may
        call this path (ADR-0005)."""
        return await self._approvals.approve(approval_id)

    def _build_context(
        self,
        identity: IdentityClaims,
        tool: str,
        arguments: dict | None,
        direction: Direction,
        call_number: int,
        history: tuple[str, ...],
    ) -> SecurityContext:
        # Lift only the declared scoping id into a structured ResourceRef
        # (ADR-0010); the raw arguments never travel further than this boundary.
        requested_resource = extract_resource(tool, self._config.resource_extractors, arguments)
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
            requested_resource=requested_resource,
            task_resources=identity.task_resources,
        )

    async def _record(
        self,
        ctx: SecurityContext,
        verdict: Verdict,
        started: float,
        detection_method: str,
        attack_type: str | None = None,
    ) -> str | None:
        latency_ms = int((perf_counter() - started) * 1000)
        incident_id: str | None = None
        if not verdict.allowed:
            incident_id = await self._store.create_incident(
                ctx,
                verdict,
                attack_type=attack_type or _attack_type(verdict),
                detection_method=detection_method,
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

    async def _log_held(self, ctx: SecurityContext, verdict: Verdict, started: float) -> None:
        # A hold is audited as a `hold` event but, like a throttle, mints no
        # incident and does NOT count toward quarantine (ADR-0010): it is a
        # governance pause awaiting approval, not an attack. Never silent (rule 5).
        latency_ms = int((perf_counter() - started) * 1000)
        await self._store.log_event(ctx, verdict, latency_ms, None)

    async def _emit(
        self,
        ctx: SecurityContext,
        verdict: Verdict,
        session_key: str,
        content: str | None = None,
        arguments: dict | None = None,
    ) -> None:
        # Publish to the parallel path. Telemetry is observability, not
        # enforcement: the decision has already been made and logged, so a sink
        # failure must never affect this call - swallow everything (no stdout in
        # stdio mode). Losing an event degrades detection, never correctness.
        try:
            await self._telemetry.publish(
                TelemetryEvent(
                    ctx=ctx,
                    verdict=verdict,
                    content=content,
                    arguments=arguments,
                    session_key=session_key,
                )
            )
        except Exception:  # noqa: BLE001 - telemetry must never break the gateway
            pass

    async def _screen_declaration(
        self,
        identity: IdentityClaims,
        name: str,
        declaration: str,
        started: float,
        kind: str,
    ) -> bool:
        """Inspect a declaration (tool/resource/prompt) that the agent's context
        ingests. Returns True if safe to expose; on a poisoned declaration or a
        rug-pull (ADR-0009) it records an incident and returns False (withhold).
        Shared by every `*/list` surface so they enforce identically."""
        ctx = self._build_context(identity, name, {"name": name}, "inbound", 0, ())
        verdict = await self._pipeline.run(ctx, content=declaration)
        if not verdict.allowed:
            await self._record(ctx, verdict, started, "pattern", attack_type=f"{kind}-poisoning")
            return False
        status = await self._store.observe_tool(
            f"{kind}:{name}", sha256(declaration.encode("utf-8")).hexdigest()
        )
        if status is BaselineStatus.CHANGED:
            rug = Verdict(
                decision=Decision.BLOCK,
                rule=f"{kind}s.rug_pull",
                evidence=bound_evidence(
                    f"{kind} '{name}' declaration changed since first seen"
                ),
            )
            await self._record(ctx, rug, started, "baseline", attack_type=f"{kind}-rug-pull")
            return False
        return True

    async def _screen_inbound_content(
        self, identity: IdentityClaims, name: str, text: str, started: float
    ) -> str | None:
        """Inspect untrusted content flowing back to the agent (resource read /
        prompt get). Returns an incident id if it must be blocked, else None
        (and logs the allow). Mirrors the inbound leg of a tool call."""
        ctx = self._build_context(identity, name, {"name": name}, "inbound", 0, ())
        verdict = await self._pipeline.run(ctx, content=text)
        return await self._record(ctx, verdict, started, "pattern")

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
        # Containment keys on the namespaced (org, agent, session) triple so a
        # reused session_id across tenants can't share quarantine/rate state.
        sid = identity.session_key
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
        # A hold is a governance pause, not a block: the call is withheld and
        # audited, but it is not an attack - no incident, no breaker trip
        # (ADR-0010). If an operator has already approved this exact call, the
        # approval is consumed (one-shot) and the call proceeds; otherwise it is
        # registered as pending and withheld until approved out-of-band.
        if out_verdict.decision is Decision.HOLD:
            akey = approval_key(sid, name, out_ctx.arguments_hash)
            if await self._approvals.consume(akey):
                # Operator-approved: proceed down the allowed path below, which
                # records this ALLOW verdict once and forwards the call.
                out_verdict = Verdict(Decision.ALLOW, rule="approval.granted")
            else:
                approval_id = await self._approvals.register(
                    akey, sid, name, out_ctx.arguments_hash, out_verdict.rule
                )
                await self._log_held(out_ctx, out_verdict, started)
                return _held_result(out_verdict, approval_id)
        if not out_verdict.allowed:
            incident_id = await self._record(out_ctx, out_verdict, started, "deterministic")
            tripped = await self._breaker.record_block(sid, incident_id)
            if tripped:
                state = self._breaker.snapshot(sid)
                if state is not None:
                    await self._store.persist_session(
                        sid, state.block_count, state.quarantined,
                        state.quarantine_reason, state.quarantine_incident_id,
                    )
            await self._emit(out_ctx, out_verdict, sid, arguments=arguments)
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
        # Outbound arguments to the parallel path (Data-Leak / Behavior sentinels).
        await self._emit(out_ctx, out_verdict, sid, arguments=arguments)
        history = (*history, name)

        # Forward. An upstream failure fails closed but is an operational
        # error, not an attack: it is audited yet does NOT count toward
        # containment (a flaky tool must not quarantine the session).
        try:
            result = await upstream.call_tool(name, arguments)
        except Exception as exc:  # noqa: BLE001
            in_ctx = self._build_context(identity, name, arguments, "inbound", call_number, history)
            verdict = Verdict(
                decision=Decision.BLOCK,
                rule="gateway.upstream_error",
                evidence=f"upstream call failed: {type(exc).__name__}",
            )
            incident_id = await self._record(in_ctx, verdict, started, "deterministic")
            return _blocked_result("inbound", verdict, incident_id or "unrecorded")

        # Inbound: inspect the full result before it reaches the agent.
        in_ctx = self._build_context(identity, name, arguments, "inbound", call_number, history)
        inbound_text = extract_inspectable_text(result)
        in_verdict = await self._pipeline.run(in_ctx, content=inbound_text)
        if not in_verdict.allowed:
            incident_id = await self._record(in_ctx, in_verdict, started, "pattern")
            tripped = await self._breaker.record_block(sid, incident_id)
            if tripped:
                state = self._breaker.snapshot(sid)
                if state is not None:
                    await self._store.persist_session(
                        sid, state.block_count, state.quarantined,
                        state.quarantine_reason, state.quarantine_incident_id,
                    )
            await self._emit(in_ctx, in_verdict, sid, content=inbound_text)
            return _blocked_result("inbound", in_verdict, incident_id or "unrecorded")
        await self._record(in_ctx, in_verdict, started, "pattern")
        # Inbound content to the parallel path (Prompt-Injection Sentinel).
        await self._emit(in_ctx, in_verdict, sid, content=inbound_text)
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
            identity = (identity_resolver() if identity_resolver else None) or self._identity

            # M3: tool names/descriptions/schemas are injected into the agent's
            # context by every MCP client, so they are untrusted content. Inspect
            # each tool; a poisoned one is WITHHELD from the listing (never
            # reaching the agent) and logged as an incident. Clean tools pass.
            safe: list[types.Tool] = []
            for tool in upstream_tools.tools:
                if await self._screen_declaration(
                    identity, tool.name, _inspectable_tool_text(tool), started, "tool"
                ):
                    safe.append(tool)

            # One aggregate audit row for the listing surface; hashing all
            # names+descriptions keeps rug-pull swaps detectable in the trail.
            descriptions = {t.name: t.description or "" for t in upstream_tools.tools}
            summary_ctx = self._build_context(
                identity, "tools/list", descriptions, "inbound", 0, ()
            )
            await self._record(summary_ctx, ALLOW, started, "pattern")
            return safe

        # validate_input=False: the gateway is transparent; schema validation
        # belongs to the upstream. Re-validating here would also desync if
        # the upstream evolves mid-session.
        @server.call_tool(validate_input=False)
        async def call_tool(name: str, arguments: dict | None) -> types.CallToolResult:
            identity = identity_resolver() if identity_resolver else None
            return await self.handle_call_tool(upstream, name, arguments, identity=identity)

        def _identity() -> IdentityClaims:
            return (identity_resolver() if identity_resolver else None) or self._identity

        # Resources & prompts (M3): also untrusted surfaces. Listings are
        # screened like tool declarations (poison/rug-pull -> withheld); read/get
        # content is inspected like a tool response (poison -> sanitized result).
        # Handlers are registered directly so upstream results pass through
        # faithfully except when blocked.
        async def handle_list_resources(
            req: types.ListResourcesRequest,
        ) -> types.ServerResult:
            started = perf_counter()
            identity = _identity()
            result = await upstream.list_resources()
            safe = [
                r
                for r in result.resources
                if await self._screen_declaration(
                    identity, str(r.uri), r.model_dump_json(), started, "resource"
                )
            ]
            return types.ServerResult(types.ListResourcesResult(resources=safe))

        async def handle_read_resource(
            req: types.ReadResourceRequest,
        ) -> types.ServerResult:
            started = perf_counter()
            identity = _identity()
            uri = req.params.uri
            try:
                result = await upstream.read_resource(uri)
            except Exception as exc:  # noqa: BLE001 - fail closed
                ctx = self._build_context(identity, str(uri), {"uri": str(uri)}, "inbound", 0, ())
                verdict = Verdict(
                    decision=Decision.BLOCK,
                    rule="gateway.upstream_error",
                    evidence=f"read_resource failed: {type(exc).__name__}",
                )
                await self._record(ctx, verdict, started, "deterministic")
                return _blocked_resource(uri, "unrecorded")
            incident = await self._screen_inbound_content(
                identity, str(uri), _resource_contents_text(result), started
            )
            if incident is not None:
                return _blocked_resource(uri, incident)
            return types.ServerResult(result)

        async def handle_list_prompts(
            req: types.ListPromptsRequest,
        ) -> types.ServerResult:
            started = perf_counter()
            identity = _identity()
            result = await upstream.list_prompts()
            safe = [
                p
                for p in result.prompts
                if await self._screen_declaration(
                    identity, p.name, p.model_dump_json(), started, "prompt"
                )
            ]
            return types.ServerResult(types.ListPromptsResult(prompts=safe))

        async def handle_get_prompt(req: types.GetPromptRequest) -> types.ServerResult:
            started = perf_counter()
            identity = _identity()
            name = req.params.name
            try:
                result = await upstream.get_prompt(name, req.params.arguments)
            except Exception as exc:  # noqa: BLE001 - fail closed
                ctx = self._build_context(identity, name, {"name": name}, "inbound", 0, ())
                verdict = Verdict(
                    decision=Decision.BLOCK,
                    rule="gateway.upstream_error",
                    evidence=f"get_prompt failed: {type(exc).__name__}",
                )
                await self._record(ctx, verdict, started, "deterministic")
                return _blocked_prompt("unrecorded")
            incident = await self._screen_inbound_content(
                identity, name, _prompt_messages_text(result), started
            )
            if incident is not None:
                return _blocked_prompt(incident)
            return types.ServerResult(result)

        server.request_handlers[types.ListResourcesRequest] = handle_list_resources
        server.request_handlers[types.ReadResourceRequest] = handle_read_resource
        server.request_handlers[types.ListPromptsRequest] = handle_list_prompts
        server.request_handlers[types.GetPromptRequest] = handle_get_prompt
        return server
