"""Olive CLI.

    olive run --config policies/default.yaml -- python demo/tools_server.py

Spawns the upstream MCP server as a subprocess, then serves MCP over stdio
to whatever client launched us. stdout is the protocol channel - all
diagnostics go to stderr.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import sys
from contextlib import AsyncExitStack
from pathlib import Path

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.server.stdio import stdio_server

from olive.config import ConfigError, GatewayConfig, load_config
from olive.gateway.pipeline import InspectorPipeline
from olive.gateway.proxy import OliveGateway
from olive.gateway.upstreams import MultiplexUpstream, NamedUpstream
from olive.inspectors.context_policy import ContextPolicyInspector
from olive.inspectors.decode import DecodeInspector
from olive.inspectors.patterns import PatternInspector
from olive.inspectors.policy import PolicyInspector
from olive.store.events import EventStore

# Capability a token must carry to approve a remediation fix (ADR-0013). Distinct
# from olive:approve (release one held call) - approving a security fix to ship is
# a strictly larger authority, and capabilities never imply one another.
REMEDIATE_SCOPE = "olive:remediate"

_ROOT = Path(__file__).resolve().parents[2]
_EVALS = _ROOT / "evals" / "run_evals.py"


def build_pipeline(config: GatewayConfig) -> InspectorPipeline:
    """The one place the inspector chain is assembled - evals use it too,
    so measured detection always reflects the real gateway code path."""
    return InspectorPipeline(
        [
            # Coarse allowlist first (default-deny). ContextPolicyInspector runs
            # next so it can only refine an already-allowed call - restrict or
            # hold, never grant (ADR-0010). Pattern inspection (layer zero), then
            # the decode layer (0.5) which defeats deterministic obfuscation.
            PolicyInspector(config.roles),
            ContextPolicyInspector(config.context_rules),
            PatternInspector(config.injection_patterns),
            DecodeInspector(config.injection_patterns),
        ]
    )


def _resolve_specs(config: GatewayConfig, cli_command: list[str]) -> list[tuple[str, list[str]]]:
    """Upstream (name, command) pairs: from the policy's `upstreams:` if present,
    otherwise the single CLI command as an unnamed (bare-tool) upstream."""
    if config.upstreams:
        if cli_command:
            print(
                "[olive] policy defines `upstreams:`; ignoring the CLI command",
                file=sys.stderr,
            )
        return [(s.name, list(s.command)) for s in config.upstreams]
    if cli_command:
        return [("", cli_command)]
    raise ConfigError("no upstream: define `upstreams:` in the policy or pass one after `--`")


async def _connect_multiplex(
    stack: AsyncExitStack, specs: list[tuple[str, list[str]]]
) -> MultiplexUpstream:
    """Spawn every upstream subprocess on the given stack and wrap them in a
    routing multiplexer (a single upstream with an empty name = bare tools)."""
    upstreams: list[NamedUpstream] = []
    for name, command in specs:
        params = StdioServerParameters(command=command[0], args=command[1:])
        read, write = await stack.enter_async_context(stdio_client(params))
        session = await stack.enter_async_context(ClientSession(read, write))
        await session.initialize()
        upstreams.append(NamedUpstream(name=name, session=session))
    return MultiplexUpstream(upstreams)


async def run_gateway(
    config_path: str, upstream_command: list[str], db_override: str | None
) -> None:
    config = load_config(config_path)
    specs = _resolve_specs(config, upstream_command)
    db_path = db_override or config.db_path

    store = EventStore(db_path)
    await store.open()
    try:
        from olive.gateway.breaker import CircuitBreaker
        from olive.gateway.mode import OperatingMode

        breaker = CircuitBreaker(max_blocks=config.max_blocks_before_quarantine)
        for s in await store.load_sessions():
            breaker.restore(
                s["session_key"], s["block_count"], s["quarantined"],
                s["quarantine_reason"], s["quarantine_incident_id"],
            )
        saved_mode = await store.load_mode()
        if saved_mode:
            breaker.restore_mode(OperatingMode(saved_mode))
        gateway = OliveGateway(config, store, build_pipeline(config), breaker=breaker)
        print(
            f"[olive] session {gateway.session_id} | agent {config.agent_id} "
            f"| role {config.role} | upstreams: {[n or '(bare)' for n, _ in specs]}",
            file=sys.stderr,
        )
        async with AsyncExitStack() as stack:
            upstream = await _connect_multiplex(stack, specs)
            server = gateway.build_server(upstream)
            async with stdio_server() as (read, write):
                await server.run(read, write, server.create_initialization_options())
    finally:
        await store.close()


def serve_http(
    config_path: str,
    upstream_command: list[str],
    ca_pubkey_path: str,
    host: str,
    port: int,
    db_override: str | None,
    json_response: bool,
    ui: bool = False,
    control_plane_url: str | None = None,
    fleet_token: str | None = None,
) -> None:
    """Serve over streamable HTTP with bearer-token identity enforcement.

    Every request must present a CA-signed token; identity is verified on the
    wire and the gateway enforces as that identity (ADR-0007). Imports are local
    so the stdio path never pays for the HTTP/ASGI stack.

    When `ui` is set (ADR-0020) the gateway is wired LIVE: telemetry flows to the
    SentinelRunner AND the read-only Command Center, the runtime org (Commander,
    operating modes, incident bus, Defense/Remediation/Red-Team/Builder
    departments) runs in-process, and the dashboard is co-mounted on the same app
    so it shows the live incident stream. Default off — bare `serve` is unchanged.
    """
    import uvicorn

    from olive.transport.http import (
        build_http_app,
        identity_from_context,
        serving_lifespan,
        session_manager_for,
    )

    config = load_config(config_path)
    specs = _resolve_specs(config, upstream_command)
    public_key_pem = Path(ca_pubkey_path).read_bytes()
    db_path = db_override or config.db_path

    if ui:
        serve_http_live(
            config, specs, public_key_pem, host, port, db_path, json_response, build_http_app,
            control_plane_url=control_plane_url,
            fleet_token=fleet_token,
        )
        return

    @contextlib.asynccontextmanager
    async def make_resources():
        store = EventStore(db_path)
        await store.open()
        try:
            async with AsyncExitStack() as stack:
                upstream = await _connect_multiplex(stack, specs)
                gateway = OliveGateway(config, store, build_pipeline(config))
                server = gateway.build_server(upstream, identity_resolver=identity_from_context)
                yield session_manager_for(server, json_response=json_response), gateway
        finally:
            await store.close()

    app = build_http_app(public_key_pem, serving_lifespan(make_resources))
    print(
        f"[olive] serving HTTP on {host}:{port} | agent {config.agent_id} "
        f"| token-verified identity enforced",
        file=sys.stderr,
    )
    uvicorn.run(app, host=host, port=port)


def serve_http_live(
    config, specs, public_key_pem, host, port, db_path, json_response, build_http_app,
    control_plane_url: str | None = None,
    fleet_token: str | None = None,
) -> None:
    """The `olive serve --ui` assembly (ADR-0020): one process, one event loop,
    sharing ONE breaker + bus + UIBroker between the gateway and the co-mounted
    Command Center. All wiring is here at the composition root; the gateway core
    never imports the intelligence/ui layers. Works with NO ANTHROPIC_API_KEY (the
    deterministic inspectors + deterministic-first sentinels still detect)."""
    import os

    import uvicorn

    from olive.gateway.breaker import CircuitBreaker
    from olive.gateway.mode import OperatingMode
    from olive.gateway.telemetry import MultiSink, QueueSink
    from olive.identity.tokens import RevokedTokenCache
    from olive.intelligence.builder_dept import ProposalLedger
    from olive.intelligence.bus import IncidentBus
    from olive.intelligence.departments import build_runtime_org, build_sentinels
    from olive.intelligence.remediation import RemediationLedger
    from olive.transport.http import (
        identity_from_context,
        serving_lifespan_with_org,
        session_manager_for,
    )
    from olive.ui.broker import UIBroker
    from olive.ui.web import _corpus_stems, ui_routes

    corpus_dir = _ROOT / "evals" / "corpus"
    hmac_key = os.urandom(32)  # one per-process bus key, reused by every department
    # Token revocation cache (M9): created at function scope so it can be passed
    # to build_http_app; seeded from DB inside make_resources once the store opens.
    revocation = RevokedTokenCache()

    @contextlib.asynccontextmanager
    async def make_resources():
        store = EventStore(db_path)
        bus = IncidentBus(db_path, hmac_key)
        ledger = RemediationLedger(db_path)
        proposals = ProposalLedger(db_path)
        await store.open()
        await bus.open()
        await ledger.open()
        await proposals.open()
        try:
            async with AsyncExitStack() as stack:
                upstream = await _connect_multiplex(stack, specs)
                # One breaker shared by the gateway (trip/quarantine) and the org
                # (Commander.set_mode); one QueueSink to the runner + UIBroker.
                breaker = CircuitBreaker(max_blocks=config.max_blocks_before_quarantine)
                for s in await store.load_sessions():
                    breaker.restore(
                        s["session_key"], s["block_count"], s["quarantined"],
                        s["quarantine_reason"], s["quarantine_incident_id"],
                    )
                saved_mode = await store.load_mode()
                if saved_mode:
                    breaker.restore_mode(OperatingMode(saved_mode))
                # Seed the token revocation cache (M9) from DB now that the store is open.
                revocation.seed(await store.load_revoked_jtis())
                queue_sink = QueueSink()
                broker = UIBroker()

                # Fleet integration (ADR-0024): when --control-plane-url is set,
                # build a FleetSink (event push) and HeartbeatLoop (mode piggyback).
                # Both are additive and default-off; bare `serve --ui` is unchanged.
                fleet_client = None
                heartbeat_loop = None
                if control_plane_url and fleet_token:
                    from olive.fleet.client import FleetClient
                    from olive.fleet.heartbeat import HeartbeatLoop
                    from olive.fleet.sink import FleetSink
                    fleet_client = FleetClient(
                        base_url=control_plane_url,
                        gateway_id=config.agent_id,
                        org_id=getattr(config, "organization_id", ""),
                        token=fleet_token,
                        allow_insecure=control_plane_url.startswith("http://"),
                    )
                    await fleet_client.open()

                telemetry_sinks = [queue_sink, broker]
                if fleet_client is not None:
                    from olive.fleet.sink import FleetSink
                    telemetry_sinks.append(FleetSink(fleet_client))

                gateway = OliveGateway(
                    config,
                    store,
                    build_pipeline(config),
                    breaker=breaker,
                    telemetry=MultiSink(*telemetry_sinks),
                    revocations=revocation,
                )

                if fleet_client is not None:
                    from olive.fleet.heartbeat import HeartbeatLoop
                    from olive.intelligence.commander import SecurityCommander
                    # Commander is built inside build_runtime_org; we build it here
                    # first so the HeartbeatLoop can reference it. build_runtime_org
                    # accepts an externally-built commander via the heartbeat_loop arg.
                    # Simpler: pass heartbeat_loop after org is built and start manually.
                    heartbeat_loop = None  # will be set after org is built below

                org = build_runtime_org(
                    breaker=breaker,
                    bus=bus,
                    ledger=ledger,
                    queue=queue_sink.queue,
                    sentinels=build_sentinels(config, store=store),
                    store=store,
                    revocations=revocation,
                    proposal_ledger=proposals,
                    operator_bridge=True,
                )

                # Wire the heartbeat now that we have the commander reference.
                if fleet_client is not None:
                    from olive.fleet.heartbeat import HeartbeatLoop
                    heartbeat_loop = HeartbeatLoop(
                        client=fleet_client,
                        commander=org.commander,
                        breaker=breaker,
                    )
                    org.heartbeat = heartbeat_loop
                # Seed the dashboard from history, then live-subscribe.
                await _seed_broker(broker, bus)
                bus.subscribe(broker.on_incident)
                server = gateway.build_server(upstream, identity_resolver=identity_from_context)
                ui_state = {
                    "broker": broker,
                    "bus": bus,
                    "corpus": _corpus_stems(corpus_dir),
                    "revocation": revocation,  # M9: /admin/revoke reads this
                    "store": store,  # history endpoints read from this
                }
                yield (
                    session_manager_for(server, json_response=json_response),
                    gateway,
                    org,
                    ui_state,
                )
        finally:
            await proposals.close()
            await ledger.close()
            await bus.close()
            await store.close()
            if fleet_client is not None:
                await fleet_client.close()

    app = build_http_app(
        public_key_pem,
        serving_lifespan_with_org(make_resources),
        extra_routes=ui_routes(),
        revocation=revocation,
    )
    if host not in ("127.0.0.1", "localhost"):
        print(
            f"[olive] WARNING: binding {host} exposes the UNAUTHENTICATED Command "
            "Center dashboard + POST /operator to the network (ADR-0020)",
            file=sys.stderr,
        )
    print(
        f"[olive] serving HTTP + live Command Center on http://{host}:{port}/ | "
        f"agent {config.agent_id} | MCP at /mcp (token-verified)",
        file=sys.stderr,
    )
    uvicorn.run(app, host=host, port=port)


async def reset_baselines(config_path: str, db_override: str | None, tool: str | None) -> None:
    """Clear rug-pull baselines so a legitimate tool-description change can be
    re-accepted on the next listing (ADR-0009) - an operator re-approval."""
    config = load_config(config_path)
    store = EventStore(db_override or config.db_path)
    await store.open()
    try:
        # Baselines are keyed by kind (tool/resource/prompt); --tool targets the
        # tool surface, no flag clears everything.
        key = f"tool:{tool}" if tool else None
        count = await store.reset_baseline(key)
        target = f"tool '{tool}'" if tool else "all tools/resources/prompts"
        print(f"[olive] cleared {count} baseline(s) for {target}", file=sys.stderr)
    finally:
        await store.close()


def _run_eval_gate(*, update_baseline: bool = False) -> tuple[int, dict | None]:
    """Run the deterministic eval gate as a subprocess and return (exit_code,
    metrics). The remediation ledger records the *real* result of this run - there
    is no in-process path that could forge a pass (ADR-0013). Metrics come from the
    runner's `--json` line; None if it could not be parsed (treated as a fail)."""
    import json
    import subprocess

    argv = [sys.executable, str(_EVALS)]
    argv.append("--update-baseline" if update_baseline else "--json")
    proc = subprocess.run(argv, cwd=str(_ROOT), capture_output=True, text=True)
    print(proc.stderr, file=sys.stderr, end="")
    metrics: dict | None = None
    for line in reversed(proc.stdout.splitlines()):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "gate_passed" in parsed:
            metrics = parsed
            break
    return proc.returncode, metrics


async def run_cycle(args: argparse.Namespace) -> int:
    """Drive one remediation cycle (ADR-0013). Deterministic at every step:
    `verify` records the real gate result, `approve` requires a verified
    olive:remediate token, `learn` refuses without a recorded approval. The ledger
    lives on the intelligence side of the open-core seam (ADR-0003); imported here
    locally so the stdio/serve paths never pay for it."""
    from olive.intelligence.remediation import (
        RemediationError,
        RemediationLedger,
        RemediationState,
        hash_patch,
    )

    config = load_config(args.config)
    ledger = RemediationLedger(args.db or config.db_path)
    await ledger.open()
    try:
        action = args.cycle_command
        if action == "open":
            cycle = await ledger.open_cycle(args.incident, args.case)
            print(cycle.cycle_id)  # stdout: the new id, for scripting
        elif action == "propose":
            cycle = await ledger.propose_fix(
                args.cycle, patch_hash=hash_patch(args.patch), patch_summary=args.summary
            )
        elif action == "verify":
            # Check the cycle is verifiable before spending a full eval run; the
            # ledger re-checks too, so this is just to avoid wasted work.
            current = await ledger.get(args.cycle)
            if current.state is not RemediationState.FIX_PROPOSED:
                want = RemediationState.FIX_PROPOSED
                raise RemediationError(f"{args.cycle} is {current.state}; verify requires {want}")
            code, metrics = _run_eval_gate()
            passed = code == 0 and metrics is not None and metrics.get("gate_passed") is True
            cycle = await ledger.record_verification(
                args.cycle,
                gate_passed=passed,
                detected=(metrics or {}).get("detected", -1),
                false_positives=(metrics or {}).get("false_positives", -1),
            )
        elif action == "approve":
            from olive.identity.claims import claims_from_token
            from olive.identity.tokens import IdentityError

            try:
                # One-shot CLI driver: a synchronous read of a small PEM file is
                # fine here (the eval gate subprocess beside it blocks too).
                pubkey = Path(args.ca_pubkey).read_bytes()  # noqa: ASYNC240
                claims = claims_from_token(args.token, pubkey)
            except IdentityError as exc:
                print(f"[olive] approval rejected: invalid token ({exc})", file=sys.stderr)
                return 1
            if REMEDIATE_SCOPE not in claims.capabilities:
                print(
                    f"[olive] approval rejected: token lacks '{REMEDIATE_SCOPE}' capability",
                    file=sys.stderr,
                )
                return 1
            cycle = await ledger.approve(args.cycle, approved_by=claims.agent_id)
        elif action == "learn":
            cycle = await ledger.learn(args.cycle)
            # The human gate has passed; lock the win in by re-pinning the baseline
            # to the (already-merged, case-promoted) corpus. Reuses ADR-0011's only
            # baseline-moving act - the cycle tool never edits the corpus itself.
            code, _ = _run_eval_gate(update_baseline=True)
            if code != 0:
                # The cycle is LEARNED (approval passed), but the baseline re-pin
                # did not complete - exit non-zero so automation re-runs it.
                print(cycle.render(), file=sys.stderr)
                print(
                    "[olive] baseline update returned non-zero; re-run "
                    "`python evals/run_evals.py --update-baseline`",
                    file=sys.stderr,
                )
                return 1
        elif action == "show":
            cycle = await ledger.get(args.cycle)
        else:  # pragma: no cover - argparse restricts the choices
            raise RemediationError(f"unknown cycle action {action!r}")
        print(cycle.render(), file=sys.stderr)
        return 0
    except RemediationError as exc:
        print(f"[olive] {exc}", file=sys.stderr)
        return 1
    finally:
        await ledger.close()


async def run_redteam(args: argparse.Namespace) -> int:
    """Run a deterministic red-team campaign against Olive's own pipeline
    (ADR-0015) and surface bypasses as `known-miss` candidate cases. Offline and
    authorized-testing-only; the engine has no enforcement-write path, so this
    can only ever produce backlog, never weaken detection. Imported locally so
    the gateway paths never pull the engine in."""
    import yaml

    from olive.redteam import run_campaign
    from olive.redteam.engine import RedTeamError, load_known_keys

    # Candidate payloads can contain non-ASCII (homoglyph attacks); the protocol
    # channel is not in use for this command, so make stdout UTF-8 safe.
    with contextlib.suppress(AttributeError, ValueError):
        sys.stdout.reconfigure(encoding="utf-8")

    corpus_dir = Path(args.corpus) if args.corpus else _ROOT / "evals" / "corpus"
    known = load_known_keys(corpus_dir)
    try:
        report = await run_campaign(policy=args.policy, known_keys=known)
    except RedTeamError as exc:
        print(f"[olive] {exc}", file=sys.stderr)
        return 1
    print(report.render(), file=sys.stderr)

    if args.emit:
        try:
            emit_dir = _emit_candidates(args.emit, report.novel)
        except ValueError as exc:
            print(f"[olive] {exc}", file=sys.stderr)
            return 1
        print(
            f"[olive] wrote {len(report.novel)} candidate case(s) to {emit_dir} "
            "(review, then commit as known-miss)",
            file=sys.stderr,
        )
    else:
        for bypass in report.novel:  # stdout: review the candidate YAML
            print("---")
            print(yaml.safe_dump(bypass.candidate(), sort_keys=False, allow_unicode=True))
    return 0


def _emit_candidates(emit_arg: str, novel: list) -> Path:
    """Write known-miss candidate YAML to a quarantine dir for human review (gate
    1). Sync (filesystem) helper. Refuses to write into the live corpus - the
    engine produces backlog for review, it never commits a case itself."""
    import yaml

    emit_dir = Path(emit_arg).resolve()
    corpus_root = (_ROOT / "evals" / "corpus").resolve()
    if emit_dir == corpus_root or corpus_root in emit_dir.parents:
        raise ValueError(
            "refusing to emit into evals/corpus (or below it); pick a quarantine "
            "dir for human review before committing"
        )
    emit_dir.mkdir(parents=True, exist_ok=True)
    for bypass in novel:
        cand = bypass.candidate()
        (emit_dir / f"{cand['id']}.yaml").write_text(
            yaml.safe_dump(cand, sort_keys=False, allow_unicode=True), encoding="utf-8"
        )
    return emit_dir


async def run_redteam_dept(args: argparse.Namespace) -> int:
    """Trigger the runtime Red-Team department once (ADR-0016): run a sandbox
    campaign and publish novel findings onto the incident bus. This is the
    external (CI/operator) trigger surface; the scheduler loop calls the same
    `run_once`. Sandbox-only by construction - the engine attacks `build_pipeline`,
    never the live gateway. Imported locally (intelligence side of the seam)."""
    import os

    from olive.intelligence.bus import IncidentBus
    from olive.intelligence.redteam_dept import RedTeamDepartment

    config = load_config(args.config)
    bus = IncidentBus(args.db or config.db_path, os.urandom(32))
    await bus.open()
    try:
        dept = RedTeamDepartment(
            bus, policy=args.policy, corpus_dir=_ROOT / "evals" / "corpus"
        )
        published = await dept.run_once()
        if published is None:
            print(
                "[olive] red-team department: skipped, a campaign is already in flight",
                file=sys.stderr,
            )
            return 0
        print(
            f"[olive] red-team department: campaign run, {published} novel finding(s) "
            "published to the bus (awaiting human triage)",
            file=sys.stderr,
        )
        for row in await bus.history():
            if row["kind"] == "redteam-finding":
                print(f"  {row['object_id']}: {row['evidence']}", file=sys.stderr)
        return 0
    finally:
        await bus.close()


async def run_builder_dept(args: argparse.Namespace) -> int:
    """Trigger the runtime Builder department once (ADR-0018): replay the bus
    history and publish a `fix-proposed` object for every NOVEL confirmed weakness
    (red-team findings + reproduced incidents). Propose-only by construction - it
    records a bounded proposal + publishes awareness, never applies a fix; the
    human `olive cycle` gate is unchanged. Imported locally (intelligence side)."""
    import os

    from olive.intelligence.builder_dept import BuilderDepartment, ProposalLedger
    from olive.intelligence.bus import IncidentBus

    config = load_config(args.config)
    db_path = args.db or config.db_path
    bus = IncidentBus(db_path, os.urandom(32))
    ledger = ProposalLedger(db_path)
    await bus.open()
    await ledger.open()
    try:
        dept = BuilderDepartment(bus, ledger)
        published = await dept.run_once()
        print(
            f"[olive] builder department: {published} novel fix-proposal(s) "
            "published to the bus (awaiting human triage via `olive cycle`)",
            file=sys.stderr,
        )
        for proposal in await ledger.list_proposals():
            print(f"  {proposal.proposal_id}: {proposal.summary}", file=sys.stderr)
        return 0
    finally:
        await ledger.close()
        await bus.close()


async def _seed_broker(broker, bus) -> None:
    """Replay non-UI-request history from the audit log into the broker on startup."""
    from olive.ui.broker import UIEvent

    for row in await bus.history():
        if row["kind"] == "operator-request":
            continue
        broker.seed(
            UIEvent(
                kind=row["kind"],
                evidence=row["evidence"],
                timestamp=row["created_at"],
                source_dept=row["source_dept"],
                object_id=row["object_id"],
                confidence=row["confidence"],
                attack_types=tuple(filter(None, (row["attack_types"] or "").split(","))),
            )
        )


async def run_ui(args: argparse.Namespace) -> int:
    """Launch the Agentic Command Center (ADR-0017/0019). Without --web: a
    read-only Textual TUI. With --web: a Starlette/WebSocket server pushing
    UIEvents to a browser dashboard. Both modes seed from audit log history and
    subscribe to the IncidentBus for live events."""
    import os

    from olive.intelligence.bus import IncidentBus
    from olive.ui.broker import UIBroker

    config = load_config(args.config)
    bus = IncidentBus(args.db or config.db_path, os.urandom(32))
    await bus.open()
    from olive.store.events import EventStore

    store = EventStore(args.db or config.db_path)
    await store.open()
    try:
        broker = UIBroker()
        await _seed_broker(broker, bus)
        bus.subscribe(broker.on_incident)
        corpus_dir = _ROOT / "evals" / "corpus"

        if getattr(args, "web", False):
            import uvicorn

            from olive.ui.web import build_app

            app = build_app(broker, bus=bus, corpus_dir=corpus_dir, store=store)
            host = getattr(args, "host", "127.0.0.1")
            port = getattr(args, "port", 7700)
            print(
                f"[olive] Agentic Command Center web dashboard at http://{host}:{port}",
                file=sys.stderr,
            )
            cfg = uvicorn.Config(app, host=host, port=port, log_level="warning")
            server = uvicorn.Server(cfg)
            await server.serve()
        else:
            from olive.ui.app import CommandCenterApp

            tui = CommandCenterApp(broker, bus=bus, corpus_dir=corpus_dir)
            await tui.run_async()
        return 0
    finally:
        await store.close()
        await bus.close()


async def _run_control_plane(args: argparse.Namespace) -> None:
    """Launch the fleet control plane (ADR-0024).

    Imported locally so gateway paths never pull in the fleet layer."""
    import uvicorn

    from olive.fleet.control_plane import build_control_plane_app
    from olive.fleet.registry import GatewayRegistry

    ca_pubkey = Path(args.ca_pubkey).read_bytes()
    policies_dir = Path(args.policies_dir) if args.policies_dir else Path("policies")
    db_path = args.db

    registry = GatewayRegistry(db_path)
    await registry.open()
    try:
        app = build_control_plane_app(registry, ca_pubkey, policies_dir)
        print(
            f"[olive] fleet control plane on http://{args.host}:{args.port} | "
            f"DB: {db_path} | policies: {policies_dir}",
            file=sys.stderr,
        )
        cfg = uvicorn.Config(app, host=args.host, port=args.port, log_level="warning")
        server = uvicorn.Server(cfg)
        await server.serve()
    finally:
        await registry.close()


def main() -> None:
    parser = argparse.ArgumentParser(prog="olive")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run the gateway over stdio in front of an upstream")
    run.add_argument("--config", required=True, help="policy YAML file")
    run.add_argument("--db", default=None, help="override audit DB path from the policy file")
    run.add_argument(
        "upstream",
        nargs=argparse.REMAINDER,
        help="upstream MCP server command (prefix with --)",
    )

    serve = sub.add_parser(
        "serve", help="serve over streamable HTTP with bearer-token identity enforcement"
    )
    serve.add_argument("--config", required=True, help="policy YAML file")
    serve.add_argument("--ca-pubkey", required=True, help="PEM file of the issuing CA public key")
    serve.add_argument("--host", default="127.0.0.1", help="bind host (default 127.0.0.1)")
    serve.add_argument("--port", type=int, default=8080, help="bind port (default 8080)")
    serve.add_argument("--db", default=None, help="override audit DB path from the policy file")
    serve.add_argument(
        "--sse",
        action="store_true",
        help="use SSE streaming responses instead of JSON (default JSON)",
    )
    serve.add_argument(
        "--ui",
        "--web",
        dest="ui",
        action="store_true",
        help="run the live Command Center: wire the runtime org in-process and "
        "co-mount the read-only dashboard at / (ADR-0020). Loopback-only by default",
    )
    serve.add_argument(
        "--control-plane-url",
        default=None,
        metavar="URL",
        help="fleet control-plane base URL (https://…); enables heartbeat + event push (ADR-0024). "
        "Requires --fleet-token. http:// is accepted only with --allow-insecure.",
    )
    serve.add_argument(
        "--fleet-token",
        default=None,
        metavar="TOKEN",
        help="CA-signed bearer token carrying olive:fleet capability for control-plane auth",
    )
    serve.add_argument(
        "upstream",
        nargs=argparse.REMAINDER,
        help="upstream MCP server command (prefix with --)",
    )

    cp = sub.add_parser(
        "control-plane",
        help="run the fleet control plane: heartbeat receiver, event aggregator, "
        "and fleet dashboard API (ADR-0024)",
    )
    cp.add_argument("--ca-pubkey", required=True, help="PEM file of the issuing CA public key")
    cp.add_argument("--host", default="127.0.0.1", help="bind host (default 127.0.0.1)")
    cp.add_argument("--port", type=int, default=9090, help="bind port (default 9090)")
    cp.add_argument(
        "--db", default="fleet.db", help="control plane SQLite DB path (default fleet.db)"
    )
    cp.add_argument(
        "--policies-dir",
        default=None,
        metavar="DIR",
        help="directory containing role YAML files served at GET /fleet/policy/{role} "
        "(default: policies/ relative to the current directory)",
    )

    reset = sub.add_parser(
        "reset-baselines",
        help="clear rug-pull tool baselines so a legitimate change is re-accepted",
    )
    reset.add_argument("--config", required=True, help="policy YAML file")
    reset.add_argument("--db", default=None, help="override audit DB path from the policy file")
    reset.add_argument("--tool", default=None, help="a single tool name (default: all)")

    cycle = sub.add_parser(
        "cycle", help="drive one remediation cycle (Reproduce->Repair->Verify->Learn, ADR-0013)"
    )
    cycle.add_argument("--config", required=True, help="policy YAML file")
    cycle.add_argument("--db", default=None, help="override audit DB path from the policy file")
    cyc = cycle.add_subparsers(dest="cycle_command", required=True)

    c_open = cyc.add_parser("open", help="start a cycle from a reproduced incident")
    c_open.add_argument("--incident", required=True, help="the incident id being remediated")
    c_open.add_argument("--case", required=True, help="the reproduced corpus case id")

    c_propose = cyc.add_parser("propose", help="record a builder's proposed fix (diff hash)")
    c_propose.add_argument("--cycle", required=True, help="cycle id (CYC-NNNN)")
    c_propose.add_argument("--patch", required=True, help="path to the proposed diff/patch file")
    c_propose.add_argument("--summary", required=True, help="bounded one-line summary of the fix")

    c_verify = cyc.add_parser(
        "verify", help="run the deterministic eval gate and record the result"
    )
    c_verify.add_argument("--cycle", required=True, help="cycle id (CYC-NNNN)")

    c_approve = cyc.add_parser("approve", help="human approval, gated on an olive:remediate token")
    c_approve.add_argument("--cycle", required=True, help="cycle id (CYC-NNNN)")
    c_approve.add_argument(
        "--ca-pubkey", required=True, help="PEM file of the issuing CA public key"
    )
    c_approve.add_argument(
        "--token", required=True, help="CA-signed token carrying olive:remediate"
    )

    c_learn = cyc.add_parser("learn", help="lock the win in (requires a recorded approval)")
    c_learn.add_argument("--cycle", required=True, help="cycle id (CYC-NNNN)")

    c_show = cyc.add_parser("show", help="print a cycle's current state")
    c_show.add_argument("--cycle", required=True, help="cycle id (CYC-NNNN)")

    redteam = sub.add_parser(
        "redteam",
        help="run a deterministic red-team campaign against Olive's own pipeline (ADR-0015)",
    )
    rt = redteam.add_subparsers(dest="redteam_command", required=True)
    rt_run = rt.add_parser("run", help="attack the real pipeline and surface bypasses")
    rt_run.add_argument("--policy", default="default.yaml", help="policy file under policies/")
    rt_run.add_argument(
        "--corpus", default=None, help="corpus dir for dedup (default evals/corpus)"
    )
    rt_run.add_argument(
        "--emit",
        default=None,
        help="write known-miss candidate cases to this quarantine dir (default: print to stdout)",
    )

    redteam_dept = sub.add_parser(
        "redteam-dept",
        help="trigger the runtime Red-Team department: a sandbox campaign that "
        "publishes findings onto the incident bus (ADR-0016)",
    )
    rtd = redteam_dept.add_subparsers(dest="redteam_dept_command", required=True)
    rtd_run = rtd.add_parser("run", help="run one sandbox campaign now and publish findings")
    rtd_run.add_argument("--config", required=True, help="policy YAML file (for the audit DB path)")
    rtd_run.add_argument("--db", default=None, help="override audit DB path from the policy file")
    rtd_run.add_argument("--policy", default="default.yaml", help="pipeline policy under policies/")

    builder_dept = sub.add_parser(
        "builder-dept",
        help="trigger the runtime Builder department: replay the bus and publish a "
        "fix-proposal for each novel confirmed weakness (ADR-0018)",
    )
    bd = builder_dept.add_subparsers(dest="builder_dept_command", required=True)
    bd_run = bd.add_parser("run", help="propose fixes now for novel confirmed weaknesses")
    bd_run.add_argument("--config", required=True, help="policy YAML file (for the audit DB path)")
    bd_run.add_argument("--db", default=None, help="override audit DB path from the policy file")

    ui = sub.add_parser(
        "ui",
        help="launch the Agentic Command Center: Textual TUI (default) or web dashboard "
        "(--web) over the incident bus + audit log (ADR-0017/0019)",
    )
    ui.add_argument("--config", required=True, help="policy YAML file (for the audit DB path)")
    ui.add_argument("--db", default=None, help="override audit DB path from the policy file")
    ui.add_argument(
        "--web", action="store_true",
        help="serve a browser dashboard (Starlette/WebSocket) instead of the Textual TUI",
    )
    ui.add_argument(
        "--host", default="127.0.0.1",
        help="bind host for --web mode (default 127.0.0.1 — loopback only; "
        "exposing to 0.0.0.0 requires a network boundary, no auth is built in)",
    )
    ui.add_argument(
        "--port", type=int, default=7700, help="bind port for --web mode (default 7700)"
    )

    args = parser.parse_args()

    if args.command == "cycle":
        try:
            sys.exit(asyncio.run(run_cycle(args)))
        except ConfigError as exc:
            parser.error(str(exc))
        return

    if args.command == "redteam":
        sys.exit(asyncio.run(run_redteam(args)))

    if args.command == "redteam-dept":
        try:
            sys.exit(asyncio.run(run_redteam_dept(args)))
        except ConfigError as exc:
            parser.error(str(exc))
        return

    if args.command == "builder-dept":
        try:
            sys.exit(asyncio.run(run_builder_dept(args)))
        except ConfigError as exc:
            parser.error(str(exc))
        return

    if args.command == "ui":
        try:
            sys.exit(asyncio.run(run_ui(args)))
        except ConfigError as exc:
            parser.error(str(exc))
        return

    if args.command == "control-plane":
        asyncio.run(_run_control_plane(args))
        return

    if args.command == "reset-baselines":
        try:
            asyncio.run(reset_baselines(args.config, args.db, args.tool))
        except ConfigError as exc:
            parser.error(str(exc))
        return
    # An upstream may come from the policy's `upstreams:` instead of the CLI, so
    # an empty command is allowed here; _resolve_specs enforces "at least one".
    upstream = [part for part in args.upstream if part != "--"]

    try:
        if args.command == "serve":
            serve_http(
                args.config,
                upstream,
                args.ca_pubkey,
                args.host,
                args.port,
                args.db,
                json_response=not args.sse,
                ui=args.ui,
                control_plane_url=getattr(args, "control_plane_url", None),
                fleet_token=getattr(args, "fleet_token", None),
            )
        else:
            asyncio.run(run_gateway(args.config, upstream, args.db))
    except ConfigError as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
