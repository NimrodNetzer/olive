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
        gateway = OliveGateway(config, store, build_pipeline(config))
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
) -> None:
    """Serve over streamable HTTP with bearer-token identity enforcement.

    Every request must present a CA-signed token; identity is verified on the
    wire and the gateway enforces as that identity (ADR-0007). Imports are local
    so the stdio path never pays for the HTTP/ASGI stack.
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


async def run_ui(args: argparse.Namespace) -> int:
    """Launch the Agentic Command Center (ADR-0017): a read-only Textual TUI over
    `UIBroker`. Runs as its own process - the audit feed is seeded from
    `incident_events` history on startup, then `UIBroker` subscribes to this
    process's `IncidentBus` for live fan-out (live telemetry from a separate
    `olive run`/`serve` process is not available; only bus history/objects
    published in-process, e.g. via the attack-theater Launch button, are live).
    Imported locally (intelligence side of the seam, optional `textual` dep)."""
    import os

    from olive.intelligence.bus import IncidentBus
    from olive.ui.app import CommandCenterApp
    from olive.ui.broker import UIBroker, UIEvent

    config = load_config(args.config)
    bus = IncidentBus(args.db or config.db_path, os.urandom(32))
    await bus.open()
    try:
        broker = UIBroker()
        for row in await bus.history():
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
        bus.subscribe(broker.on_incident)
        app = CommandCenterApp(broker, bus=bus, corpus_dir=_ROOT / "evals" / "corpus")
        await app.run_async()
        return 0
    finally:
        await bus.close()


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
        "upstream",
        nargs=argparse.REMAINDER,
        help="upstream MCP server command (prefix with --)",
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

    ui = sub.add_parser(
        "ui",
        help="launch the Agentic Command Center: a read-only TUI over the "
        "incident bus + audit log (ADR-0017, requires the 'ui' extra)",
    )
    ui.add_argument("--config", required=True, help="policy YAML file (for the audit DB path)")
    ui.add_argument("--db", default=None, help="override audit DB path from the policy file")

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

    if args.command == "ui":
        try:
            sys.exit(asyncio.run(run_ui(args)))
        except ConfigError as exc:
            parser.error(str(exc))
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
            )
        else:
            asyncio.run(run_gateway(args.config, upstream, args.db))
    except ConfigError as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
