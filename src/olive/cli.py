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
from olive.inspectors.patterns import PatternInspector
from olive.inspectors.policy import PolicyInspector
from olive.store.events import EventStore


def build_pipeline(config: GatewayConfig) -> InspectorPipeline:
    """The one place the inspector chain is assembled - evals use it too,
    so measured detection always reflects the real gateway code path."""
    return InspectorPipeline(
        [
            PolicyInspector(config.roles),
            PatternInspector(config.injection_patterns),
        ]
    )


def _resolve_specs(
    config: GatewayConfig, cli_command: list[str]
) -> list[tuple[str, list[str]]]:
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
    raise ConfigError(
        "no upstream: define `upstreams:` in the policy or pass one after `--`"
    )


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
                server = gateway.build_server(
                    upstream, identity_resolver=identity_from_context
                )
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

    args = parser.parse_args()

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
