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
from pathlib import Path

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.server.stdio import stdio_server

from olive.config import GatewayConfig, load_config
from olive.gateway.pipeline import InspectorPipeline
from olive.gateway.proxy import OliveGateway
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


async def run_gateway(
    config_path: str, upstream_command: list[str], db_override: str | None
) -> None:
    config = load_config(config_path)
    db_path = db_override or config.db_path

    store = EventStore(db_path)
    await store.open()
    try:
        gateway = OliveGateway(config, store, build_pipeline(config))
        print(
            f"[olive] session {gateway.session_id} | agent {config.agent_id} "
            f"| role {config.role} | upstream trust: {config.upstream_trust}",
            file=sys.stderr,
        )

        params = StdioServerParameters(command=upstream_command[0], args=upstream_command[1:])
        async with stdio_client(params) as (upstream_read, upstream_write):
            async with ClientSession(upstream_read, upstream_write) as upstream:
                await upstream.initialize()
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
    public_key_pem = Path(ca_pubkey_path).read_bytes()
    db_path = db_override or config.db_path

    @contextlib.asynccontextmanager
    async def make_resources():
        store = EventStore(db_path)
        await store.open()
        try:
            params = StdioServerParameters(
                command=upstream_command[0], args=upstream_command[1:]
            )
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as upstream:
                    await upstream.initialize()
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

    args = parser.parse_args()
    upstream = [part for part in args.upstream if part != "--"]
    if not upstream:
        parser.error(
            "missing upstream server command,"
            " e.g.: olive run --config p.yaml -- python server.py"
        )

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


if __name__ == "__main__":
    main()
