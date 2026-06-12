"""Shield Wall CLI.

    shieldwall run --config policies/default.yaml -- python demo/tools_server.py

Spawns the upstream MCP server as a subprocess, then serves MCP over stdio
to whatever client launched us. stdout is the protocol channel - all
diagnostics go to stderr.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.server.stdio import stdio_server

from shieldwall.config import GatewayConfig, load_config
from shieldwall.gateway.pipeline import InspectorPipeline
from shieldwall.gateway.proxy import ShieldWallGateway
from shieldwall.inspectors.patterns import PatternInspector
from shieldwall.inspectors.policy import PolicyInspector
from shieldwall.store.events import EventStore


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
        gateway = ShieldWallGateway(config, store, build_pipeline(config))
        print(
            f"[shieldwall] session {gateway.session_id} | agent {config.agent_id} "
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


def main() -> None:
    parser = argparse.ArgumentParser(prog="shieldwall")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run the gateway in front of an upstream MCP server")
    run.add_argument("--config", required=True, help="policy YAML file")
    run.add_argument("--db", default=None, help="override audit DB path from the policy file")
    run.add_argument(
        "upstream",
        nargs=argparse.REMAINDER,
        help="upstream MCP server command (prefix with --)",
    )

    args = parser.parse_args()
    upstream = [part for part in args.upstream if part != "--"]
    if not upstream:
        parser.error(
            "missing upstream server command,"
            " e.g.: shieldwall run --config p.yaml -- python server.py"
        )

    asyncio.run(run_gateway(args.config, upstream, args.db))


if __name__ == "__main__":
    main()
