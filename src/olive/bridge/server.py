"""HTTP-to-MCP bridge server (ADR-0025).

Reads a YAML bridge config and exposes each configured HTTP endpoint as an MCP
tool over stdio. Olive spawns this as a subprocess upstream — from Olive's
perspective it is an ordinary MCP server.

Rule 3 compliance: raw HTTP response bodies are never logged. Error paths emit
only the status code + a bounded excerpt (≤200 chars). Successful response
bodies are returned as MCP TextContent; Olive's inbound pipeline owns hashing.

Imports: mcp SDK + httpx + olive.bridge.spec only. Must not import from
olive.gateway, olive.store, olive.intelligence, olive.fleet, or olive.identity
(ADR-0025 §6).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

import httpx
import mcp.types as types
from mcp.server import Server
from mcp.server.stdio import stdio_server

from olive.bridge.spec import BridgeConfig, BridgeToolSpec, load_bridge_config


def _input_schema(spec: BridgeToolSpec) -> dict:
    """Minimal JSON Schema derived from config — never from HTTP responses."""
    props: dict = {p: {"type": "string"} for p in spec.path_params}
    if spec.body_from_arguments:
        props["body"] = {"type": "object", "description": "JSON body for the request"}
    return {"type": "object", "properties": props}


async def _call_http(spec: BridgeToolSpec, arguments: dict) -> str:
    """Execute the HTTP request and return the response body as text.

    Raises RuntimeError with a bounded message on any failure so the caller
    can return it as MCP error content (fail closed — no silent pass-through)."""
    url = spec.url
    for param in spec.path_params:
        url = url.replace(f"{{{param}}}", str(arguments.get(param, "")))

    body_bytes: bytes | None = None
    if spec.body_from_arguments:
        body_src = arguments.get("body") or {
            k: v for k, v in arguments.items() if k not in spec.path_params
        }
        body_bytes = json.dumps(body_src).encode()

    try:
        async with httpx.AsyncClient(timeout=spec.timeout_seconds) as client:
            response = await client.request(
                method=spec.method,
                url=url,
                headers=spec.headers,
                content=body_bytes,
            )
    except httpx.TimeoutException:
        raise RuntimeError(
            f"HTTP {spec.method} timed out after {spec.timeout_seconds}s"
        )
    except httpx.RequestError as exc:
        raise RuntimeError(f"HTTP {spec.method} connection error: {str(exc)[:200]}")

    if response.status_code >= 400:
        excerpt = response.text[:200].replace("\n", " ")
        raise RuntimeError(f"HTTP {response.status_code}: {excerpt}")

    return response.text


async def list_tools_handler(config: BridgeConfig) -> list[types.Tool]:
    """Return the MCP Tool list for this config. Exposed for direct testing."""
    return [
        types.Tool(
            name=name,
            description=spec.description,
            inputSchema=_input_schema(spec),
        )
        for name, spec in config.tools.items()
    ]


async def call_tool_handler(
    config: BridgeConfig, name: str, arguments: dict | None
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    """Dispatch a tool call. Exposed for direct testing."""
    spec = config.tools.get(name)
    if spec is None:
        return [types.TextContent(type="text", text=f"[bridge error] unknown tool: {name}")]
    try:
        text = await _call_http(spec, arguments or {})
        return [types.TextContent(type="text", text=text)]
    except RuntimeError as exc:
        return [types.TextContent(type="text", text=f"[bridge error] {exc}")]


def build_bridge_server(config: BridgeConfig) -> Server:
    """Build and return the MCP Server wired to the bridge config."""
    server = Server("olive-bridge")

    @server.list_tools()
    async def _list_tools() -> list[types.Tool]:
        return await list_tools_handler(config)

    @server.call_tool()
    async def _call_tool(
        name: str, arguments: dict | None
    ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
        return await call_tool_handler(config, name, arguments)

    return server


async def _run(config_path: str) -> None:
    config = load_bridge_config(config_path)
    server = build_bridge_server(config)
    print(
        f"[olive-bridge] {len(config.tools)} tool(s): {', '.join(config.tools)}",
        file=sys.stderr,
    )
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m olive.bridge.server")
    parser.add_argument("--config", required=True, help="bridge YAML config file")
    args = parser.parse_args()
    asyncio.run(_run(args.config))


if __name__ == "__main__":
    main()
