"""Multi-upstream multiplexing (ADR-0008).

`MultiplexUpstream` presents several upstream MCP servers to the gateway as a
single one: tools are namespaced `"<name>.<tool>"` and `tools/call` is routed
back to the owning server. It implements the same `list_tools`/`call_tool`
surface the gateway already uses, so the proxy stays unchanged.

A single upstream with an empty name yields bare tool names - identical to
talking to that server directly (single-upstream back-compat).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

import mcp.types as types

SEPARATOR = "."


class UpstreamSession(Protocol):
    """The subset of an MCP ClientSession the gateway uses."""

    async def list_tools(self) -> types.ListToolsResult: ...
    async def call_tool(
        self, name: str, arguments: dict | None = None
    ) -> types.CallToolResult: ...
    async def list_resources(self) -> types.ListResourcesResult: ...
    async def read_resource(self, uri) -> types.ReadResourceResult: ...
    async def list_prompts(self) -> types.ListPromptsResult: ...
    async def get_prompt(
        self, name: str, arguments: dict | None = None
    ) -> types.GetPromptResult: ...


class UnknownUpstreamError(Exception):
    """A namespaced tool could not be routed to an upstream. The gateway treats
    this as fail-closed (its upstream-error path blocks the call)."""


@dataclass(frozen=True, slots=True)
class NamedUpstream:
    name: str  # namespace prefix; "" only allowed when it is the sole upstream
    session: UpstreamSession


class MultiplexUpstream:
    def __init__(self, upstreams: list[NamedUpstream]) -> None:
        if not upstreams:
            raise ValueError("at least one upstream is required")
        if len(upstreams) > 1:
            names = [u.name for u in upstreams]
            if any(not n for n in names):
                raise ValueError("every upstream needs a non-empty name when there are several")
            if any(SEPARATOR in n for n in names):
                raise ValueError(f"upstream names must not contain '{SEPARATOR}'")
            if len(set(names)) != len(names):
                raise ValueError("upstream names must be unique")
        self._by_name = {u.name: u for u in upstreams}
        self._single = upstreams[0] if len(upstreams) == 1 else None

    def _namespaced(self, name: str, tool: str) -> str:
        return tool if name == "" else f"{name}{SEPARATOR}{tool}"

    def _route(self, namespaced: str) -> tuple[NamedUpstream, str]:
        # Single upstream: names are passed through verbatim (bare).
        if self._single is not None:
            return self._single, namespaced
        prefix, sep, bare = namespaced.partition(SEPARATOR)
        upstream = self._by_name.get(prefix) if sep else None
        if upstream is None:
            raise UnknownUpstreamError(namespaced)
        return upstream, bare

    async def list_tools(self) -> types.ListToolsResult:
        tools: list[types.Tool] = []
        for upstream in self._by_name.values():
            result = await upstream.session.list_tools()
            for tool in result.tools:
                namespaced = self._namespaced(upstream.name, tool.name)
                tools.append(tool.model_copy(update={"name": namespaced}))
        return types.ListToolsResult(tools=tools)

    async def call_tool(
        self, name: str, arguments: dict | None = None
    ) -> types.CallToolResult:
        upstream, bare = self._route(name)  # raises UnknownUpstreamError -> fail closed
        return await upstream.session.call_tool(bare, arguments)

    # --- prompts: namespaced by name, exactly like tools -------------------

    async def list_prompts(self) -> types.ListPromptsResult:
        prompts: list[types.Prompt] = []
        for upstream in self._by_name.values():
            result = await upstream.session.list_prompts()
            for prompt in result.prompts:
                namespaced = self._namespaced(upstream.name, prompt.name)
                prompts.append(prompt.model_copy(update={"name": namespaced}))
        return types.ListPromptsResult(prompts=prompts)

    async def get_prompt(
        self, name: str, arguments: dict | None = None
    ) -> types.GetPromptResult:
        upstream, bare = self._route(name)
        return await upstream.session.get_prompt(bare, arguments)

    # --- resources: aggregated; URIs are not prefixed (assumed unique). A
    #     read is routed by trying each upstream until one owns the URI. -----

    async def list_resources(self) -> types.ListResourcesResult:
        resources: list[types.Resource] = []
        for upstream in self._by_name.values():
            result = await upstream.session.list_resources()
            resources.extend(result.resources)
        return types.ListResourcesResult(resources=resources)

    async def read_resource(self, uri) -> types.ReadResourceResult:
        if self._single is not None:
            return await self._single.session.read_resource(uri)
        last_error: Exception | None = None
        for upstream in self._by_name.values():
            try:
                return await upstream.session.read_resource(uri)
            except Exception as exc:  # noqa: BLE001 - try the next owner
                last_error = exc
        raise UnknownUpstreamError(str(uri)) from last_error
