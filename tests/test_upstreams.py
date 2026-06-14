"""MultiplexUpstream unit tests (ADR-0008)."""

from __future__ import annotations

import mcp.types as types
import pytest

from olive.gateway.upstreams import (
    MultiplexUpstream,
    NamedUpstream,
    UnknownUpstreamError,
)


class StubSession:
    def __init__(
        self,
        tool_names: list[str],
        text: str = "ok",
        prompt_names: list[str] | None = None,
        resource_uri: str | None = None,
    ) -> None:
        self._tool_names = tool_names
        self._text = text
        self._prompt_names = prompt_names or []
        self._resource_uri = resource_uri
        self.calls: list[str] = []
        self.prompt_calls: list[str] = []
        self.resource_reads: list[str] = []

    async def list_tools(self) -> types.ListToolsResult:
        return types.ListToolsResult(
            tools=[
                types.Tool(name=n, description=f"{n} desc", inputSchema={"type": "object"})
                for n in self._tool_names
            ]
        )

    async def call_tool(self, name, arguments=None) -> types.CallToolResult:
        self.calls.append(name)
        return types.CallToolResult(content=[types.TextContent(type="text", text=self._text)])

    async def list_prompts(self) -> types.ListPromptsResult:
        return types.ListPromptsResult(
            prompts=[types.Prompt(name=n, description=f"{n} desc") for n in self._prompt_names]
        )

    async def get_prompt(self, name, arguments=None) -> types.GetPromptResult:
        self.prompt_calls.append(name)
        return types.GetPromptResult(
            messages=[
                types.PromptMessage(
                    role="user", content=types.TextContent(type="text", text=self._text)
                )
            ]
        )

    async def list_resources(self) -> types.ListResourcesResult:
        if self._resource_uri is None:
            return types.ListResourcesResult(resources=[])
        return types.ListResourcesResult(
            resources=[types.Resource(uri=self._resource_uri, name="r")]
        )

    async def read_resource(self, uri) -> types.ReadResourceResult:
        self.resource_reads.append(str(uri))
        if self._resource_uri is None or str(uri) != self._resource_uri:
            raise KeyError(f"not my resource: {uri}")
        return types.ReadResourceResult(
            contents=[types.TextResourceContents(uri=uri, text=self._text, mimeType="text/plain")]
        )


async def test_single_unnamed_upstream_is_bare_passthrough():
    s = StubSession(["read_faq"])
    mux = MultiplexUpstream([NamedUpstream("", s)])
    tools = (await mux.list_tools()).tools
    assert [t.name for t in tools] == ["read_faq"]  # no prefix
    await mux.call_tool("read_faq", {})
    assert s.calls == ["read_faq"]  # forwarded verbatim


async def test_multi_upstream_namespaces_tools():
    files = StubSession(["read_file"])
    db = StubSession(["read_file", "query"])  # same tool name as files!
    mux = MultiplexUpstream([NamedUpstream("files", files), NamedUpstream("db", db)])
    names = sorted(t.name for t in (await mux.list_tools()).tools)
    assert names == ["db.query", "db.read_file", "files.read_file"]


async def test_calls_route_to_the_owning_upstream():
    files = StubSession(["read_file"], text="from-files")
    db = StubSession(["read_file"], text="from-db")
    mux = MultiplexUpstream([NamedUpstream("files", files), NamedUpstream("db", db)])

    r = await mux.call_tool("db.read_file", {"x": 1})
    assert r.content[0].text == "from-db"
    assert db.calls == ["read_file"] and files.calls == []  # prefix stripped, routed


async def test_tool_name_containing_separator_routes_on_first_segment():
    s = StubSession(["a.b"])  # upstream tool already has a dot
    mux = MultiplexUpstream([NamedUpstream("ns", s), NamedUpstream("other", StubSession([]))])
    await mux.call_tool("ns.a.b", {})
    assert s.calls == ["a.b"]  # split on first separator only


async def test_unknown_prefix_fails_closed():
    mux = MultiplexUpstream(
        [NamedUpstream("files", StubSession([])), NamedUpstream("db", StubSession([]))]
    )
    with pytest.raises(UnknownUpstreamError):
        await mux.call_tool("nope.read_file", {})


async def test_prompts_are_namespaced_and_routed():
    a = StubSession([], text="from-a", prompt_names=["greet"])
    b = StubSession([], text="from-b", prompt_names=["greet"])  # same prompt name
    mux = MultiplexUpstream([NamedUpstream("a", a), NamedUpstream("b", b)])

    names = sorted(p.name for p in (await mux.list_prompts()).prompts)
    assert names == ["a.greet", "b.greet"]

    result = await mux.get_prompt("b.greet", {})
    assert result.messages[0].content.text == "from-b"
    assert b.prompt_calls == ["greet"] and a.prompt_calls == []  # routed, prefix stripped


async def test_resources_aggregated_and_read_routed():
    a = StubSession([], text="res-a", resource_uri="file:///a.txt")
    b = StubSession([], text="res-b", resource_uri="file:///b.txt")
    mux = MultiplexUpstream([NamedUpstream("a", a), NamedUpstream("b", b)])

    uris = sorted(str(r.uri) for r in (await mux.list_resources()).resources)
    assert uris == ["file:///a.txt", "file:///b.txt"]

    # read tries each upstream until the owner returns it
    result = await mux.read_resource("file:///b.txt")
    assert result.contents[0].text == "res-b"


async def test_unknown_resource_read_fails_closed():
    a = StubSession([], resource_uri="file:///a.txt")
    b = StubSession([], resource_uri="file:///b.txt")
    mux = MultiplexUpstream([NamedUpstream("a", a), NamedUpstream("b", b)])
    with pytest.raises(UnknownUpstreamError):
        await mux.read_resource("file:///nope.txt")


def test_validation_rejects_bad_configurations():
    def u(name: str) -> NamedUpstream:
        return NamedUpstream(name, StubSession([]))

    with pytest.raises(ValueError):
        MultiplexUpstream([])
    with pytest.raises(ValueError):  # empty name with several upstreams
        MultiplexUpstream([u(""), u("db")])
    with pytest.raises(ValueError):  # duplicate names
        MultiplexUpstream([u("x"), u("x")])
    with pytest.raises(ValueError):  # name contains the separator
        MultiplexUpstream([u("a.b"), u("c")])
