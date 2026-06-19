"""LangChain adapter for Olive-protected tools (ADR-0028).

Wraps an Olive HTTP gateway as a set of LangChain BaseTool instances.
Any LangChain agent that uses these tools automatically gets Olive's full
inspection and enforcement without any changes to the gateway or the agent.

Usage::

    from olive.adapters.langchain import OliveToolkit

    toolkit = OliveToolkit(gateway_url="http://localhost:7800/mcp", token="<jwt>")
    tools = toolkit.get_tools()   # list[BaseTool]

`langchain-core` is an optional dependency. Install with::

    pip install olive[langchain]

The adapter raises `ImportError` (with instructions) if langchain-core is absent.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass  # avoid hard dep at import time


def _require_langchain() -> Any:
    try:
        import langchain_core.tools as lc_tools  # noqa: PLC0415
        return lc_tools
    except ImportError as exc:
        raise ImportError(
            "langchain-core is required for OliveToolkit. "
            "Install it with: pip install olive[langchain]"
        ) from exc


def _require_httpx() -> Any:
    try:
        import httpx  # noqa: PLC0415
        return httpx
    except ImportError as exc:
        raise ImportError(
            "httpx is required for OliveToolkit. "
            "Install it with: pip install httpx"
        ) from exc


class _OliveTool:
    """Internal: a single Olive-protected tool wrapped as a LangChain BaseTool.

    Constructed by OliveToolkit.get_tools(); do not instantiate directly.
    """

    def __init__(
        self,
        name: str,
        description: str,
        input_schema: dict,
        gateway_url: str,
        token: str | None,
    ) -> None:
        self._name = name
        self._description = description
        self._input_schema = input_schema
        self._gateway_url = gateway_url.rstrip("/")
        self._token = token

    def _as_base_tool(self) -> Any:
        lc_tools = _require_langchain()
        httpx = _require_httpx()
        gateway_url = self._gateway_url
        token = self._token
        tool_name = self._name
        tool_desc = self._description

        class _Wrapped(lc_tools.BaseTool):
            name: str = tool_name
            description: str = tool_desc

            def _run(self, **kwargs: Any) -> str:  # type: ignore[override]
                headers: dict[str, str] = {"Content-Type": "application/json"}
                if token:
                    headers["Authorization"] = f"Bearer {token}"
                payload = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": tool_name, "arguments": kwargs},
                }
                resp = httpx.post(
                    f"{gateway_url}",
                    content=json.dumps(payload),
                    headers=headers,
                    timeout=30,
                )
                resp.raise_for_status()
                data = resp.json()
                if "error" in data:
                    raise RuntimeError(f"Olive gateway error: {data['error']}")
                result = data.get("result", {})
                content = result.get("content", [])
                parts = [
                    block.get("text", "")
                    for block in content
                    if block.get("type") == "text"
                ]
                return "\n".join(parts) if parts else json.dumps(result)

        return _Wrapped()


class OliveToolkit:
    """Fetch and wrap all tools from an Olive HTTP gateway as LangChain BaseTools.

    Parameters
    ----------
    gateway_url:
        The MCP endpoint of the Olive HTTP gateway
        (e.g. ``http://localhost:7800/mcp``).
    token:
        Bearer JWT for the gateway (required when dashboard-token auth is
        enabled; omit for unauthenticated localhost-only gateways).
    """

    def __init__(self, gateway_url: str, token: str | None = None) -> None:
        self._gateway_url = gateway_url.rstrip("/")
        self._token = token

    def _list_tools(self) -> list[dict]:
        """Call tools/list on the gateway and return the raw tool dicts."""
        httpx = _require_httpx()
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {},
        }
        resp = httpx.post(
            self._gateway_url,
            content=json.dumps(payload),
            headers=headers,
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        if "error" in data:
            raise RuntimeError(f"Olive gateway error: {data['error']}")
        return data.get("result", {}).get("tools", [])

    def get_tools(self) -> list[Any]:
        """Return a `BaseTool` instance for each tool the gateway exposes."""
        _require_langchain()  # validate dep before network call
        raw_tools = self._list_tools()
        result = []
        for t in raw_tools:
            wrapped = _OliveTool(
                name=t["name"],
                description=t.get("description", ""),
                input_schema=t.get("inputSchema", {}),
                gateway_url=self._gateway_url,
                token=self._token,
            )
            result.append(wrapped._as_base_tool())
        return result
