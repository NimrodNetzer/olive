"""Bridge tests — spec loading, server tool dispatch, and layering rule (ADR-0025)."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from olive.bridge.spec import BridgeConfig, BridgeToolSpec, load_bridge_config
from olive.bridge.server import (
    _call_http,
    _input_schema,
    build_bridge_server,
    call_tool_handler,
    list_tools_handler,
)


# ---- spec: load_bridge_config -----------------------------------------------


def _write_config(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "bridge.yaml"
    p.write_text(textwrap.dedent(content), encoding="utf-8")
    return p


def test_load_minimal_config(tmp_path):
    p = _write_config(tmp_path, """
        tools:
          ping:
            method: GET
            url: "https://api.test/ping"
    """)
    cfg = load_bridge_config(p)
    assert "ping" in cfg.tools
    spec = cfg.tools["ping"]
    assert spec.method == "GET"
    assert spec.url == "https://api.test/ping"
    assert spec.path_params == ()
    assert spec.timeout_seconds == 30.0
    assert spec.description == "HTTP GET https://api.test/ping"


def test_load_full_config(tmp_path, monkeypatch):
    monkeypatch.setenv("MY_TOKEN", "tok123")
    p = _write_config(tmp_path, """
        tools:
          get_user:
            method: GET
            url: "https://api.test/users/{user_id}"
            path_params: [user_id]
            headers:
              Authorization: "Bearer ${MY_TOKEN}"
            description: "Fetch a user by ID"
            timeout_seconds: 10
    """)
    cfg = load_bridge_config(p)
    spec = cfg.tools["get_user"]
    assert spec.path_params == ("user_id",)
    assert spec.headers["Authorization"] == "Bearer tok123"
    assert spec.description == "Fetch a user by ID"
    assert spec.timeout_seconds == 10.0


def test_load_env_var_missing_raises(tmp_path):
    p = _write_config(tmp_path, """
        tools:
          t:
            method: GET
            url: "https://x.test/"
            headers:
              Authorization: "Bearer ${MISSING_VAR_XYZ}"
    """)
    with pytest.raises(ValueError, match="MISSING_VAR_XYZ"):
        load_bridge_config(p)


def test_load_invalid_method_raises(tmp_path):
    p = _write_config(tmp_path, """
        tools:
          t:
            method: CONNECT
            url: "https://x.test/"
    """)
    with pytest.raises(ValueError, match="invalid method"):
        load_bridge_config(p)


def test_load_missing_url_raises(tmp_path):
    p = _write_config(tmp_path, """
        tools:
          t:
            method: GET
    """)
    with pytest.raises(ValueError, match="url"):
        load_bridge_config(p)


def test_load_body_from_arguments(tmp_path):
    p = _write_config(tmp_path, """
        tools:
          create:
            method: POST
            url: "https://api.test/items"
            body_from_arguments: true
    """)
    cfg = load_bridge_config(p)
    assert cfg.tools["create"].body_from_arguments is True


# ---- spec: _input_schema -------------------------------------------------------


def test_input_schema_path_params():
    spec = BridgeToolSpec(method="GET", url="https://x/{id}", path_params=("id",))
    schema = _input_schema(spec)
    assert schema["properties"]["id"] == {"type": "string"}
    assert "body" not in schema["properties"]


def test_input_schema_body():
    spec = BridgeToolSpec(method="POST", url="https://x/", body_from_arguments=True)
    schema = _input_schema(spec)
    assert "body" in schema["properties"]


# ---- server: _call_http -------------------------------------------------------


async def _fake_response(status: int, text: str):
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status
    resp.text = text
    return resp


async def test_call_http_success():
    spec = BridgeToolSpec(method="GET", url="https://api.test/ping")

    with patch("olive.bridge.server.httpx.AsyncClient") as MockClient:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '{"ok": true}'
        cm = AsyncMock()
        cm.__aenter__ = AsyncMock(return_value=AsyncMock(request=AsyncMock(return_value=mock_resp)))
        cm.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = cm

        result = await _call_http(spec, {})
    assert result == '{"ok": true}'


async def test_call_http_path_param_substitution():
    spec = BridgeToolSpec(
        method="GET",
        url="https://api.test/users/{user_id}",
        path_params=("user_id",),
    )
    called_url: list[str] = []

    async def fake_request(method, url, headers, content):
        called_url.append(url)
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "ok"
        return resp

    with patch("olive.bridge.server.httpx.AsyncClient") as MockClient:
        mock_client = AsyncMock()
        mock_client.request = fake_request
        MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

        await _call_http(spec, {"user_id": "42"})

    assert called_url == ["https://api.test/users/42"]


async def test_call_http_4xx_raises():
    spec = BridgeToolSpec(method="GET", url="https://api.test/gone")

    with patch("olive.bridge.server.httpx.AsyncClient") as MockClient:
        mock_client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 404
        resp.text = "Not Found"
        mock_client.request = AsyncMock(return_value=resp)
        MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

        with pytest.raises(RuntimeError, match="404"):
            await _call_http(spec, {})


async def test_call_http_timeout_raises():
    spec = BridgeToolSpec(method="GET", url="https://slow.test/", timeout_seconds=5.0)

    with patch("olive.bridge.server.httpx.AsyncClient") as MockClient:
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(side_effect=httpx.TimeoutException("timed out"))
        MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
        MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

        with pytest.raises(RuntimeError, match="timed out"):
            await _call_http(spec, {})


# ---- server: build_bridge_server / MCP dispatch -----------------------------


def _make_config(*tool_names: str, method: str = "GET") -> BridgeConfig:
    return BridgeConfig(
        tools={
            name: BridgeToolSpec(method=method, url=f"https://api.test/{name}")
            for name in tool_names
        }
    )


async def test_list_tools_returns_all_configured():
    config = _make_config("alpha", "beta")
    result = await list_tools_handler(config)
    names = {t.name for t in result}
    assert names == {"alpha", "beta"}


async def test_call_tool_returns_text_content():
    config = _make_config("ping")

    with patch("olive.bridge.server._call_http", new=AsyncMock(return_value='{"pong": 1}')):
        result = await call_tool_handler(config, "ping", {})

    assert len(result) == 1
    assert result[0].text == '{"pong": 1}'


async def test_call_tool_unknown_returns_error_content():
    config = _make_config("ping")
    result = await call_tool_handler(config, "no_such_tool", {})
    assert "[bridge error]" in result[0].text


async def test_call_tool_http_error_returns_error_content():
    config = _make_config("ping")

    with patch(
        "olive.bridge.server._call_http",
        new=AsyncMock(side_effect=RuntimeError("HTTP 503: service unavailable")),
    ):
        result = await call_tool_handler(config, "ping", {})

    assert "[bridge error]" in result[0].text
    assert "503" in result[0].text


# ---- layering rule (ADR-0025 §6) --------------------------------------------


def test_bridge_does_not_import_gateway_core():
    """olive.bridge must not import from olive.gateway, olive.store,
    olive.intelligence, olive.fleet, or olive.identity."""
    import importlib
    import sys

    forbidden_prefixes = (
        "olive.gateway",
        "olive.store",
        "olive.intelligence",
        "olive.fleet",
        "olive.identity",
        "olive.inspectors",
    )
    # Reload bridge modules to get a fresh import set
    for mod_name in list(sys.modules):
        if mod_name.startswith("olive.bridge"):
            importlib.reload(sys.modules[mod_name])

    bridge_imports = {
        k for k in sys.modules
        if k.startswith("olive.bridge")
    }
    # Collect all modules that bridge modules import transitively
    # (checking directly imported modules is sufficient for the layering rule)
    import olive.bridge.spec as spec_mod
    import olive.bridge.server as server_mod

    for mod in (spec_mod, server_mod):
        for attr in vars(mod).values():
            mod_name = getattr(attr, "__module__", "") or ""
            for prefix in forbidden_prefixes:
                assert not mod_name.startswith(prefix), (
                    f"{mod.__name__} imports from {mod_name} (forbidden by ADR-0025 §6)"
                )


def test_gateway_core_does_not_import_bridge():
    """olive.gateway (and olive.store, olive.inspectors) must not import olive.bridge."""
    import sys
    for mod_name, mod in sys.modules.items():
        if not mod_name.startswith(("olive.gateway", "olive.store", "olive.inspectors")):
            continue
        for attr in vars(mod or {}).values():
            imported_from = getattr(attr, "__module__", "") or ""
            assert not imported_from.startswith("olive.bridge"), (
                f"{mod_name} imports from olive.bridge (forbidden by ADR-0025 §6 / ADR-0003)"
            )
