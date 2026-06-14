"""HTTP transport tests - wire identity enforcement (ADR-0007, slice 4b)."""

from __future__ import annotations

import contextlib

import httpx
import mcp.types as types
import pytest

from olive.config import GatewayConfig
from olive.gateway.pipeline import InspectorPipeline
from olive.gateway.proxy import OliveGateway
from olive.identity.tokens import MockCA
from olive.inspectors.patterns import PatternInspector
from olive.inspectors.policy import PolicyInspector, RolePolicy
from olive.store.events import EventStore
from olive.transport.http import (
    OliveTokenVerifier,
    build_http_app,
    identity_from_context,
    serving_lifespan,
    session_manager_for,
)


class StubUpstream:
    def __init__(self, response_text: str = "clean response") -> None:
        self.response_text = response_text
        self.calls: list[str] = []

    async def call_tool(self, name, arguments=None):
        self.calls.append(name)
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=self.response_text)]
        )

    async def list_tools(self):
        return types.ListToolsResult(
            tools=[types.Tool(name="read_faq", description="FAQ", inputSchema={"type": "object"})]
        )


def make_config() -> GatewayConfig:
    return GatewayConfig(
        agent_id="cfg-agent",
        organization_id="cfg-org",
        role="customer-support",
        declared_goal="testing",
        db_path=":memory:",
        upstream_trust="untrusted",
        roles={
            "customer-support": RolePolicy(
                allowed_tools=frozenset({"read_faq"}),
                forbidden_tools=frozenset({"access_payroll"}),
            )
        },
        injection_patterns=["ignore previous instructions"],
    )


def issue(ca: MockCA, **overrides) -> str:
    defaults = dict(
        agent_id="http-agent",
        organization="demo-company",
        role="customer-support",
        session_id="sess-http",
        capabilities=["read_faq"],
    )
    defaults.update(overrides)
    return ca.issue(**defaults)


@pytest.fixture
def ca() -> MockCA:
    return MockCA()


@pytest.fixture
async def app_ctx(tmp_path, ca):
    """Yields (app, store, upstream) with the lifespan ready to run."""
    store = EventStore(tmp_path / "events.db")
    await store.open()
    upstream = StubUpstream()

    @contextlib.asynccontextmanager
    async def make_resources():
        config = make_config()
        pipeline = InspectorPipeline(
            [PolicyInspector(config.roles), PatternInspector(config.injection_patterns)]
        )
        gateway = OliveGateway(config, store, pipeline)
        server = gateway.build_server(upstream, identity_resolver=identity_from_context)
        yield session_manager_for(server, json_response=True), gateway

    app = build_http_app(ca.public_key_pem(), serving_lifespan(make_resources))
    try:
        yield app, store, upstream
    finally:
        await store.close()


# ---- unit: verifier --------------------------------------------------------


async def test_verifier_accepts_valid_token(ca):
    verifier = OliveTokenVerifier(ca.public_key_pem())
    access = await verifier.verify_token(issue(ca))
    assert access is not None
    assert access.subject == "http-agent"
    assert access.claims["role"] == "customer-support"
    assert "read_faq" in access.scopes


async def test_verifier_rejects_forged_and_garbage(ca):
    verifier = OliveTokenVerifier(ca.public_key_pem())
    assert await verifier.verify_token("not-a-jwt") is None
    other = MockCA()
    assert await OliveTokenVerifier(other.public_key_pem()).verify_token(issue(ca)) is None


# ---- wire enforcement ------------------------------------------------------


async def test_mcp_endpoint_rejects_unauthenticated(app_ctx):
    app, _, upstream = app_ctx
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://olive.test") as client:
            resp = await client.post(
                "/mcp",
                json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                headers={"Accept": "application/json, text/event-stream"},
            )
    assert resp.status_code == 401
    assert upstream.calls == [], "no token must never reach the gateway/upstream"


async def test_mcp_endpoint_rejects_forged_token(app_ctx, ca):
    app, _, upstream = app_ctx
    forged = MockCA().issue(  # signed by a different CA
        agent_id="x", organization="o", role="customer-support",
        session_id="s", capabilities=["read_faq"],
    )
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://olive.test") as client:
            resp = await client.post(
                "/mcp",
                json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                headers={
                    "Authorization": f"Bearer {forged}",
                    "Accept": "application/json, text/event-stream",
                },
            )
    assert resp.status_code == 401
    assert upstream.calls == []


# ---- admin release ---------------------------------------------------------


async def test_admin_release_requires_capability(app_ctx, ca):
    app, _, _ = app_ctx
    body = {"organization": "o", "agent_id": "a", "session_id": "sess-x"}
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://olive.test") as client:
            # no token
            assert (await client.post("/admin/release", json=body)).status_code == 401
            # valid token without the release capability
            plain = issue(ca, capabilities=["read_faq"])
            r = await client.post(
                "/admin/release", json=body, headers={"Authorization": f"Bearer {plain}"}
            )
            assert r.status_code == 403
            # token carrying the release capability
            admin = issue(ca, agent_id="ops", capabilities=["olive:release"])
            r = await client.post(
                "/admin/release", json=body, headers={"Authorization": f"Bearer {admin}"}
            )
            assert r.status_code == 200
            assert r.json()["session_id"] == "sess-x"
            assert r.json()["released"] is False  # no such quarantined session


# ---- end-to-end: real MCP handshake over HTTP, in-process -----------------


async def test_end_to_end_authenticated_enforcement(app_ctx, ca, tmp_path):
    import sqlite3

    from mcp.client.session import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    app, _, upstream = app_ctx
    token = issue(ca, agent_id="wire-agent", session_id="sess-wire", capabilities=["read_faq"])

    def factory(headers=None, timeout=None, auth=None):
        return httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://olive.test",
            headers=headers,
            timeout=timeout,
        )

    async with app.router.lifespan_context(app):
        async with streamablehttp_client(
            "http://olive.test/mcp",
            headers={"Authorization": f"Bearer {token}"},
            httpx_client_factory=factory,
            timeout=5,
        ) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                allowed = await session.call_tool("read_faq", {"q": "policy"})
                forbidden = await session.call_tool("access_payroll", {})

    assert not allowed.isError
    assert forbidden.isError, "forbidden tool blocked under the wire identity"
    assert upstream.calls == ["read_faq"], "forbidden call never forwarded upstream"

    # The audit trail records the verified token identity, not the config one.
    db = sqlite3.connect(tmp_path / "events.db")
    rows = db.execute("SELECT DISTINCT agent_id, session_id FROM events").fetchall()
    db.close()
    assert ("wire-agent", "sess-wire") in rows
