"""End-to-end over real MCP stdio: client -> gateway subprocess -> demo server.

This is the walking-skeleton acceptance test: a real MCP client, the real
gateway binary, the real demo tool server, real protocol on the wire.

Note: the gateway session is opened inside each test body (not a fixture)
because anyio cancel scopes must enter and exit in the same task -
pytest-asyncio finalizes async-generator fixtures in a different task.
"""

from __future__ import annotations

import sqlite3
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import mcp.types as types
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

ROOT = Path(__file__).parent.parent


@asynccontextmanager
async def gateway_session(db_path: Path):
    params = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "olive.cli",
            "run",
            "--config",
            str(ROOT / "policies" / "default.yaml"),
            "--db",
            str(db_path),
            "--",
            sys.executable,
            str(ROOT / "demo" / "tools_server.py"),
        ],
        cwd=str(ROOT),
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield session


def text_of(result: types.CallToolResult) -> str:
    return "".join(b.text for b in result.content if isinstance(b, types.TextContent))


async def test_walking_skeleton(tmp_path):
    async with gateway_session(tmp_path / "e2e_events.db") as session:
        # tools/list is proxied from the real upstream
        tools = await session.list_tools()
        names = {t.name for t in tools.tools}
        assert {"read_faq", "access_payroll", "read_file"} <= names

        # 1. legitimate call passes through with real content
        faq = await session.call_tool("read_faq", {"topic": "returns"})
        assert not faq.isError
        assert "30 days" in text_of(faq)

        # 2. forbidden tool blocked outbound - simulated payroll never leaks
        payroll = await session.call_tool("access_payroll", {"scope": "all"})
        assert payroll.isError
        assert "PAYROLL" not in text_of(payroll)
        assert "Olive" in text_of(payroll)

        # 3. poisoned document blocked inbound - injection never reaches client
        poisoned = await session.call_tool("read_file", {"name": "external_brief.txt"})
        assert poisoned.isError
        assert "ignore previous instructions" not in text_of(poisoned).lower()

        # clean document still flows
        safe = await session.call_tool("read_file", {"name": "safe_document.txt"})
        assert not safe.isError
        assert "onboarding" in text_of(safe).lower()


async def test_audit_trail_written(tmp_path):
    db_path = tmp_path / "e2e_events.db"
    async with gateway_session(db_path) as session:
        await session.call_tool("read_faq", {"topic": "returns"})
        await session.call_tool("access_payroll", {"scope": "all"})

    db = sqlite3.connect(db_path)
    try:
        decisions = db.execute(
            "SELECT tool, direction, decision FROM events ORDER BY rowid"
        ).fetchall()
        incidents = db.execute("SELECT attack_type FROM incidents").fetchall()
    finally:
        db.close()

    assert ("read_faq", "outbound", "allow") in decisions
    assert ("read_faq", "inbound", "allow") in decisions
    assert ("access_payroll", "outbound", "block") in decisions
    assert ("privilege-escalation",) in incidents
