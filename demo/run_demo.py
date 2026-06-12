"""Walking-skeleton demo: a real MCP client talking to real tools THROUGH
Olive.

Spawns the gateway (which spawns the demo tool server), then drives an MCP
client through three flows:
  1. legitimate call          -> allowed, response clean
  2. privilege escalation     -> blocked outbound, upstream never contacted
  3. poisoned document read   -> allowed outbound, response blocked inbound

Run:  python demo/run_demo.py
"""

from __future__ import annotations

import asyncio
import sqlite3
import sys
from pathlib import Path

import mcp.types as types
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from rich.console import Console
from rich.table import Table

ROOT = Path(__file__).parent.parent
DB_PATH = ROOT / "demo_events.db"
CONFIG = ROOT / "policies" / "default.yaml"
TOOLS_SERVER = ROOT / "demo" / "tools_server.py"

console = Console()


def first_text(result: types.CallToolResult) -> str:
    for block in result.content:
        if isinstance(block, types.TextContent):
            return block.text
    return "<no text content>"


def report(label: str, result: types.CallToolResult) -> None:
    if result.isError:
        console.print(f"  [bold red][BLOCKED][/bold red] {label}")
        console.print(f"            [dim]{first_text(result)}[/dim]")
    else:
        console.print(f"  [bold green][ALLOWED][/bold green] {label}")
        console.print(f"            [dim]{first_text(result)[:90]}...[/dim]")


async def run() -> None:
    if DB_PATH.exists():
        DB_PATH.unlink()

    console.rule("[bold]OLIVE - walking skeleton demo")
    console.print("Gateway: real MCP proxy (stdio) | upstream: demo-tools server\n")

    params = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "olive.cli",
            "run",
            "--config",
            str(CONFIG),
            "--db",
            str(DB_PATH),
            "--",
            sys.executable,
            str(TOOLS_SERVER),
        ],
        cwd=str(ROOT),
    )

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = await session.list_tools()
            console.print(f"[cyan]tools/list[/cyan] via gateway: {[t.name for t in tools.tools]}\n")

            console.print("[bold]1. Legitimate work[/bold]")
            report(
                'read_faq("return policy")',
                await session.call_tool("read_faq", {"topic": "return policy"}),
            )
            report(
                'read_customer_order("918")',
                await session.call_tool("read_customer_order", {"order_id": "918"}),
            )

            console.print("\n[bold]2. Privilege escalation attempt[/bold]")
            report(
                'access_payroll("all_employees")',
                await session.call_tool("access_payroll", {"scope": "all_employees"}),
            )

            console.print("\n[bold]3. Poisoned document (injection in tool RESPONSE)[/bold]")
            report(
                'read_file("safe_document.txt")',
                await session.call_tool("read_file", {"name": "safe_document.txt"}),
            )
            report(
                'read_file("external_brief.txt")',
                await session.call_tool("read_file", {"name": "external_brief.txt"}),
            )

    print_audit_summary()


def print_audit_summary() -> None:
    console.print()
    console.rule("[bold]Audit trail (SQLite)")
    db = sqlite3.connect(DB_PATH)
    try:
        events = db.execute(
            "SELECT tool, direction, decision, policy_rule, incident_id FROM events ORDER BY rowid"
        ).fetchall()
        table = Table(show_header=True, header_style="bold")
        for col in ("tool", "direction", "decision", "rule", "incident"):
            table.add_column(col)
        for tool, direction, decision, rule, incident in events:
            style = "green" if decision == "allow" else "red"
            table.add_row(
                tool, direction, f"[{style}]{decision}[/{style}]", rule or "-", incident or "-"
            )
        console.print(table)

        incidents = db.execute(
            "SELECT incident_id, attack_type, detection_method, evidence"
            " FROM incidents ORDER BY rowid"
        ).fetchall()
        if incidents:
            console.print("[bold]Incidents:[/bold]")
            for incident_id, attack_type, method, evidence in incidents:
                console.print(f"  {incident_id}  {attack_type}  ({method})")
                console.print(f"    [dim]{evidence}[/dim]")
    finally:
        db.close()
    console.print(f"\n[dim]Full audit DB: {DB_PATH}[/dim]")


if __name__ == "__main__":
    asyncio.run(run())
