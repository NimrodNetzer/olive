"""Olive integration demo - ProjectX code-assistant agent.

Runs 5 attack scenarios twice:
  Phase 1 - UNPROTECTED: agent talks directly to tool_server.py
  Phase 2 - PROTECTED:   agent talks through Olive (one process in the middle)

Demonstrates 4 distinct Olive protection layers:
  1. PolicyInspector   - blocks forbidden tools (privilege escalation)
  2. PatternInspector  - blocks prompt injection in tool responses
  3. DecodeInspector   - blocks base64-encoded injection payloads
  4. CircuitBreaker    - quarantines the session after 3 accumulated blocks

Run from the repo root:
  python demo_project/run_demo.py
"""

from __future__ import annotations

import asyncio
import sqlite3
import sys
import time
from pathlib import Path

import mcp.types as types
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from rich import box
from rich.console import Console
from rich.table import Table

ROOT = Path(__file__).parent.parent
TOOL_SERVER = ROOT / "demo_project" / "tool_server.py"
POLICY = ROOT / "demo_project" / "policy.yaml"
DB_PATH = ROOT / "demo_project" / "demo_events.db"

console = Console()

# ---------------------------------------------------------------------------
# Scenarios: (short label, tool name, arguments, protection layer, description)
# ---------------------------------------------------------------------------
SCENARIOS = [
    (
        "Legitimate read",
        "read_file",
        {"name": "project_readme.txt"},
        "-",
        "Agent reads the project README - normal, benign work",
    ),
    (
        "Privilege escalation",
        "get_system_config",
        {},
        "PolicyInspector",
        "Agent tries to read system secrets - role is not allowed to call this tool",
    ),
    (
        "Prompt injection (response)",
        "read_file",
        {"name": "api_notes.txt"},
        "PatternInspector",
        "Tool response contains 'ignore previous instructions' payload",
    ),
    (
        "Encoded injection (base64)",
        "read_file",
        {"name": "encoded_brief.txt"},
        "DecodeInspector",
        "Tool response hides injection as base64 - decoded and caught",
    ),
    (
        "Post-quarantine (circuit breaker)",
        "read_file",
        {"name": "project_readme.txt"},
        "CircuitBreaker",
        "3 blocks accumulated - entire session is now quarantined",
    ),
]


def first_text(result: types.CallToolResult) -> str:
    for block in result.content:
        if isinstance(block, types.TextContent):
            return block.text
    return ""


async def run_scenarios(
    session: ClientSession,
) -> list[tuple[str, bool, str, float]]:
    """Run every scenario, return (label, was_blocked, text_snippet, latency_ms)."""
    results = []
    for label, tool, args, _layer, _desc in SCENARIOS:
        t0 = time.perf_counter()
        result = await session.call_tool(tool, args)
        latency_ms = (time.perf_counter() - t0) * 1000
        results.append((label, result.isError, first_text(result)[:120], latency_ms))
    return results


def print_phase(
    results: list[tuple[str, bool, str, float]],
    title: str,
) -> None:
    console.print()
    console.rule(f"[bold]{title}")
    rows = zip(results, SCENARIOS, strict=False)
    for (label, blocked, snippet, latency), (_, _, _, layer, _) in rows:
        badge = "[bold red]BLOCKED[/bold red]" if blocked else "[bold green]ALLOWED[/bold green]"
        console.print(f"  {badge}  {label}  [dim]({latency:.0f} ms)[/dim]")
        console.print(f"           [dim]{snippet[:100]}[/dim]")
        if blocked:
            console.print(f"           [yellow]  layer: {layer}[/yellow]")


def print_comparison(
    unprotected: list[tuple[str, bool, str, float]],
    protected: list[tuple[str, bool, str, float]],
) -> None:
    console.print()
    console.rule("[bold]SIDE-BY-SIDE COMPARISON")
    table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold cyan")
    table.add_column("Scenario", style="white", no_wrap=True)
    table.add_column("Without Olive", justify="center")
    table.add_column("With Olive", justify="center")
    table.add_column("Olive layer", style="yellow")
    table.add_column("Overhead", justify="right")

    for (label, u_blocked, _, u_lat), (_, p_blocked, _, p_lat), (_, _, _, layer, _) in zip(
        unprotected, protected, SCENARIOS, strict=False
    ):
        is_attack = layer != "-"
        if u_blocked:
            u_str = "[dim]blocked[/dim]"
        elif is_attack:
            u_str = "[red]EXPOSED[/red]"
        else:
            u_str = "[green]PASSED[/green]"
        if p_blocked:
            p_str = "[green]BLOCKED[/green]"
        elif is_attack:
            p_str = "[red]EXPOSED[/red]"
        else:
            p_str = "[green]PASSED[/green]"
        overhead = p_lat - u_lat
        table.add_row(label, u_str, p_str, layer, f"+{overhead:.0f} ms")

    console.print(table)


def print_audit_trail() -> None:
    if not DB_PATH.exists():
        return
    console.print()
    console.rule("[bold]AUDIT TRAIL  (every decision written to SQLite)")
    db = sqlite3.connect(DB_PATH)
    try:
        rows = db.execute(
            "SELECT tool, direction, decision, policy_rule, incident_id "
            "FROM events ORDER BY rowid"
        ).fetchall()
        table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
        for col in ("tool", "dir", "decision", "rule", "incident"):
            table.add_column(col)
        for tool, direction, decision, rule, incident in rows:
            style = "green" if decision == "allow" else "red"
            table.add_row(
                tool,
                direction,
                f"[{style}]{decision}[/{style}]",
                rule or "-",
                incident or "-",
            )
        console.print(table)

        incidents = db.execute(
            "SELECT incident_id, attack_type, detection_method, evidence "
            "FROM incidents ORDER BY rowid"
        ).fetchall()
        if incidents:
            console.print(f"\n[bold]{len(incidents)} incident(s) recorded:[/bold]")
            for inc_id, attack_type, method, evidence in incidents:
                console.print(f"  [red]{inc_id}[/red]  {attack_type}  [dim]({method})[/dim]")
                console.print(f"    [dim]{evidence}[/dim]")
    finally:
        db.close()
    console.print(f"\n[dim]Full audit DB: {DB_PATH}[/dim]")


# ---------------------------------------------------------------------------
# Phase runners
# ---------------------------------------------------------------------------

async def phase1_unprotected() -> list[tuple[str, bool, str, float]]:
    """Agent → tool_server directly (no Olive)."""
    params = StdioServerParameters(
        command=sys.executable,
        args=[str(TOOL_SERVER)],
        cwd=str(ROOT),
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            return await run_scenarios(session)


async def phase2_protected() -> list[tuple[str, bool, str, float]]:
    """Agent → Olive → tool_server (transparent proxy)."""
    if DB_PATH.exists():
        DB_PATH.unlink()
    params = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m", "olive.cli", "run",
            "--config", str(POLICY),
            "--db", str(DB_PATH),
            "--",
            sys.executable, str(TOOL_SERVER),
        ],
        cwd=str(ROOT),
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            return await run_scenarios(session)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def main() -> None:
    console.rule("[bold white]OLIVE - INTEGRATION DEMO[/bold white]")
    console.print(
        "\n[cyan]Setup:[/cyan]  A code-assistant agent reads ProjectX documentation.\n"
        "        Three of the files contain hidden attack payloads.\n"
        "        Olive sits transparently between the agent and the tools.\n"
    )

    console.print("[bold]5 scenarios:[/bold]")
    for i, (label, _, _, layer, desc) in enumerate(SCENARIOS, 1):
        layer_tag = f"  [yellow][{layer}][/yellow]" if layer != "-" else ""
        console.print(f"  {i}. [cyan]{label}[/cyan]{layer_tag}")
        console.print(f"     [dim]{desc}[/dim]")

    console.print()
    console.print("[bold yellow]>> Phase 1:[/bold yellow] WITHOUT Olive -- direct connection")
    unprotected = await phase1_unprotected()
    print_phase(unprotected, "WITHOUT Olive -- attacks land undetected")

    console.print()
    console.print(
        "[bold yellow]>> Phase 2:[/bold yellow] WITH Olive -- transparent proxy (zero code changes)"
    )
    protected = await phase2_protected()
    print_phase(protected, "WITH Olive - attacks blocked, legitimate traffic flows")

    print_comparison(unprotected, protected)
    print_audit_trail()


if __name__ == "__main__":
    asyncio.run(main())
