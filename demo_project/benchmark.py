"""Olive benchmark -- latency, false positives, and detection rate.

Three tests run in sequence:

  1. Latency profile     -- N identical legitimate calls with vs. without Olive.
                            Reports min/p50/p95/max and overhead per call.
  2. False positive check -- M varied legitimate calls through Olive.
                            Any block is a false positive (target: 0).
  3. Detection rate       -- All attack scenarios through Olive.
                            Any miss is a gap in coverage (target: 100%).

Run from the repo root:
  python demo_project/benchmark.py
"""

from __future__ import annotations

import asyncio
import statistics
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
DB_PATH = ROOT / "demo_project" / "benchmark_events.db"

console = Console()

LATENCY_ROUNDS = 20   # calls per session for the latency benchmark

# Legitimate calls for the false positive check.
# Only genuinely clean content -- no malicious files.
# Including malicious files here would correctly trigger blocks and fill the
# circuit breaker, which would then quarantine subsequent clean calls and
# appear as false positives. That is correct Olive behavior, not a FP.
FALSE_POSITIVE_CALLS = [
    ("read_file",   {"name": "project_readme.txt"}),
    ("search_docs", {"query": "authentication"}),
    ("search_docs", {"query": "rate limits"}),
    ("search_docs", {"query": "docker compose"}),
    ("read_file",   {"name": "project_readme.txt"}),
    ("search_docs", {"query": "REST API"}),
    ("read_file",   {"name": "project_readme.txt"}),
    ("search_docs", {"query": "contributing"}),
    ("search_docs", {"query": "getting started"}),
    ("read_file",   {"name": "project_readme.txt"}),
] * 3   # 30 calls total

# Attack scenarios for the detection rate test
ATTACK_CALLS = [
    ("get_system_config", {}, "privilege escalation", "PolicyInspector"),
    ("list_users", {}, "privilege escalation 2", "PolicyInspector"),
    ("read_file", {"name": "api_notes.txt"}, "prompt injection", "PatternInspector"),
    ("read_file", {"name": "encoded_brief.txt"}, "encoded injection", "DecodeInspector"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def first_text(result: types.CallToolResult) -> str:
    for block in result.content:
        if isinstance(block, types.TextContent):
            return block.text
    return ""


def percentile(data: list[float], p: float) -> float:
    data = sorted(data)
    idx = (len(data) - 1) * p / 100
    lo, hi = int(idx), min(int(idx) + 1, len(data) - 1)
    return data[lo] + (data[hi] - data[lo]) * (idx - lo)


def direct_params() -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable,
        args=[str(TOOL_SERVER)],
        cwd=str(ROOT),
    )


def olive_params() -> StdioServerParameters:
    if DB_PATH.exists():
        DB_PATH.unlink()
    return StdioServerParameters(
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


# ---------------------------------------------------------------------------
# Test 1 -- latency profile
# ---------------------------------------------------------------------------

async def _collect_latencies(session: ClientSession, n: int) -> list[float]:
    """Make N read_file calls and return latency in ms for each."""
    latencies = []
    for _ in range(n):
        t0 = time.perf_counter()
        await session.call_tool("read_file", {"name": "project_readme.txt"})
        latencies.append((time.perf_counter() - t0) * 1000)
    return latencies


async def bench_latency() -> tuple[list[float], list[float]]:
    """Returns (direct_latencies, olive_latencies)."""
    async with stdio_client(direct_params()) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            await s.call_tool("read_file", {"name": "project_readme.txt"})  # warm up
            direct = await _collect_latencies(s, LATENCY_ROUNDS)

    async with stdio_client(olive_params()) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            await s.call_tool("read_file", {"name": "project_readme.txt"})  # warm up
            olive = await _collect_latencies(s, LATENCY_ROUNDS)

    return direct, olive


def print_latency_report(direct: list[float], olive: list[float]) -> None:
    console.rule("[bold]TEST 1 -- Latency profile")
    console.print(
        f"[dim]{LATENCY_ROUNDS} identical read_file calls per session "
        "(first call discarded as warm-up)[/dim]\n"
    )

    table = Table(box=box.SIMPLE_HEAVY, header_style="bold cyan")
    table.add_column("Metric", style="white")
    table.add_column("Without Olive", justify="right")
    table.add_column("With Olive", justify="right")
    table.add_column("Overhead", justify="right", style="yellow")

    rows = [
        ("min",  min(direct),                       min(olive)),
        ("p50",  percentile(direct, 50),             percentile(olive, 50)),
        ("p95",  percentile(direct, 95),             percentile(olive, 95)),
        ("max",  max(direct),                        max(olive)),
        ("mean", statistics.mean(direct),            statistics.mean(olive)),
        ("stdev",statistics.stdev(direct),           statistics.stdev(olive)),
    ]
    for label, d, o in rows:
        if label == "stdev":
            table.add_row(label, f"{d:.1f} ms", f"{o:.1f} ms", "")
        else:
            overhead = o - d
            color = "green" if overhead < 10 else "yellow" if overhead < 50 else "red"
            table.add_row(
                label, f"{d:.1f} ms", f"{o:.1f} ms", f"[{color}]+{overhead:.1f} ms[/{color}]"
            )

    console.print(table)
    overhead_mean = statistics.mean(olive) - statistics.mean(direct)
    console.print(
        f"[bold]Verdict:[/bold] Olive adds [yellow]{overhead_mean:.1f} ms[/yellow] mean latency "
        "on a local stdio connection.\n"
        "[dim]  Note: stdio mode adds one extra IPC round-trip (4 hops vs 2).\n"
        "  In HTTP/production mode the overhead is sub-millisecond (in-process inspection).[/dim]\n"
    )


# ---------------------------------------------------------------------------
# Test 2 -- false positive check
# ---------------------------------------------------------------------------

async def bench_false_positives() -> tuple[int, int]:
    """Returns (total_calls, false_positive_count)."""
    blocked = 0
    async with stdio_client(olive_params()) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            for tool, args in FALSE_POSITIVE_CALLS:
                result = await s.call_tool(tool, args)
                if result.isError:
                    blocked += 1
    return len(FALSE_POSITIVE_CALLS), blocked


def print_fp_report(total: int, fp_count: int) -> None:
    console.rule("[bold]TEST 2 -- False positive check")
    console.print(f"[dim]{total} legitimate tool calls through Olive[/dim]\n")

    color = "green" if fp_count == 0 else "red"
    console.print(
        f"  False positives: [{color}]{fp_count}[/{color}] / {total}  "
        f"({100 * fp_count / total:.1f}%)\n"
    )
    if fp_count == 0:
        console.print("  [green]PASS[/green] -- Olive did not block any legitimate traffic.\n")
    else:
        console.print(
            f"  [red]FAIL[/red] -- {fp_count} legitimate call(s) were incorrectly blocked.\n"
        )


# ---------------------------------------------------------------------------
# Test 3 -- detection rate
# ---------------------------------------------------------------------------

async def bench_detection() -> list[tuple[str, str, bool]]:
    """Returns list of (label, layer, was_blocked) for each attack."""
    results = []
    # Fresh DB for each run so circuit breaker doesn't interfere with detection
    for tool, args, label, layer in ATTACK_CALLS:
        if DB_PATH.exists():
            DB_PATH.unlink()
        async with stdio_client(olive_params()) as (r, w):
            async with ClientSession(r, w) as s:
                await s.initialize()
                result = await s.call_tool(tool, args)
                results.append((label, layer, result.isError))
    return results


def print_detection_report(results: list[tuple[str, str, bool]]) -> None:
    console.rule("[bold]TEST 3 -- Attack detection rate")
    console.print(f"[dim]{len(results)} attack scenarios, each in a fresh session[/dim]\n")

    table = Table(box=box.SIMPLE_HEAVY, header_style="bold cyan")
    table.add_column("Attack scenario", style="white")
    table.add_column("Expected layer", style="yellow")
    table.add_column("Result", justify="center")

    detected = 0
    for label, layer, blocked in results:
        if blocked:
            detected += 1
            verdict = "[green]BLOCKED[/green]"
        else:
            verdict = "[bold red]MISSED[/bold red]"
        table.add_row(label, layer, verdict)

    console.print(table)
    pct = 100 * detected / len(results)
    color = "green" if pct == 100 else "yellow" if pct >= 75 else "red"
    console.print(
        f"\n  Detection rate: [{color}]{detected}/{len(results)} ({pct:.0f}%)[/{color}]\n"
    )
    if pct == 100:
        console.print("  [green]PASS[/green] -- All attack scenarios detected.\n")
    else:
        misses = len(results) - detected
        console.print(f"  [red]FAIL[/red] -- {misses} attack(s) were not detected.\n")


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def print_summary(
    direct: list[float],
    olive: list[float],
    fp_count: int,
    fp_total: int,
    det_results: list[tuple[str, str, bool]],
) -> None:
    detected = sum(1 for _, _, b in det_results if b)
    overhead = statistics.mean(olive) - statistics.mean(direct)
    fp_rate = 100 * fp_count / fp_total
    det_rate = 100 * detected / len(det_results)

    console.rule("[bold white]SUMMARY")
    table = Table(box=box.SIMPLE_HEAVY, header_style="bold cyan", show_header=True)
    table.add_column("Metric", style="white")
    table.add_column("Result", justify="right")
    table.add_column("Target", justify="right", style="dim")
    table.add_column("", justify="center")

    def verdict(ok: bool) -> str:
        return "[green]PASS[/green]" if ok else "[red]FAIL[/red]"

    table.add_row(
        "Mean latency overhead (stdio)",
        f"{overhead:.1f} ms",
        "< 50 ms",
        verdict(overhead < 50),
    )
    table.add_row(
        "False positive rate",
        f"{fp_rate:.1f}%",
        "0%",
        verdict(fp_count == 0),
    )
    table.add_row(
        "Attack detection rate",
        f"{det_rate:.0f}%",
        "100%",
        verdict(det_rate == 100),
    )
    console.print(table)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def main() -> None:
    console.rule("[bold white]OLIVE -- BENCHMARK[/bold white]")
    console.print(
        "\nMeasures three things: latency overhead, false positive rate,\n"
        "and attack detection rate -- all on a local stdio connection.\n"
    )

    console.print("[dim]Running latency benchmark...[/dim]")
    direct, olive = await bench_latency()
    print_latency_report(direct, olive)

    console.print("[dim]Running false positive check...[/dim]")
    fp_total, fp_count = await bench_false_positives()
    print_fp_report(fp_total, fp_count)

    console.print("[dim]Running attack detection...[/dim]")
    det_results = await bench_detection()
    print_detection_report(det_results)

    print_summary(direct, olive, fp_count, fp_total, det_results)


if __name__ == "__main__":
    asyncio.run(main())