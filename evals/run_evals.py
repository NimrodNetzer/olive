"""Eval runner - measures Olive's detection honestly.

Runs every corpus case through the REAL inspector pipeline (assembled by the
same function the gateway uses - no eval-only shortcuts) and reports
detection rate, false-positive rate, and known misses per category.

Exit code 1 on regression: an `active` case whose outcome no longer matches
its `expected` verdict.

Run:  python evals/run_evals.py
"""

from __future__ import annotations

import asyncio
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

import yaml
from rich.console import Console
from rich.table import Table

from olive.cli import build_pipeline
from olive.config import load_config
from olive.gateway.context import SecurityContext, hash_arguments

ROOT = Path(__file__).parent.parent
CORPUS = Path(__file__).parent / "corpus"

console = Console()


@dataclass
class CaseResult:
    case: dict
    blocked: bool

    @property
    def matches_expected(self) -> bool:
        return self.blocked == (self.case["expected"] == "block")


def build_context(case: dict) -> SecurityContext:
    ctx = case["context"]
    return SecurityContext(
        agent_id="eval-agent",
        session_id="sess-eval",
        organization_id="eval-org",
        role=ctx["role"],
        declared_goal="evaluation",
        tool=ctx["tool"],
        arguments_hash=hash_arguments(None),
        direction=case["direction"],
        call_number=1,
        session_tool_history=(),
        source_trust=ctx.get("source_trust", "untrusted"),
        timestamp=SecurityContext.now(),
    )


async def run() -> int:
    config = load_config(ROOT / "policies" / "default.yaml")
    pipeline = build_pipeline(config)

    cases = [yaml.safe_load(p.read_text(encoding="utf-8")) for p in sorted(CORPUS.glob("*.yaml"))]
    if not cases:
        console.print("[red]no corpus cases found[/red]")
        return 1

    results: list[CaseResult] = []
    for case in cases:
        ctx = build_context(case)
        content = case["payload"] if case["direction"] == "inbound" else None
        verdict = await pipeline.run(ctx, content)
        results.append(CaseResult(case, blocked=not verdict.allowed))

    by_category: dict[str, list[CaseResult]] = defaultdict(list)
    for r in results:
        by_category[r.case["category"]].append(r)

    table = Table(title="Olive detection evals", header_style="bold")
    for col in ("category", "cases", "as expected", "known misses", "regressions"):
        table.add_column(col, justify="right")
    table.columns[0].justify = "left"

    regressions: list[CaseResult] = []
    fixed: list[CaseResult] = []
    for category in sorted(by_category):
        rows = by_category[category]
        ok = sum(1 for r in rows if r.matches_expected and r.case["status"] == "active")
        known = [r for r in rows if r.case["status"] == "known-miss"]
        cat_regressions = [
            r for r in rows if r.case["status"] == "active" and not r.matches_expected
        ]
        regressions.extend(cat_regressions)
        fixed.extend(r for r in known if r.matches_expected)
        table.add_row(
            category,
            str(len(rows)),
            str(ok),
            str(sum(1 for r in known if not r.matches_expected)),
            f"[red]{len(cat_regressions)}[/red]" if cat_regressions else "0",
        )
    console.print(table)

    malicious = [r for r in results if r.case["expected"] == "block"]
    benign = [r for r in results if r.case["expected"] == "allow"]
    detected = sum(1 for r in malicious if r.blocked)
    false_positives = sum(1 for r in benign if r.blocked)

    console.print(
        f"\nDetection rate (all malicious cases, honest): "
        f"[bold]{detected}/{len(malicious)}[/bold]"
    )
    console.print(
        f"False positives (benign cases blocked):        "
        f"[bold]{false_positives}/{len(benign)}[/bold]"
    )
    console.print(
        "[dim]Layer-zero deterministic patterns only (M1). Known misses are the\n"
        "backlog the M3 sentinels and M4 corpus expansion exist to close.[/dim]"
    )

    for r in fixed:
        console.print(
            f"[yellow]NOTE[/yellow] {r.case['id']} (known-miss) now behaves as expected - "
            "promote to active."
        )
    for r in regressions:
        console.print(
            f"[red]REGRESSION[/red] {r.case['id']}: expected {r.case['expected']}, "
            f"got {'block' if r.blocked else 'allow'}"
        )

    return 1 if regressions else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(run()))
