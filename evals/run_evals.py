"""Eval runner - measures Olive's detection honestly.

Runs every corpus case through the REAL inspector pipeline (assembled by the
same function the gateway uses - no eval-only shortcuts) and reports detection
rate, false-positive rate, per-category breakdown, and added latency p50/p95.

The run is a CI regression gate (ADR-0011). It exits 1 on any backslide:

  1. an `active` case whose outcome no longer matches its `expected` verdict;
  2. total `detected` below the committed baseline (catches a silent drop
     however it happens - a flip, a reclassification to known-miss, a deletion);
  3. any per-category `detected` below its baseline;
  4. `false_positives` above the committed baseline.

The baseline (`evals/baseline.json`) only moves by an explicit, reviewable act:
    python evals/run_evals.py --update-baseline

Run:  python evals/run_evals.py
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

import yaml
from rich.console import Console
from rich.table import Table

from olive.cli import build_pipeline
from olive.config import load_config
from olive.gateway.context import ResourceRef, SecurityContext, hash_arguments

ROOT = Path(__file__).parent.parent
CORPUS = Path(__file__).parent / "corpus"
BASELINE = Path(__file__).parent / "baseline.json"

console = Console()


def _resource_ref(ctx: dict) -> ResourceRef | None:
    """Build the structured resource a contextual case targets (ADR-0010). The
    extractor has its own unit tests; here the case states the ref directly so
    the corpus measures the inspector verdict."""
    res = ctx.get("resource")
    if not res:
        return None
    return ResourceRef(
        type=res["type"],
        id=str(res.get("id", "")),
        classification=res.get("classification"),
        id_hashed=bool(res.get("id_hashed", False)),
    )


@dataclass
class CaseResult:
    case: dict
    blocked: bool
    latency_ms: float

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
        requested_resource=_resource_ref(ctx),
        task_resources=tuple(ctx.get("task_resources", ())),
    )


def _pipeline_for(policy: str, cache: dict):
    """One real pipeline per policy file (assembled by the gateway's own
    build_pipeline). A case may name a `policy:`; most use the default."""
    if policy not in cache:
        cache[policy] = build_pipeline(load_config(ROOT / "policies" / policy))
    return cache[policy]


def _percentile(values: list[float], pct: float) -> float:
    """Nearest-rank percentile; small-sample friendly, no numpy dependency."""
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(0, min(len(ordered) - 1, round(pct / 100 * len(ordered) + 0.5) - 1))
    return ordered[rank]


def _metrics(results: list[CaseResult]) -> dict:
    """The aggregate numbers the baseline gate pins (ADR-0011). Counts, not
    percentages - a percentage floor drifts as the corpus grows and hides
    absolute loss. Only `active` malicious cases count toward detection; a
    known-miss is honest backlog, never credited."""
    active = [r for r in results if r.case["status"] == "active"]
    malicious = [r for r in active if r.case["expected"] == "block"]
    benign = [r for r in active if r.case["expected"] == "allow"]
    per_category: dict[str, dict[str, int]] = {}
    for r in malicious:
        cat = per_category.setdefault(r.case["category"], {"detected": 0, "total": 0})
        cat["total"] += 1
        cat["detected"] += int(r.blocked)
    return {
        "detected": sum(1 for r in malicious if r.blocked),
        "malicious_total": len(malicious),
        "false_positives": sum(1 for r in benign if r.blocked),
        "benign_total": len(benign),
        "per_category": dict(sorted(per_category.items())),
    }


def _gate(metrics: dict, baseline: dict) -> list[str]:
    """Return one failure line per backslide vs. the committed baseline; empty
    means the floor held. Detection may rise freely; it may never drop."""
    failures: list[str] = []
    if metrics["detected"] < baseline["detected"]:
        failures.append(
            f"detection dropped: {metrics['detected']} < baseline {baseline['detected']} "
            "(a catch was lost - flip, reclassification to known-miss, or deletion)"
        )
    if metrics["false_positives"] > baseline["false_positives"]:
        failures.append(
            f"false positives rose: {metrics['false_positives']} > baseline "
            f"{baseline['false_positives']} (a benign hard negative started tripping)"
        )
    for cat, base in baseline.get("per_category", {}).items():
        now = metrics["per_category"].get(cat, {"detected": 0})
        if now["detected"] < base["detected"]:
            failures.append(
                f"category '{cat}' detection dropped: {now['detected']} < "
                f"baseline {base['detected']}"
            )
    return failures


async def run(update_baseline: bool = False) -> int:
    pipelines: dict = {}

    cases = [yaml.safe_load(p.read_text(encoding="utf-8")) for p in sorted(CORPUS.glob("*.yaml"))]
    if not cases:
        console.print("[red]no corpus cases found[/red]")
        return 1

    results: list[CaseResult] = []
    for case in cases:
        pipeline = _pipeline_for(case.get("policy", "default.yaml"), pipelines)
        ctx = build_context(case)
        content = case["payload"] if case["direction"] == "inbound" else None
        start = time.perf_counter()
        verdict = await pipeline.run(ctx, content)
        elapsed_ms = (time.perf_counter() - start) * 1000
        results.append(CaseResult(case, blocked=not verdict.allowed, latency_ms=elapsed_ms))

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

    metrics = _metrics(results)
    console.print(
        f"\nDetection rate (active malicious cases, honest): "
        f"[bold]{metrics['detected']}/{metrics['malicious_total']}[/bold]"
    )
    console.print(
        f"False positives (benign cases blocked):          "
        f"[bold]{metrics['false_positives']}/{metrics['benign_total']}[/bold]"
    )
    console.print(f"Corpus size: [bold]{len(results)}[/bold] cases")

    # Added latency p50/p95 per direction (ADR-0011: reported, not gated -
    # wall-clock on CI is too noisy to fail a build on).
    lat_table = Table(title="Added pipeline latency (ms)", header_style="bold")
    for col in ("direction", "cases", "p50", "p95"):
        lat_table.add_column(col, justify="right")
    lat_table.columns[0].justify = "left"
    for direction in ("inbound", "outbound"):
        lats = [r.latency_ms for r in results if r.case["direction"] == direction]
        if lats:
            lat_table.add_row(
                direction,
                str(len(lats)),
                f"{_percentile(lats, 50):.2f}",
                f"{_percentile(lats, 95):.2f}",
            )
    console.print(lat_table)

    console.print(
        "[dim]Layer-zero deterministic patterns only. Known misses are the honest\n"
        "backlog the M6 sentinels and ongoing corpus expansion exist to close.[/dim]"
    )

    for r in fixed:
        console.print(
            f"[yellow]NOTE[/yellow] {r.case['id']} (known-miss) now behaves as expected - "
            "promote to active and run --update-baseline to lock the win in."
        )
    for r in regressions:
        console.print(
            f"[red]REGRESSION[/red] {r.case['id']}: expected {r.case['expected']}, "
            f"got {'block' if r.blocked else 'allow'}"
        )

    if update_baseline:
        BASELINE.write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
        try:
            shown = BASELINE.relative_to(ROOT)
        except ValueError:
            shown = BASELINE
        console.print(f"\n[green]baseline updated[/green] -> {shown}")
        return 0

    if not BASELINE.exists():
        console.print(
            "\n[red]no baseline.json[/red] - run `python evals/run_evals.py "
            "--update-baseline` to create one"
        )
        return 1

    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    gate_failures = _gate(metrics, baseline)
    for line in gate_failures:
        console.print(f"[red]GATE[/red] {line}")

    return 1 if (regressions or gate_failures) else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(run(update_baseline="--update-baseline" in sys.argv)))
