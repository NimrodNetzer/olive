"""The eval harness is itself part of the moat (ADR-0011), so it is tested like
any other code: the metrics math, the regression gate, and an end-to-end smoke
run of the real corpus through the real pipeline."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
RUNNER = ROOT / "evals" / "run_evals.py"

# run_evals.py is a script, not an installed module - load it by path. It must
# be registered in sys.modules before exec so its @dataclass can resolve.
_spec = importlib.util.spec_from_file_location("run_evals", RUNNER)
assert _spec and _spec.loader
run_evals = importlib.util.module_from_spec(_spec)
sys.modules["run_evals"] = run_evals
_spec.loader.exec_module(run_evals)


def _case(*, expected: str, status: str, category: str, blocked: bool):
    """A minimal CaseResult standing in for a corpus run."""
    return run_evals.CaseResult(
        case={"expected": expected, "status": status, "category": category, "direction": "inbound"},
        blocked=blocked,
        latency_ms=0.1,
    )


def test_percentile_nearest_rank():
    assert run_evals._percentile([], 50) == 0.0
    assert run_evals._percentile([5.0], 95) == 5.0
    assert run_evals._percentile([1.0, 2.0, 3.0, 4.0], 50) == 2.0
    assert run_evals._percentile([1.0, 2.0, 3.0, 4.0], 100) == 4.0


def test_metrics_counts_only_active_cases():
    results = [
        _case(expected="block", status="active", category="injection.trigger", blocked=True),
        _case(expected="block", status="active", category="injection.trigger", blocked=False),
        # a known-miss malicious case is honest backlog - never credited or counted
        _case(expected="block", status="known-miss", category="injection.encoded", blocked=False),
        _case(expected="allow", status="active", category="benign", blocked=False),
        # a known-miss benign (known FP) is excluded from the active FP count
        _case(expected="allow", status="known-miss", category="benign", blocked=True),
    ]
    m = run_evals._metrics(results)
    assert m["detected"] == 1
    assert m["malicious_total"] == 2
    assert m["false_positives"] == 0
    assert m["benign_total"] == 1
    assert m["per_category"]["injection.trigger"] == {"detected": 1, "total": 2}
    assert "injection.encoded" not in m["per_category"]


def test_gate_passes_when_floor_held():
    metrics = {"detected": 22, "false_positives": 0, "per_category": {"x": {"detected": 3}}}
    baseline = {"detected": 22, "false_positives": 0, "per_category": {"x": {"detected": 3}}}
    assert run_evals._gate(metrics, baseline) == []
    # detection rising and FP staying is fine
    better = {"detected": 25, "false_positives": 0, "per_category": {"x": {"detected": 4}}}
    assert run_evals._gate(better, baseline) == []


def test_gate_fails_on_detection_drop():
    metrics = {"detected": 21, "false_positives": 0, "per_category": {}}
    baseline = {"detected": 22, "false_positives": 0, "per_category": {}}
    failures = run_evals._gate(metrics, baseline)
    assert any("detection dropped" in f for f in failures)


def test_gate_fails_on_false_positive_rise():
    metrics = {"detected": 22, "false_positives": 1, "per_category": {}}
    baseline = {"detected": 22, "false_positives": 0, "per_category": {}}
    failures = run_evals._gate(metrics, baseline)
    assert any("false positives rose" in f for f in failures)


def test_gate_fails_on_per_category_drop_even_if_total_holds():
    # total detected unchanged, but a category silently lost a catch
    metrics = {
        "detected": 22,
        "false_positives": 0,
        "per_category": {"a": {"detected": 2}, "b": {"detected": 4}},
    }
    baseline = {
        "detected": 22,
        "false_positives": 0,
        "per_category": {"a": {"detected": 3}, "b": {"detected": 3}},
    }
    failures = run_evals._gate(metrics, baseline)
    assert any("category 'a' detection dropped" in f for f in failures)


def test_update_baseline_writes_valid_metrics(tmp_path, monkeypatch):
    """--update-baseline serializes the live metrics and exits 0."""
    import asyncio

    target = tmp_path / "baseline.json"
    monkeypatch.setattr(run_evals, "BASELINE", target)
    exit_code = asyncio.run(run_evals.run(update_baseline=True))
    assert exit_code == 0
    written = json.loads(target.read_text(encoding="utf-8"))
    assert written["false_positives"] == 0
    assert written["detected"] == written["malicious_total"] >= 1
    assert "per_category" in written


def test_missing_baseline_fails_closed(tmp_path, monkeypatch):
    """With no baseline to gate against, the run fails closed rather than
    silently passing."""
    import asyncio

    monkeypatch.setattr(run_evals, "BASELINE", tmp_path / "absent.json")
    assert asyncio.run(run_evals.run(update_baseline=False)) == 1


def test_baseline_matches_current_corpus():
    """The committed baseline must equal a fresh run of the real corpus - i.e.
    nobody edited the corpus down without re-running --update-baseline."""
    baseline = json.loads((ROOT / "evals" / "baseline.json").read_text(encoding="utf-8"))
    exit_code = pytest.importorskip("asyncio").run(run_evals.run())
    assert exit_code == 0, "eval gate failed against committed baseline"
    assert baseline["false_positives"] == 0, "no active false positives may be committed"
    assert baseline["malicious_total"] >= 1
