# ADR-0023: Detection depth — cross-session behavioral baselines and corpus 107

**Status:** accepted (2026-06-18, retrospective for M10)

## Context

The `BehaviorSentinel` (ADR-0012) detected anomalous tool-call sequences within
a single session (e.g., read → egress within one MCP conversation). Multi-day
slow-burn campaigns — where an attacker spreads reconnaissance across several
sessions to avoid per-session detection — were invisible because the sentinel
had no memory beyond the current session.

Separately, the eval corpus at M9 covered 62 cases. The known-miss catalog
documented several realistic attack patterns (multi-session chains, rug-pull
variants, escalation-via-typosquatting) that the corpus did not exercise.
A corpus that only tests what already works is not a moat.

M10 addresses both: cross-session baselines for the BehaviorSentinel, and a
corpus expansion from 62 to 107 cases that honestly documents what is and is
not detected.

## Decision

### 1. Cross-session behavioral baseline via `agent_tool_history` table

A new `agent_tool_history` table in the SQLite store records every allowed
outbound tool call: `agent_id`, `session_id`, `tool`, `direction`, `timestamp`.
The proxy calls `store.log_allowed_call()` after every allowed outbound call.
This is append-only; it is never read on the fast path.

`store.recent_agent_tools(agent_id, since_hours)` queries the table and returns
a list of `(tool, timestamp)` tuples. This is the cross-session feed.

`BehaviorSentinel` accepts an optional `cross_session_fn: Callable[[str], list]`
parameter. When provided, it calls `cross_session_fn(agent_id)` to retrieve the
agent's recent cross-session history and folds it into the sequence analysis.
Cross-session signals fire at confidence 0.5 (softer than the in-session 0.6
threshold) because cross-session correlation has higher false-positive risk —
legitimate agents have recurring tool-call patterns.

`build_sentinels()` in `intelligence/departments.py` accepts an optional
`store=` parameter. When present, it wires `cross_session_fn` from
`store.recent_agent_tools`. CLI passes `store` to `build_sentinels` in both
`run_gateway` and `serve_http_live`.

The `agent_tool_history` table is advisory telemetry; it is never read on the
enforcement fast path. A corrupt or unavailable query degrades to no cross-session
signal (the sentinel continues with in-session analysis only), consistent with
the advisory-only rule (ADR-0005).

### 2. Corpus expansion: 62 → 107 cases

45 new cases were added across six categories:

| Category | New cases | Representative gaps closed |
|---|---|---|
| `inj` (injection) | 16 | Markdown hidden, RTL override, zero-width interleave, fictional framing, numbered-list obfuscation, instruction-at-EOF |
| `ben` (benign hard negatives) | 9 | Technical docs, base64 in product code, quoted policy references, SQL in error messages, code snippets |
| `exf` (exfiltration) | 6 | Staged multi-step exfil, URL leak, slow-burn cross-session, DNS-lookup exfil, env-var probe |
| `esc` (escalation) | 4 | Tool-name typosquatting, capability-escalation claim, JWT claim inflation, sudo prompt injection |
| `chn` (chain) | 4 | Reconnaissance-then-escalation, tool-response chain injection, phased data assembly, slow-burn multi-session |
| `rug` (rug-pull) | 4 | Subtle schema change, description expansion, schema type widening, tool added mid-session |
| `desc` (description poison) | 2 | First-sight benign tool / malicious description, first-sight trigger in description |

The known-miss catalog was expanded to document cases where detection requires
semantic analysis or fleet-level correlation that the deterministic layer cannot
provide. These are honest non-guarantees, not regressions.

Eval baseline updated: **42/42 active malicious cases caught, 0/24 false
positives**. Known-miss cases carry `status: known-miss` and are excluded from
the baseline count per ADR-0011.

### 3. Scope

**IN:** `agent_tool_history` table; `log_allowed_call()` + `recent_agent_tools()`
on `EventStore`; `cross_session_fn` parameter on `BehaviorSentinel`; `store=`
parameter on `build_sentinels()`; 45 new corpus YAML files; updated
`evals/baseline.json`; `test_detection_depth.py` (14 new tests, 258 LOC).

**OUT:** Fleet-wide cross-agent baselines (this is per-agent-id within one
gateway's store; cross-fleet correlation requires M11); automated corpus
generation (all 45 cases are human-authored); latency gating on the
`recent_agent_tools` query (measured and reported, not gated per ADR-0011).

## Consequences

- Multi-session slow-burn campaigns are now detectable within a single gateway
  deployment. An agent that spreads reconnaissance across three sessions is no
  longer invisible.
- The 9 new benign hard negatives raise the bar against false positives on
  realistic content (SQL in error messages, base64 in source code).
- `agent_tool_history` grows unboundedly for long-running gateways; a
  `since_hours` window (default 72 h) bounds the query result but not the table
  size. Table pruning is deferred.
- Cross-session confidence (0.5) is deliberately softer than in-session (0.6)
  to limit false positives on agents with stable recurring patterns.

## Required doc updates

- `docs/ARCHITECTURE.md` — add `agent_tool_history` table to the Event Store
  section; update BehaviorSentinel description to mention cross-session feed.
- `docs/THREAT_MODEL.md` — update "cross-session detection" from gap to
  per-gateway guarantee; note cross-fleet correlation as remaining non-guarantee.
