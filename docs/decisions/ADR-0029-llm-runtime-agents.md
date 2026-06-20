# ADR-0029 — LLM-Powered Runtime Departments (M12)

**Status:** accepted  
**Date:** 2026-06-20

---

## Context

Olive's runtime currently has one LLM integration: `SemanticAnalyzer`, a
single-shot per-call classifier inside `PromptInjectionSentinel`. Every other
department (Defense, RedTeam, Builder, Remediation) is pure deterministic
Python.

Deterministic enforcement is the correct foundation — it cannot be confused,
hallucinated through, or rate-limited into silence. But it is bounded by its
corpus. Novel attacks that were never patterned, multi-call campaigns that only
make sense in sequence, and policy patches that require reasoning beyond
template substitution are all out of reach of pure code.

The product vision calls for a *combination*: deterministic enforcement that
cannot be bypassed, plus LLM reasoning agents that surface what determinism
missed. The architecture already supports this — the incident bus is the
safe communication layer, the advisory constraint is already enforced, and the
LangChain adapter (ADR-0028) proves the integration path.

---

## Decision

Add **optional LLM reasoning agents** to three departments, all mediated
exclusively through the incident bus. No LLM agent has an enforcement path.

### Three agent types

**1. LLMContextSentinel** (defense layer)

Replaces `SemanticAnalyzer`'s one-shot classify with a reasoning agent that
holds a **bounded session window** (last N events, hashed + excerpted per
rule 3). It reasons about *sequences*, not individual calls:

- Is the pattern of tool calls consistent with the declared role?
- Does the distribution of calls suggest reconnaissance?
- Does a response contain implicit redirection (not keyword-matching)?

Publishes advisory `llm-detection` bus objects. If it fires, the SentinelRunner
combines it with the deterministic signal and may raise confidence above threshold.

**2. LLMRedTeamAgent** (red-team layer)

Extends `RedTeamDepartment.run_once()` with a hypothesis-generation step:
given the current policy YAML and the known corpus, prompt an LLM to propose
bypass strategies not yet in the corpus. Outputs candidate attack strings fed
into the existing deterministic mutation engine for validation. Novel findings
go through the same `redteam-finding` → human-triage pipeline unchanged.

**3. LLMBuilderAgent** (builder layer)

Extends `BuilderDepartment` with a patch-proposal step: given a confirmed
incident + reproduced corpus case, prompt an LLM to:
- Propose a minimal YAML policy addition (new forbidden pattern, role rule, etc.)
- Explain the tradeoff (false-positive risk, scope)
- Draft the corpus case update

Output is a bounded text proposal appended to the `fix-proposed` bus object.
Never applied automatically; the `olive cycle approve` human gate is unchanged.

---

## Non-negotiable constraints (carry forward from CLAUDE.md)

1. **Advisory only.** LLM agents publish bus objects. They never call
   `breaker.trip()`, `session.quarantine()`, or any enforcement method.
   A test asserts the import set for each agent module (same pattern as ADR-0027).

2. **Fail-safe.** Any LLM agent error → no signal. The deterministic layers
   already enforced what they could. A failed LLM call must never produce a
   block.

3. **No raw payloads.** Agents receive SHA-256 hashes + bounded excerpts
   (≤200 chars, matched region only) — never full tool arguments or response
   bodies. Same rule as the audit log (CLAUDE.md rule 3).

4. **Bus-mediated.** LLM agents communicate only through signed `IncidentObject`
   bus messages. They never call into another department's methods directly.

5. **Rate-limited.** A shared `AgentLLMClient` wraps the Groq/Anthropic SDK
   with per-minute and per-day token budgets. Requests over budget → no-op
   (counted, logged, never block-on-failure).

6. **Bounded context.** Agents receive at most the last 20 events per session
   from the store, and at most 4000 chars of combined context. This prevents
   prompt injection via accumulated history.

---

## New files

| File | Purpose |
|---|---|
| `src/olive/intelligence/agent_client.py` | Shared LLM client: key management, rate limiting, defensive parse, provider fallback |
| `src/olive/intelligence/llm_sentinel.py` | `LLMContextSentinel` — session-window reasoning |
| `src/olive/intelligence/llm_redteam.py` | `LLMRedTeamAgent` — hypothesis generation |
| `src/olive/intelligence/llm_builder.py` | `LLMBuilderAgent` — patch proposal |
| `tests/test_llm_sentinel.py` | Unit tests (mock LLM, no real API) |
| `tests/test_llm_redteam.py` | Unit tests |
| `tests/test_llm_builder.py` | Unit tests |

---

## Modified files

| File | Change |
|---|---|
| `src/olive/intelligence/departments.py` | Wire agents into `build_runtime_org()` behind `llm_agents: bool = False` flag |
| `src/olive/intelligence/sentinels.py` | `PromptInjectionSentinel.analyze()` calls `LLMContextSentinel` when wired |
| `src/olive/intelligence/runner.py` | Accept `LLMContextSentinel` as optional extra sentinel |
| `src/olive/cli.py` | Add `--llm-agents` flag to `serve` subcommand |
| `pyproject.toml` | `intelligence` extras already include `openai>=1.0`; no new dep needed |

---

## Data flow

```
Tool response arrives
       │
       ▼
PatternInspector ──► block/allow (deterministic, fast)
       │ (if allow)
       ▼
PromptInjectionSentinel
  ├─ deterministic_trigger() ──► Signal.fire (confidence=1.0) if match
  └─ (if no det. match)
       ├─ SemanticAnalyzer.classify()  ← existing per-call Groq/Anthropic
       └─ LLMContextSentinel.score()   ← NEW: session-window reasoning
              │
              ▼ (advisory signal)
         SentinelRunner
              │
              ▼ (if threshold exceeded)
         breaker.trip() ← DETERMINISTIC, never LLM
              │
              ▼
         DefenseDepartment.publish_report()
              │
              ▼ (bus)
         LLMRedTeamAgent  ← NEW: listens for detections, proposes novel bypasses
         LLMBuilderAgent  ← NEW: listens for reproduced incidents, proposes patches
```

---

## Additive / default-off

`--llm-agents` flag activates all three agents. Without it, the gateway is
identical to M11: only `SemanticAnalyzer` (existing). The flag is safe to
run in production only when a Groq/Anthropic key is configured and the
operator accepts the token cost.

---

## Consequences

- Novel attacks not in the corpus are surfaced (LLMContextSentinel,
  LLMRedTeamAgent).
- Policy patches emerge from incidents with reasoning, not just templates
  (LLMBuilderAgent).
- Token cost is non-zero in `--llm-agents` mode; the rate limiter in
  `AgentLLMClient` bounds daily spend.
- All existing tests pass unchanged; new tests cover the LLM path with mocked
  clients.
