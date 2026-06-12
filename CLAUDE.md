# Shield Wall

Zero-trust runtime security gateway for AI agents. Shield Wall is a transparent
MCP proxy that sits between an agent and its tools, inspects every tool call
**and every tool response**, and blocks, holds, or quarantines malicious
behavior — with every decision fully auditable. The product loop is:
**Govern → Detect → Contain → Reproduce → Repair → Verify.**

Read `docs/VISION.md` for the product thesis, `docs/THREAT_MODEL.md` before
touching any enforcement code, and `docs/ARCHITECTURE.md` for the system design.

## Repo map

```
docs/                  Vision, threat model, architecture, roadmap, evals strategy
docs/decisions/        ADRs — one per irreversible/architectural decision
.claude/agents/        The agent company: architect, security-reviewer, red-team, qa
policies/              Policy-as-code (roles, tool allowlists, trust labels, patterns)
src/shieldwall/
  gateway/             MCP proxy core: proxy, inspector pipeline, SecurityContext
  inspectors/          Pluggable inspectors (policy, patterns; LLM sentinels in M3)
  identity/            Agent identity tokens (mock CA JWT for now)
  store/               SQLite event + incident audit log
  cli.py               `shieldwall` entry point
demo/                  Demo MCP tool server + scripted demo run (NOT the product)
evals/                 Attack corpus + eval runner — detection is measured, not assumed
tests/                 pytest unit + integration suites
```

## Non-negotiable security rules

These govern all code in this repo. Violating one is a bug even if tests pass.

1. **All tool output is untrusted input.** The gateway never trusts content
   returned by tools, tool descriptions, or server metadata — regardless of
   trust label. Trust labels only decide *how much* inspection runs, never zero.
2. **LLM verdicts are advisory only.** Enforcement decisions (allow / block /
   quarantine) are made by deterministic code (policy engine, circuit breaker).
   An LLM sentinel may only emit a signal; it must never directly enforce.
3. **Never log raw payloads.** Tool arguments and response bodies may contain
   secrets/PII. Log SHA-256 hashes plus bounded evidence excerpts (≤200 chars,
   only the matched region) — nothing more.
4. **Fail closed.** If an inspector or the pipeline errors, the decision is
   `block`, logged with the error as evidence. Never silently pass through.
5. **Every decision is auditable.** Each allow/block/hold/quarantine writes an
   event row with the rule that fired and why. No silent decisions.

## Engineering conventions

- Python ≥ 3.11, `src/` layout, async-first, full type hints.
- `pytest` + `pytest-asyncio` for tests; `ruff` for lint + format.
- No new dependency without a one-line justification in the commit message.
- Demo scenarios are not tests. Every behavior demonstrated in `demo/` must
  also be covered by a real test in `tests/`.
- Detection logic changes must add or update cases in `evals/corpus/`.

## Workflow — the company process

This project is run like a company of agents with human supervision:

- **Architectural / irreversible decisions** → write an ADR in
  `docs/decisions/` (next number, short, status: accepted) *before* implementing.
- **Changes touching `gateway/` or `inspectors/`** → run the
  `security-reviewer` agent on the diff before considering the work done.
- **New or changed detection logic** → run the `red-team` agent to attempt
  bypasses; every bypass found becomes a new `evals/corpus/` case.
- **Before closing a milestone** → run the `qa` agent to verify test coverage
  and the end-to-end demo flow.
- Nothing merges without tests.

## Agent roster (`.claude/agents/`)

| Agent | Use when |
|---|---|
| `architect` | Designing a new component, or a change conflicts with ARCHITECTURE.md/ADRs |
| `security-reviewer` | Any diff to `gateway/`, `inspectors/`, `identity/`, or `store/` |
| `red-team` | New/changed detection logic — generates bypass attempts + corpus cases |
| `qa` | Milestone close — coverage check + demo smoke run |
