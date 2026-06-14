# Roadmap

Milestones, not dates. Each milestone ends with: tests green, `qa` agent pass,
`security-reviewer` pass on enforcement code, demo runnable. New/changed
detection logic also gets a `red-team` pass, and every bypass becomes a corpus
case.

This roadmap follows the full vision (`docs/VISION.md`): build the deterministic
**wall** first (M1–M5), then the advisory **intelligence** (M6), then the first
slice of the **company of agents** (M7).

## M1 — Foundation + walking skeleton  ✅ done

- Foundation docs (vision, threat model, architecture, evals strategy, ADRs).
- The build-time agent company (`.claude/agents/`): architect,
  security-reviewer, red-team, qa.
- Real MCP proxy over stdio: `tools/list` + `tools/call` forwarded,
  bidirectional inspection.
- Policy inspector (outbound, default-deny) + pattern inspector (inbound,
  layer zero, Unicode-normalized).
- SQLite audit store (events + incidents, hash-only).
- Identity module (mock-CA RS256 JWT) — unit-tested, not yet wire-enforced.
- Demo MCP tool server + scripted demo: allow / policy-block / response-block.
- Seed eval corpus (~12 cases incl. benign) + eval runner with detection table.

Proves: **Govern → Detect → Block → Log.**

## M2 — Identity & containment  ✅ done

- ✅ Session state tracking (call sequence, counts, first/last seen) as a real
  tracked entity, not just in-process counters.
- ✅ **Circuit breaker** (`gateway/breaker.py`): in-memory session blocklist
  checked before any pipeline work; trips on repeated blocks or a signal;
  reversible **human release**. Quarantined sessions get `quarantined` responses.
  Namespaced (org+agent+session) keys + idle eviction (quarantine never evicted).
- ✅ Rate limiting per role (`max_calls_per_minute`), multi-tenant.
- ✅ Identity binding + per-request identity (ADR-0007): role is identity-bound.
- ✅ Streamable HTTP transport (`olive serve`); **JWT identity enforced on the
  wire** (bearer token, fail-closed) + capability-gated admin session release.
- ✅ Multi-upstream support (ADR-0008): one gateway fronting several tool
  servers, tools namespaced `server.tool`, calls routed to the owning server.

Adds **Contain** to the cycle.

## M3 — Complete MCP-surface protection  ← current

Inspect the whole MCP surface, not just `tools/call` content:

- ✅ Tool names, descriptions, and schemas content-inspected at `tools/list`;
  poisoned tools are withheld from the agent and logged (`tool-poisoning`).
- ⬜ Detect **changes in tool descriptions between sessions** (rug-pull / MCP
  description-poisoning) — persist a per-(upstream, tool) baseline and flag
  drift.
- ⬜ Extend inspection to resources and prompts offered by upstreams.

## M4 — Contextual authorization

Move beyond "this role may call this tool" toward "this specific agent may
perform this specific action on this specific resource for this specific task."
Policies grow to include: user identity, organization, current goal, requested
resource, data classification, delegation source, session history, risk level,
and approval requirements.

## M5 — Measured detection (the moat)

- Attack corpus ≥ 50 cases: trigger phrases, encoded/obfuscated (base64,
  unicode, homoglyph, language-switch), semantic (no trigger words),
  tool-description poisoning / rug-pull, exfiltration-via-arguments, multi-step
  chains, plus benign hard negatives.
- Metrics: detection rate, false-positive rate, added latency p50/p95, results
  per attack category.
- CI regression gate: detection may never silently drop.

> A security product without measurable results becomes marketing.

## M6 — Intelligence agents (advisory only — ADR-0005)

The Defensive Department's sentinels, on the parallel path. Advisory only: they
emit signals to the deterministic circuit breaker, never enforce directly.

- Telemetry queue from fast path to parallel path.
- **Prompt-Injection Sentinel**: deterministic first; Claude API semantic
  analysis only for unmatched untrusted content; fires the breaker above
  threshold.
- **Behavior Sentinel**: session sequence vs. role/goal every N calls.
- **Data-Leak Sentinel**: exfiltration patterns in outbound arguments.
- **Identity / Tool-Usage / Agent-Communication Sentinels** as the surface
  grows.
- Incident reporter: structured, human-readable incident reports.

## M7 — The first complete department cycle

A small, real version of the full vision — the loop nobody else runs end to end:

```text
Defender detects incident
        ↓
Red Team reproduces it (safe sandbox)
        ↓
Builder proposes a fix (policy/code/tests, never straight to prod)
        ↓
Verifier reruns the attack + full corpus, checks regressions/FP/latency
        ↓
Human approves
        ↓
Fix deployed and monitored
```

Completes **Reproduce → Repair → Verify → Learn & strengthen**. This is where
Olive begins evolving from an MCP firewall into the security organization the
vision describes — including the operating modes (Normal / Suspicious / Siege)
and the Command & Coordination hierarchy.

## Later — the bets

- Real agent identity: toward "SPIFFE for agents", delegation chains,
  capability attenuation.
- Enterprise control plane: centralized policy, agent inventory, org-wide
  visibility, attack replay, cross-session behavioral detection, compliance
  evidence, fleet management — the likely commercial layer.
- Business posture decision (ADR-0003 revisit) after first external feedback.
