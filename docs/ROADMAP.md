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

## M3 — Complete MCP-surface protection  ✅ done

Inspect the whole MCP surface, not just `tools/call` content:

- ✅ Tool names, descriptions, and schemas content-inspected at `tools/list`;
  poisoned tools are withheld from the agent and logged (`tool-poisoning`).
- ✅ **Rug-pull** detection (ADR-0009): trust-on-first-use baselines flag a
  declaration that changes between sessions; it is withheld until an operator
  re-approves (`olive reset-baselines`).
- ✅ Resources & prompts: `resources/list` + `prompts/list` declarations
  screened (poison/rug-pull → withheld); `resources/read` + `prompts/get`
  content inspected like a tool response (poison → sanitized).

## M4 — Contextual authorization  🚧 in progress

Move beyond "this role may call this tool" toward "this specific agent may
perform this specific action on this specific resource for this specific task."
Policies grow to include: user identity, organization, current goal, requested
resource, data classification, delegation source, session history, risk level,
and approval requirements.

Decided in ADR-0010 and built so far:

- ✅ **Structured resource extraction**: per-tool extractors lift only the
  declared scoping id into a `ResourceRef` (`type`, `id`, `classification`) -
  never the payload (rule 3); sensitive ids are hashed.
- ✅ **`ContextPolicyInspector`** (refine-only, after the coarse allowlist):
  ordered deterministic rules that `block` or `hold` an already-allowed call,
  never grant one. Predicates: explicit task binding
  (`resource.id_in: task.resources`), classification ceilings, approval.
- ✅ **`Decision.HOLD` wired**: a governance pause (no incident, no breaker
  trip), with a capability-gated (`olive:approve`) operator approval that
  releases one specific held call (one-shot, argument-specific).
- ✅ Corpus `ctx-*` cases run against `policies/contextual.yaml`.

## M5 — Measured detection (the moat)  ✅ done

- ✅ Attack corpus = 53 cases: trigger phrases, encoded/obfuscated (base64,
  fullwidth-unicode, homoglyph, hex, rot13, url-encode, zero-width,
  language-switch), semantic (no trigger words), tool-description poisoning /
  rug-pull (content surface), exfiltration-via-arguments, multi-step chains,
  plus benign hard negatives. Honest by construction: cases layer-zero cannot
  catch are `known-miss`, kept visible as the backlog M6 closes.
- ✅ Metrics in the runner: detection rate, false-positive rate, added latency
  p50/p95 per direction, per-category breakdown, corpus size.
- ✅ CI regression gate (ADR-0011): a committed `evals/baseline.json` of
  **counts** pins the floor; the run exits non-zero on a per-case flip, a total
  or per-category detection drop (incl. silent reclassification to known-miss),
  or a false-positive rise. `.github/workflows/ci.yml` runs tests + the gate on
  every push/PR. The harness itself is unit-tested (`tests/test_evals.py`).

> A security product without measurable results becomes marketing.

## M6 — Intelligence agents (advisory only — ADR-0005)  ✅ done

The Defensive Department's sentinels, on the parallel path. Advisory only: they
emit signals to the deterministic circuit breaker, never enforce directly.
Decided in ADR-0012, split along the architectural law (agents advise,
deterministic code enforces):

- ✅ **Deterministic decode layer (inline, enforces, CI-gated)** — the
  "deterministic first" half: `inspectors/decode.py` (layer 0.5) decodes
  base64/hex/rot13/url-encoding and folds homoglyphs, then re-runs the trigger
  matcher. Closed 5 encoded `known-miss` corpus cases (promoted to `active`,
  baseline raised: detection 22→27).
- ✅ **Telemetry seam** (`gateway/telemetry.py`): the gateway publishes a
  `TelemetryEvent` to a `TelemetrySink` after each decision (default `NullSink`,
  zero overhead). The open-core boundary (ADR-0003) is now real and exercised —
  gateway core never imports the intelligence layer.
- ✅ **Intelligence layer** (`src/olive/intelligence/`, advisory only):
  - **Prompt-Injection Sentinel**: deterministic-first; Claude API semantic
    analysis only for unmatched untrusted content; hostile-content delimiter
    defense + defensive strict-JSON parse; degrades to no-signal without a key.
  - **Data-Leak Sentinel**: exfiltration indicators in outbound arguments.
  - **Behavior Sentinel**: read → egress chain across the session sequence.
  - **SentinelRunner**: aggregates signals; the only place a signal becomes an
    action — a single deterministic `breaker.trip` above a threshold.
  - **Incident reporter**: structured, human-readable incident objects.
- ✅ red-team pass: 7 new deterministic-bypass `known-miss` cases
  (inj-0018..0024 — base32/base85/nested/fragmented/capital-homoglyph) +
  2 benign hard negatives; corpus 53→62, gate still 0 FP.
- **Identity / Tool-Usage / Agent-Communication Sentinels** remain future work
  as the surface grows.

## M7 — The first complete department cycle  🚧 in progress

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

**First slice (built — ADR-0013):** the deterministic, human-gated cycle itself.
- ✅ `builder` agent (`.claude/agents/`): proposes a fix as a reviewable diff,
  never applied to prod, never self-approves, never silently weakens detection.
  Verifier is **not** a new LLM agent — it stays `qa` + the deterministic eval
  gate (ADR-0005 spirit).
- ✅ **Remediation cycle ledger** (`intelligence/remediation.py`): states
  `reproduced → fix-proposed → verified → approved → learned` (+ `rejected`),
  driven by `olive cycle open/propose/verify/approve/learn/show`. **Verify** is
  writable only from the real `run_evals.py` gate result; **learn** (the
  baseline lock-in) is refused without a recorded capability-gated
  (`olive:remediate`) human approval. Rule-3 fields only (patch hash + bounded
  summary). Lives on the intelligence side of the open-core seam (ADR-0003).
- ✅ Reuses: `red-team` = Reproducer, eval corpus + baseline gate = Verifier and
  the Learn mechanism (`--update-baseline`), `incidents`/`IncidentReport` = the
  structured incident.

**Second slice (built — ADR-0014):** the runtime agent company foundation.
- ✅ **Operating modes** (`gateway/mode.py` + breaker): `normal/suspicious/siege`
  as a core-owned value the breaker holds; mode tunes the deterministic inline
  containment threshold. Delivered through `breaker.set_mode` — a second narrow
  inward seam crossing, the same shape as `trip`.
- ✅ **Security Commander** (`intelligence/commander.py`): deterministic, not an
  LLM. Sole caller of `set_mode`; escalates from the detection stream via a pure
  `target_mode()` policy; only a capability-gated (`olive:command`) human
  de-escalates. `SentinelRunner` keeps sole `trip` authority — one writer each.
- ✅ **Incident bus** (`intelligence/bus.py`): async pub/sub + append-only
  `incident_events` audit table; HMAC-signed `IncidentObject`s (forged/tampered
  rejected fail-closed); rule-3 envelope (no raw payloads). Departments collaborate
  through structured objects, never group chat.
- ✅ **Two departments wired** (`intelligence/departments.py`): Defense
  (`SentinelRunner.on_report` → bus) and Remediation (ledger subscribes; a
  `reproduced` object opens a cycle). `build_runtime_org` shares one breaker.

**Still deferred (later within/after M7):** the supervisor tier of the Command &
Coordination hierarchy; runtime Red-Team/Builder **autonomy** (build-time agents
only for now); credential/token freezing in Siege; durable/fleet-wide mode + bus.

## Later — the bets

- Real agent identity: toward "SPIFFE for agents", delegation chains,
  capability attenuation.
- Enterprise control plane: centralized policy, agent inventory, org-wide
  visibility, attack replay, cross-session behavioral detection, compliance
  evidence, fleet management — the likely commercial layer.
- Business posture decision (ADR-0003 revisit) after first external feedback.
