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

**Third slice (built — ADR-0015):** the autonomous red-team engine that closes the
self-improvement loop.
- ✅ **`olive redteam`** (`src/olive/redteam/`): deterministic, offline. Applies
  `AttackStrategy` mutators (base32 / double-base64 / chunked-base64 /
  capital-homoglyph — mapped to existing known-miss cases) to seed intents and runs
  every variant through the **real** `build_pipeline`; an allowed variant is a
  bypass. Proves the pipeline is live (plain trigger must block) before trusting a
  finding; has **no enforcement-write path** (only emits `known-miss` candidates) —
  so it can never weaken detection to fake a win.
- ✅ Closes the loop with the existing pieces: bypass → human commits known-miss →
  `builder` fixes → `olive cycle` verify → human approve → baseline rises. "Stronger"
  is measured on the existing baseline + bypass count, not a new metric.
- ✅ The four seed-mapped known-miss cases carry a `redteam_key`, so the engine
  reports them as rediscovered (not novel) — and surfaces genuinely new gaps.

**Fourth slice (built — ADR-0016):** the runtime Red-Team **department**.
- ✅ **`intelligence/redteam_dept.py`**: wraps the ADR-0015 engine as a runtime
  department that, on a trigger (`run_once()` or a scheduled interval), runs a
  **sandbox** campaign and publishes bypass findings onto the bus as a distinct
  `redteam-finding` kind. `olive redteam-dept run` is the operator/CI trigger.
- ✅ Three structural guarantees: **sandbox-only** (cannot import the
  proxy/upstreams/ClientSession/live breaker — a test asserts it; it attacks only
  `build_pipeline`, never live traffic); **a drill never escalates the mode**
  (Commander only reads `detection`); **no feedback loop** (publishes, subscribes
  to nothing). Anti-DoS: min-interval floor + single-flight + novel-only dedup.
- ✅ Advisory-only (never `trip`/`set_mode`/`olive cycle`); Remediation records a
  finding as an intent; humans still gate every promotion (ADR-0013).

**Fifth slice (built — ADR-0018):** the runtime Builder **department**.
- ✅ **`intelligence/builder_dept.py`**: subscribes to confirmed weaknesses
  (`redteam-finding` + `reproduced`) and turns each novel one into a bounded
  fix-proposal — a `builder_proposals` row (rule-3: hash + ≤200-char summary,
  never a diff) + a published `fix-proposed` object. `olive builder-dept run`
  replays the bus and proposes for novel weaknesses.
- ✅ **Propose-only by construction**: cannot import the
  proxy/upstreams/breaker/ClientSession and never calls `trip`/`set_mode`/`olive
  cycle`/baseline update (a test asserts the import set *and* no enforcement call);
  authors **no diff** at runtime (`patch_hash` null — the diff stays the build-time
  `.claude/agents/builder.md`). No self-trigger (never subscribes to its own
  `fix-proposed`); `confidence=0.0` so it cannot move the mode. Spam-bounded by
  novelty dedup.
- ✅ Promotion unchanged: a proposal is inert until a human walks the fix through
  `olive cycle` (eval gate + `olive:remediate` token).

**Still deferred (later within/after M7):** the **supervisor tier** of the Command
& Coordination hierarchy (no specialists to supervise yet); **event-triggered**
Red-Team ("after every incident"); **auto-apply** of a proposed fix (permanently
human-gated); LLM-creative generation in CI (stays the human-supervised build-time
agents); CI plumbing for deploy/PR triggers; per-department **CA-signed bus**
identities (parallel, non-gating); credential/token freezing in Siege;
durable/fleet-wide mode + bus.

**Sixth slice (built — ADR-0017):** the Agentic Command Center (Textual TUI).
- ✅ **`olive ui`** (`src/olive/ui/`): a read-only Textual TUI visualizing the
  runtime org — department status, the central gateway node, a live
  mitigation/audit feed, and an attack-theater sidebar over `evals/corpus/`
  (fires the existing sandbox `run_campaign`/`run_once()`, never live traffic).
- ✅ `UIBroker` is a third intelligence-side `TelemetrySink` + `IncidentBus`
  subscriber, projecting into a bounded rule-3 `UIEvent`; read-only by
  construction (import-set test excludes breaker/proxy/Commander). UI-initiated
  requests publish an announce-only `operator-request` bus object — they never
  themselves change mode or trip the breaker.

**Seventh slice (built — ADR-0019):** the web dashboard.
- ✅ **`olive ui --web`** (`ui/web.py` + `ui/static/`): Starlette/WebSocket
  server pushing the same `UIEvent` stream to a browser. Plain HTML/CSS/JS, no
  build step, loopback-only default. `POST /operator` is the single inbound write
  (announce-only, same closed action set as ADR-0017 §5).

**Eighth slice (built — ADR-0020):** the LIVE Command Center — the runtime org
wired into `olive serve`.
- ✅ **`olive serve --ui`**: one process, one event loop, sharing one bus +
  breaker + UIBroker between the gateway and the co-mounted dashboard, so the UI
  shows the live incident stream. A `MultiSink` fans telemetry to the
  SentinelRunner and the UIBroker; the runtime org runs in the ASGI lifespan.
- ✅ UI routes co-mounted **without** bearer auth (`/mcp` stays protected); the
  "fire drill" button → `run-campaign-request` → a deterministic `OperatorBridge`
  → a sandbox `run_once()`. Additive, default-off, no API key required for the
  full detect → bus → UI → fix-proposal loop. Loopback-only by default.

## Later — the bets

- Real agent identity: toward "SPIFFE for agents", delegation chains,
  capability attenuation.
- Enterprise control plane: centralized policy, agent inventory, org-wide
  visibility, attack replay, cross-session behavioral detection, compliance
  evidence, fleet management — the likely commercial layer.
- Business posture decision (ADR-0003 revisit) after first external feedback.
