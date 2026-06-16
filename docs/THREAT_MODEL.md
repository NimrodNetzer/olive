# Threat Model

Read this before touching any enforcement code. If a change conflicts with
this document, update the document first (via ADR if the change is structural).

## Protected assets

- Customer/business data reachable through tools (databases, files, email).
- Credentials and secrets reachable through tools or embedded in tool servers.
- The agent's own behavior: its instructions, memory, and goal integrity.
- The audit trail (events/incidents DB) — integrity and confidentiality.
- The **remediation cycle ledger** (`remediation_cycles`, ADR-0013) — its
  integrity is what guarantees a fix was actually verified by the gate and
  approved by a human before its baseline win was locked in.
- The **operating mode** and the **incident bus** (ADR-0014). A forged
  mode-change could stand the organization down (force Normal during an attack)
  or wedge it into Siege as a denial-of-service; a forged bus object could fake a
  detection or a verification. Bus objects are therefore signed and verified, and
  the mode is writable only through the breaker's narrow `set_mode` by the
  deterministic Commander.
- The **builder-proposals ledger** (`builder_proposals`, ADR-0018) — its
  integrity matters because a proposal must never be *promotable* into a shipped
  fix without re-passing the eval gate and a human `olive:remediate` approval. A
  forged or malicious proposal is inert data: it carries no diff and grants no
  authority until a human drives it through `olive cycle`.

## Trusted components

- The gateway process itself (code, config loading).
- Policy files in `policies/` at load time.
- The local signing key of the mock CA (`identity/`).
- The SQLite event store, as written by the gateway.

## Untrusted inputs — everything that crosses the wire

- All MCP `tools/call` arguments from the client (the agent may already be
  compromised).
- **All tool results** — text, resource contents, structured content. This is
  the highest-risk surface and the reason Olive exists.
- **All MCP server metadata, including tool names and descriptions.** Tool
  descriptions are injected into the agent's context by every MCP client,
  which makes *tool-description poisoning* a first-class injection vector —
  including the "rug pull": a server presents benign descriptions at review
  time and swaps them later.
- Prompts and resources offered by upstream servers.
- Any identity claim not verified cryptographically.

## Attack surfaces

| Surface | Direction | Examples |
|---|---|---|
| Tool call requests | agent → tool | privilege escalation, exfiltration via arguments, tool misuse outside declared role |
| Tool responses | tool → agent | indirect prompt injection, goal hijacking, poisoned retrievals — **most dangerous, most ignored** |
| Tool listings / descriptions | server → agent | description poisoning, rug-pull description swaps, shadowing another server's tool names |
| Server registration | config | malicious or typosquatted MCP servers added as upstreams |
| Agent identity | session | forged identity, replayed/expired tokens, role claims above actual grant |
| Policy & audit files | local | tampering with policies or the event store to hide activity |

## Attacker capabilities assumed

- A legitimate agent that has been **compromised mid-session** by injected
  instructions (the primary scenario — not an obviously evil "attacker agent").
- A legitimate agent attempting actions outside its declared role.
- A malicious external agent claiming a trusted identity.
- A malicious or compromised upstream MCP server, including one that changes
  its tool descriptions between sessions.
- Adversarial content hidden in any document, web page, or API response a
  tool can return — including encoded, obfuscated, or non-English payloads.

## Security guarantees (current milestone)

- Tool calls not allowed by policy are blocked **before** reaching the tool.
- **All untrusted content surfaces are inspected before reaching the agent** —
  tool responses, **resource reads, and rendered prompts** — and matched
  injection content never enters the agent's context (blocked/sanitized).
- Every decision (allow/block/hold/quarantine) produces an auditable event
  with the rule that fired.
- Inspector failure results in `block`, never silent pass-through (fail closed).
- Raw arguments/response bodies are never persisted — hashes and bounded
  evidence excerpts only.
- A session that accumulates repeated security blocks is **quarantined** by the
  circuit breaker (ADR-0006): every subsequent call is denied deterministically
  *before* any inspector runs and *before* the upstream is contacted, until a
  human releases it. Containment is message-independent — it stops the probing
  session, not just the individual payload.
- **Contextual authorization (M4, ADR-0010):** beyond "role may call tool", an
  already-allowed call can be further restricted to the **resource bound to the
  current task** (explicit task binding) or by **data classification ceiling**,
  and high-risk actions can be **held for operator approval**. All checks are
  deterministic structured comparisons over the `SecurityContext`; the inspector
  is refine-only (can block/hold, never grant) and runs after default-deny.
  A held call is released only by a capability-gated (`olive:approve`) operator
  and is specific to one exact call (one-shot) — never by an LLM.

## Explicit non-guarantees (current milestone)

- No protection if the **gateway process itself** is compromised.
- Deterministic patterns do **not** stop semantic, encoded, homoglyph, or
  novel injections — they are layer zero only (unicode NFKC folding and
  format-character stripping are applied, lookalike-character substitution is
  not). LLM sentinels (M6) and the eval harness (M5) address this; until
  then, detection coverage is limited and must be described honestly.
- **Tool, resource, and prompt declarations** (`*/list`) are **content-inspected**
  before reaching the agent (M3): a declaration that trips a layer-zero pattern
  is **withheld** from the listing and logged (`{tool,resource,prompt}-poisoning`).
- **Rug-pull** (a declaration that *changes* between sessions) is detected
  via trust-on-first-use baselines (ADR-0009): a changed declaration is withheld
  and logged as `tool-rug-pull`, even when the new text is pattern-clean; the
  baseline is never overwritten by the swap, and an operator re-approves a
  legitimate change with `olive reset-baselines`. Limits: detection is still
  layer-zero for *content*, so **semantic** description poisoning present from
  the **first** sighting (no trigger words, never changed) is missed until the
  M6 sentinels; and baselines are per-gateway (not federated).
- Containment state (session status, quarantine) is **in-memory and
  per-process** (ADR-0006). In stdio mode that is the whole session, so
  quarantine is effective for the run; but state does not survive a restart and
  there is no cross-process admin surface to release a session yet — that lands
  with the HTTP transport (M2). Release is currently reachable only in-process.
- A call admitted by the breaker *immediately before* a concurrent block trips
  quarantine may still complete (a small TOCTOU window under parallel
  dispatch). Its response is still inbound-inspected, so this does not bypass
  content inspection — it only means containment stops the *next* call, not an
  already-in-flight one.
- Identity is a verified, transport-independent object the gateway enforces as
  (ADR-0007): a signed token's claims drive `agent_id`/`org`/`role`, and **role
  is identity-bound** (a forged or unbacked role is rejected / hits
  default-deny). Over **HTTP (`olive serve`) this is enforced on the wire**:
  every request must carry a CA-signed bearer token; a missing/invalid/expired/
  forged token is 401 *before the gateway is reached* (fail closed). In **stdio**
  mode the gateway still runs under a config-derived **unverified** identity
  (`verified=False`); acceptable only because stdio is single-tenant and spawned
  by a trusting client.
- Capability attenuation (token capabilities ∩ role) is carried but **not yet
  enforced** for tool calls (later M2/M3 slice); today capabilities gate the
  admin endpoints only (`olive:release` for session release, `olive:approve`
  for releasing a held call — distinct scopes, neither implies the other).
- **Remediation cycle (M7, ADR-0013):** the loop never auto-applies a fix — a
  fix reaching production is always a human action in version control. The
  ledger's `verify` transition is writable only from the real eval-gate result
  and `learn` (the baseline lock-in) is refused without a recorded
  capability-gated (`olive:remediate`) approval, so no LLM can self-verify or
  self-approve a change to the security system. Residual risk: a **malicious
  human operator** who holds an `olive:remediate` token *and* can write the DB
  can still approve a bad baseline change — the same insider class as a
  malicious `olive:approve` holder. The cycle narrows the blast radius (fixes are
  proposed as diffs, re-tested, and the approver is recorded) but does not
  eliminate insider risk; `olive:remediate` must be issued narrowly.
- **Red-team engine (M7, ADR-0015):** the `olive redteam` engine attacks Olive's
  OWN pipeline offline and has **no enforcement-write path** — its only outputs are
  a report and `known-miss` candidate cases, so it can never weaken detection to
  fake a win, and it refuses to run if a plain trigger is not caught (no findings
  against a mock). It targets only `build_pipeline` in local/CI context: no network
  egress, no external target (authorized-testing-only, VISION). Residual risk: a
  malicious operator could commit a poisoned candidate, but it lands as inert
  `known-miss` and any promotion still requires the eval gate + an `olive:remediate`
  approval — the same insider class as the remediation cycle.
- **Runtime Red-Team department (M7, ADR-0016):** the scheduled department adds
  *autonomy, not reach*. It attacks only the sandboxed `build_pipeline` — by
  construction it cannot import or be handed the proxy, an upstream, a
  `ClientSession`, or the live breaker, so it can **never inject attacks into real
  agent sessions or tools**. It is advisory-only (never `trip`/`set_mode`), has no
  enforcement-write path, and its findings are a distinct bus kind that **cannot
  move the operating mode** (a drill can't force Siege). Residual risk: a
  misconfigured short interval is a self-DoS class, bounded by the min-interval
  floor + single-flight; the scheduler is in-memory/per-process (same
  non-guarantee as mode/bus). Event-triggered campaigns are deferred precisely
  because they reintroduce a feedback-loop risk this slice structurally avoids.
- **Runtime Builder department (M7, ADR-0018):** adds *autonomy to propose, never
  reach to enforce*. It reacts to confirmed weaknesses and emits a bounded
  fix-proposal + a `fix-proposed` bus object; by construction it cannot import or
  be handed the proxy/upstreams/breaker/`ClientSession`, authors no diff at
  runtime, and never calls `trip`/`set_mode`/`olive cycle`/baseline update (a test
  asserts both the import set and that no enforcement method is referenced). A
  compromised LLM proposer can at worst emit a *bad proposal*, which is inert
  until a human drives it through the eval gate + `olive:remediate` approval — the
  same insider class already documented for ADR-0013. Proposal-spam is bounded by
  novelty dedup (`finding_key` UNIQUE) + single-flight on the replay path; a
  `fix-proposed` object carries `confidence=0.0` and the Commander reads only
  `detection`, so it **cannot move the operating mode**. The department signs with
  the existing per-process HMAC bus key (ADR-0014); this does **not** raise bus
  privilege because no bus object it introduces crosses an enforcement seam
  without independent re-verification. The moment a future slice lets a bus object
  directly drive enforcement without re-verification, per-department CA-signed bus
  identities become a hard prerequisite for it.
- **Co-mounted Command Center (M7, ADR-0020):** running `olive serve --ui` mounts
  the read-only dashboard on the same Starlette app and event loop as the
  bearer-protected gateway. The dashboard and `POST /operator` are NOT behind the
  gateway's bearer auth; their safety rests on the ADR-0017 §5 announce-only closed
  action set and the UI's import-set exclusion (no `trip`/`set_mode`/Commander
  reachable), not on authentication. The single sanctioned on-demand action,
  `run-campaign-request`, runs only a sandbox drill (`run_once()` over
  `build_pipeline`, never live traffic); `force-mode-request` is announce-only.
  Default bind is loopback; `--host 0.0.0.0` would expose the unauthenticated
  dashboard and `POST /operator` to the network and must be explicit (the gateway
  warns). A UI WebSocket flood cannot apply backpressure to the fast path
  (drop-on-full on `MultiSink`, the per-client WS sub-queue, and `QueueSink`).
  Bus/breaker/mode remain in-memory/per-process; a restart loses live containment
  and posture (same non-guarantee as ADR-0006/0014).
- **Runtime agent company (M7, ADR-0014):** the Security Commander is
  deterministic code — no LLM decides the operating mode or any enforcement
  action. LLM agents only publish evidence objects to the bus; the deterministic
  Commander (or a capability-gated `olive:command` human) moves the mode, and the
  `SentinelRunner` remains the sole `trip` authority. Bus objects are
  HMAC-signed so a compromised agent cannot forge a mode-change/verification.
  Honest limits: the operating mode and the in-process bus queue are
  **in-memory/per-process** (like containment) — they do not survive a restart
  and do not propagate across a fleet; the first slice's bus signing uses a
  per-process key, so bus integrity rests on that key (a process-memory
  compromise undermines it, the same class as the mock-CA key assumption). Only
  Defense and Remediation are wired; runtime Red-Team/Builder autonomy and the
  supervisor hierarchy do not exist yet.
- **Contextual authz limits (M4, ADR-0010):** resource scoping only applies to
  tools with a declared extractor and to predicates over the *scoping id* and
  *classification* — **content-aware** authorization (e.g. "the body contains no
  external address") is deferred to the M6 Data-Leak Sentinel (advisory).
  Pending-approval state is **in-memory/per-process** (like containment): it does
  not survive a restart. Task-resource binding is only as trustworthy as the
  identity that carries it — under stdio's unverified identity it is advisory.
- Containment keys on the namespaced **(org, agent, session_id)** triple
  (`IdentityClaims.session_key`), so two tokens that reuse a `session_id` across
  different agents/orgs do **not** share breaker/rate-limiter state. State is
  still in-memory/per-process (no persistence across restarts).
- Per-session breaker/rate-limiter state is **evicted when idle** past a TTL
  (lazy sweep + `evict_idle`), bounding memory under many short-lived sessions.
  **Quarantined sessions are never evicted** — going idle cannot clear a
  quarantine. (A real persistence layer for quarantine across restarts is still
  future work.)
- Token verification trusts the configured CA public key (`--ca-pubkey`); a
  compromised CA key or a misconfigured public key undermines identity. The mock
  CA is for dev; production needs a real key-managed CA.
- No detection of multi-day slow-burn campaigns or covert channels hidden in
  *allowed* traffic.
- No protection against a malicious human operator with local file access.
