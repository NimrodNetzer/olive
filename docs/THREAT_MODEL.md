# Threat Model

Read this before touching any enforcement code. If a change conflicts with
this document, update the document first (via ADR if the change is structural).

## Protected assets

- Customer/business data reachable through tools (databases, files, email).
- Credentials and secrets reachable through tools or embedded in tool servers.
- The agent's own behavior: its instructions, memory, and goal integrity.
- The audit trail (events/incidents DB) — integrity and confidentiality.

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
- Tool responses from untrusted sources are inspected **before** reaching the
  agent; matched injection content never enters the agent's context.
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

## Explicit non-guarantees (current milestone)

- No protection if the **gateway process itself** is compromised.
- Deterministic patterns do **not** stop semantic, encoded, homoglyph, or
  novel injections — they are layer zero only (unicode NFKC folding and
  format-character stripping are applied, lookalike-character substitution is
  not). LLM sentinels (M6) and the eval harness (M5) address this; until
  then, detection coverage is limited and must be described honestly.
- Tool declarations from `tools/list` (name + description + input schema) are
  now **content-inspected** before reaching the agent (M3): a tool whose
  declaration trips a layer-zero pattern is **withheld** from the listing and
  logged as a `tool-poisoning` incident, and a hash of all names+descriptions is
  still recorded per listing.
- **Rug-pull** (a tool declaration that *changes* between sessions) is detected
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
  enforced** for tool calls (later M2/M3 slice); today capabilities only gate the
  admin release endpoint (`olive:release`).
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
