# ADR-0009: Rug-pull detection via trust-on-first-use baselines

**Status:** accepted (2026-06-14)

## Context
A compromised or malicious MCP server can present benign tool declarations at
review/first-use, then **swap them later** to inject the agent (the "rug-pull",
THREAT_MODEL.md). Slice 1 (M3) inspects every `tools/list` declaration through
the layer-zero pattern pipeline, but that only catches descriptions that *trip a
pattern*. A rug-pull whose new description is semantically malicious yet
pattern-clean would pass. Detecting the **change itself** — independent of
content — is the missing defense, and it is inherently **stateful** (it compares
across sessions), unlike the content-based eval corpus.

## Decision
**Trust-on-first-use (TOFU) baselines**, persisted in the existing SQLite store
(ADR-0004):

- New table `tool_baselines(tool_name PK, declaration_hash, first_seen,
  last_seen)`. The key is the (namespaced) tool name, so a baseline is a
  property of the upstream tool, shared across agents/sessions.
- On each listing, after slice-1 pattern inspection passes, the gateway calls
  `observe_tool(name, hash)` where `hash` = SHA-256 of the full tool declaration
  (name + description + schema):
  - **NEW** (unseen): record the baseline, serve the tool (first-use trust).
  - **UNCHANGED**: refresh `last_seen`, serve.
  - **CHANGED**: a declaration differs from its baseline → **withhold** the tool
    and log a `tool-rug-pull` incident. **Fail closed**: a silent change is
    treated as hostile until a human re-approves.
- **The baseline is never auto-updated on a mismatch.** Otherwise the swap would
  become the new baseline and succeed on the next session. It only advances on a
  match (or an explicit reset).
- **Operator re-approval**: `olive reset-baselines` clears baselines (all or one
  tool) so a *legitimate* description update can be accepted on the next listing.

## Limits / non-goals
- **TOFU trusts the first sighting.** A server malicious from the very first
  listing is not caught by *this* mechanism (slice-1 patterns and the M6
  sentinels are the content defenses). Rug-pull defends change-after-trust.
- State is per-gateway (its DB); not federated across deployments.

## Consequences
- Semantic rug-pulls that evade pattern matching are caught by the *change*
  signal — withheld and audited — closing a documented MCP-specific gap.
- Because this is stateful, it is verified by unit/integration tests rather than
  the content-based corpus (the corpus stays single-payload).
- Legitimate description churn requires a deliberate operator reset — an
  intentional, audited friction that matches a fail-closed posture.
