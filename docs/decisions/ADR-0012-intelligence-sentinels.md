# ADR-0012: Intelligence sentinels — the advisory parallel path

**Status:** accepted (2026-06-14)

## Context
Through M5 every enforcement decision is deterministic and inline: the policy,
context-policy, and layer-zero pattern inspectors run on the fast path and
`block`/`hold`/`quarantine` is decided by code with explicit rules. That floor is
honest but shallow — the M5 corpus keeps ~20 `known-miss` cases visible:
encoded/obfuscated injections (base64, hex, rot13, url-encode, homoglyph),
semantic injections with no trigger words (paraphrase, language switch),
multi-step chains, and outbound-argument exfiltration. M6 is where Olive adds the
*intelligence* the vision's Defensive Department describes, without ever letting
that intelligence make an enforcement decision (ADR-0005, CLAUDE.md rule 2).

Two distinct kinds of "smarter detection" are conflated if we are not careful,
and they have opposite enforcement properties:

1. **Deterministic-but-deeper.** Decoding an obfuscated payload and re-running the
   *same* deterministic trigger match is still deterministic. There is no reason
   to demote it to advice: a base64 blob that decodes to a known trigger phrase
   should be **blocked inline**, exactly like the plaintext trigger is.
2. **Semantic/behavioral judgement.** "This paraphrase *means* ignore your
   instructions", "this session's tool sequence doesn't match its role" — these
   require an LLM or cross-call state and are non-deterministic and injectable.
   Per ADR-0005 they may only **advise**.

## Decision
M6 is built as two separated pieces along that exact line.

### 1. Deterministic decode layer — inline, enforcing (the "deterministic first")
A new inbound inspector, `DecodeInspector` (`inspectors/decode.py`), runs after
the layer-zero `PatternInspector`. For each inbound content body it derives a
bounded set of **decoded views** — NFKC + homoglyph fold, base64, hex, rot13,
percent/url-decode — and re-runs the existing trigger patterns over each view.
A match `block`s inline, with evidence naming the transform and the matched
region (rule 3: bounded excerpt, never the payload). This is layer "0.5": still
pure deterministic code, still enforcing, still measured by the CI gate
(ADR-0011). It closes the *encoded* `known-miss` cases, which are then promoted to
`active` and the baseline raised — a real, offline, locked-in detection win.

Decoders are conservative to protect the false-positive floor: a view is only
scanned if it decodes to plausible UTF-8 text, and the benign hard-negatives must
still pass (the gate enforces this).

### 2. Advisory sentinels — parallel path, never enforcing
The gateway publishes a `TelemetryEvent` to a `TelemetrySink` after each decision
(`gateway/telemetry.py`). The default sink is `NullSink` (zero overhead, no
behaviour change); the HTTP/stdio composition root may instead install a
queue-backed sink drained by the `SentinelRunner`. Sentinels live in a separate
`intelligence/` layer that the gateway core **never imports** (ADR-0003): the
only paths across the seam are telemetry *out* (the sink) and a quarantine signal
*in* (`CircuitBreaker.trip`, already the documented M6 entry point in ADR-0006).

- **Sentinels emit `Signal(detected, confidence, evidence, sentinel)` only.** The
  `SentinelRunner` aggregates signals and trips the breaker when confidence
  crosses a configured threshold. No sentinel calls `trip` directly and no LLM
  output is ever interpolated into an enforcement path, a policy, or a response
  to the agent (ADR-0005). Sentinel inputs are treated as hostile (the content
  may target the sentinel itself); LLM outputs are parsed defensively (strict
  JSON schema, reject-on-malformed → no signal).
- **Prompt-Injection Sentinel** is deterministic-first: it asks the inline decode
  layer's matcher first and only calls the Claude API for content that produced
  no deterministic match. The semantic verdict is a signal, never a block.
- **Data-Leak Sentinel** scans outbound argument content (in memory only — rule 3)
  for exfiltration indicators and emits a signal.
- **Behavior Sentinel** examines the session tool sequence against the role/goal
  every N calls and emits a signal on drift.
- **Incident reporter** renders the aggregated signals + breaker action into a
  structured, human-readable incident object (hash + bounded evidence only).

### The async-quarantine trade-off, restated
Because semantic sentinels are off the fast path, a response may reach the agent
*before* a sentinel verdict lands. The breaker therefore contains the **session**
(the next call is denied), not that message — exactly the trade-off ADR-0005
documented. Anything we want enforced on the offending message itself must be
deterministic and inline (piece 1), not a sentinel.

## What stays out of scope here (honest boundaries)
- **Inline outbound-argument inspection.** The Data-Leak Sentinel sees argument
  content only on the parallel path, so `exf-*` cases stay `known-miss` in the
  offline gate (covered by sentinel unit tests instead). Making outbound-argument
  exfil an *inline enforced* block requires threading argument content through the
  pipeline plus a dedicated rule-3 review — deferred.
- **Cross-session behavioral state.** The Behavior Sentinel reasons over the
  in-session sequence the breaker already tracks; fleet-wide behavioral baselines
  are a later (likely commercial) layer.
- **The CI gate never depends on a live LLM call.** The Claude path degrades to
  *no signal* when no API key is present, so the deterministic gate stays offline
  and reproducible. Semantic detection is demonstrated by sentinel unit tests
  (with a fake analyzer) and an opt-in, key-gated eval — not the CI floor.

## Consequences
- Encoded injections become deterministic, enforced, CI-gated catches; the
  semantic/behavioral/exfil backlog remains visible `known-miss` until a sentinel
  (or a future inline layer) closes it.
- The open-core seam is now real and exercised: `src/olive/` runs and enforces
  with the intelligence layer entirely absent (NullSink); the intelligence layer
  is additive and removable.
- Every quarantine a sentinel causes is still reproducible from logged signals +
  the breaker threshold — the audit story (ADR-0005) holds.
