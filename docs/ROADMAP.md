# Roadmap

Milestones, not dates. Each milestone ends with: tests green, `qa` agent pass,
`security-reviewer` pass on enforcement code, demo runnable.

## M1 — Foundation + walking skeleton  ← current

- Foundation docs (vision, threat model, architecture, evals strategy, ADRs).
- The agent company (`.claude/agents/`): architect, security-reviewer,
  red-team, qa.
- Real MCP proxy over stdio: `tools/list` + `tools/call` forwarded,
  bidirectional inspection.
- Policy inspector (outbound, default-deny) + pattern inspector (inbound,
  layer zero).
- SQLite audit store (events + incidents, hash-only).
- Identity module (mock-CA RS256 JWT) — unit-tested, not yet wire-enforced.
- Demo MCP tool server + scripted demo: allow / policy-block / response-block.
- Seed eval corpus (~10 cases incl. benign) + eval runner with detection table.

## M2 — Sessions, containment, HTTP

- Session state tracking (call sequence, counts, first/last seen).
- Circuit breaker: quarantine on signal, blocklist check on every call,
  reversible human release.
- Streamable HTTP transport; JWT identity enforced on the wire.
- Multi-upstream support (one gateway fronting several tool servers).
- Rate limiting per role (`max_calls_per_minute`).

## M3 — Intelligence layer (advisory only — ADR-0005)

- Telemetry queue from fast path to parallel path.
- Injection sentinel: deterministic first; Claude API semantic analysis only
  for unmatched untrusted content; fires circuit breaker above threshold.
- Behavior sentinel: session sequence vs. role/goal every N calls.
- Incident reporter: structured, human-readable incident reports.

## M4 — Measured detection (the moat)

- Attack corpus ≥ 50 cases: trigger phrases, encoded/obfuscated (base64,
  unicode, language-switch), semantic (no trigger words), tool-description
  poisoning / rug-pull, exfiltration-via-arguments, plus benign hard negatives.
- Metrics: detection rate, false-positive rate, added latency p50/p95.
- CI regression gate: detection may never silently drop.
- Tool-description inspection in the gateway (`tools/list` diffing).

## M5 — Showable

- Rich terminal dashboard (events vs. incidents, live).
- Polished demo: the three-agent scenario (support / finance escalation /
  compromised vendor) running through the real gateway.
- README quickstart ≤ 5 minutes; architecture diagram; honest detection
  numbers from M4.
- First external demos (design-partner conversations).

## Later — the bets

- Real agent identity: toward "SPIFFE for agents", delegation chains,
  capability attenuation.
- **Reproduce → Repair → Verify**: incident → reproducible corpus case →
  proposed policy/detection fix → verified by eval rerun. Human-approved.
- Fleet management, compliance reporting (the likely commercial layer).
- Business posture decision (ADR-0003 revisit) after first external feedback.
