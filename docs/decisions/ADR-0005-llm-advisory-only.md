# ADR-0005: LLM verdicts are advisory, never enforcing

**Status:** accepted (2026-06-12)

## Context
LLM-based detection is powerful against semantic attacks but is itself an
injectable, non-deterministic component. A security control that can be
prompt-injected into approving the attack it inspects is worse than none —
and a gateway whose decisions can't be reproduced can't be audited.

## Decision
LLM sentinels run on the parallel path only. They emit signals
(`detected, confidence, evidence`) to the circuit breaker; the breaker — pure
deterministic code with explicit thresholds — makes every enforcement
decision. No LLM output is ever interpolated into an enforcement code path,
a policy file, or a response to the agent. Sentinel inputs are treated as
hostile (the content being analyzed may target the sentinel itself);
sentinel outputs are parsed defensively (strict JSON schema, reject on
malformed).

## Consequences
- Every block/quarantine is reproducible and explainable from logged signals
  + thresholds.
- Detection latency for semantic attacks is async (a response may be released
  before a sentinel verdict lands → quarantine catches the *session*, not
  that message). This trade-off is documented honestly in the threat model.
- Holding responses for inline LLM checks is possible later via the `hold`
  decision, as an opt-in per trust label — never the silent default.
