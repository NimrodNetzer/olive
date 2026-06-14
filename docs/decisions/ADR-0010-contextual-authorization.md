# ADR-0010: Contextual authorization

**Status:** accepted (2026-06-14)

## Context

Through M3, authorization is coarse: a `role` may call an `allowed_tool`
(`inspectors/policy.py`, default-deny). The vision and ROADMAP (M4) require
finer authority — "this specific agent may perform this action on this
specific resource for this task" — expressing user/org identity, current
goal, requested resource, data classification, delegation, session history,
risk, and approval requirements.

Three constraints shape the design:

1. **Rule 3 (CLAUDE.md):** raw tool arguments never enter `SecurityContext`
   or the store — only `arguments_hash` + bounded evidence. So resource-scoping
   predicates cannot regex the arguments.
2. **ADR-0005:** no LLM output may reach an enforcement path.
3. The pipeline already defines `Decision.HOLD` (`gateway/pipeline.py`) but
   nothing produces or consumes it.

## Decision

Add **contextual authorization as a second, refine-only deterministic
inspector**, layered on top of the unchanged coarse allowlist.

- **Structured resource references, not raw-argument inspection.**
  `SecurityContext` gains one field, `requested_resource: ResourceRef | None`,
  where `ResourceRef = (type, id, classification)`. A per-tool **resource
  extractor** (declared in policy by argument key) pulls only the *scoping
  identifier* from named arguments — never the payload. Contextual predicates
  compare **structured fields** (set membership, ordinal classification,
  equality against a session task binding) — never free text. The raw argument
  values still never enter context or store; the resource `id` is a non-secret
  scoping key stored under the existing hash discipline. This is a *narrowing*
  of rule 3, not an exception: we read a declared, non-secret identifier by
  key, we do not scan the payload. A tool whose scoping id is itself sensitive
  declares it `hash-only`; predicates may then only test equality of hashes.
  Predicates needing argument *content* (e.g. "body contains no external
  address") are out of scope for the wall and belong to the M6 Data-Leak
  Sentinel (advisory, parallel path).

- **`ContextPolicyInspector`** (outbound, `inspectors/context_policy.py`):
  ordered structured rules per role. A rule matches on `tool` + structured
  `when:` conditions and yields `allow-refine | block | hold`. It runs
  **after** the coarse `PolicyInspector`, so it can only further restrict or
  hold — never grant a tool the allowlist denied. Default-deny is unchanged.

- **Reuse `Decision.HOLD` for human-in-the-loop.** An approval-required action
  yields `hold`: the call is not forwarded and not treated as an attack. It
  mints **no incident** and does **not** count toward the breaker's quarantine
  threshold (like a rate-limit throttle, ADR-0006) — it is a governance pause,
  audited as a `hold` event (rule 5). Release is a **deterministic,
  capability-gated operator action** (`olive:approve`, mirroring the
  `olive:release` surface of ADR-0006/0007). **No LLM may release a hold**
  (ADR-0005).

- **Backward-compatible schema.** `roles.{allowed_tools, forbidden_tools,
  max_calls_per_minute}` are untouched and remain the authoritative coarse
  gate. New keys (`max_classification`, `rules:`, resource-extractor decls) are
  **optional and additive**; a role without them behaves exactly as M3.
  `default.yaml`/`multi.yaml` keep working unchanged.

- **Composition with the wall's guarantees.** Contextual rules are
  AND-on-top-of the allowlist (refine-only, never grant). Fail-closed holds:
  the new inspector is an ordinary plugin, so any exception → `block`
  (`pipeline.py`); a malformed rule fails closed at load (`ConfigError`).
  Layering (ADR-0003) is intact: everything lives in `inspectors/`,
  `gateway/context.py`, `config.py`, and the existing capability-gated admin
  surface — no intelligence/fleet imports, no LLM on the path.

## Scope / deferral

- Resource extraction reads only declared scoping ids; content-aware
  authorization is M6 (advisory).
- Pending holds are **in-memory/per-process** initially (like ADR-0006
  containment); a `pending_approvals` table is added only when cross-process /
  restart-surviving approval is required — it would reuse the ADR-0004 store.
- Delegation chains / capability attenuation predicates consume the
  `IdentityClaims.capabilities` already carried (ADR-0007); full delegation is
  a later bet.

## Consequences

- Authorization moves from "role may call tool" to per-resource, per-task,
  classification-aware, approval-gated decisions — all deterministic and
  auditable, the `Govern` step deepened without weakening the wall.
- `Decision.HOLD` becomes live, giving operators a human-in-the-loop gate that
  is explicitly *not* an attack signal.
- New/changed detection logic → `red-team` pass; every bypass becomes a
  corpus case (ROADMAP). `security-reviewer` on the `gateway/`+`inspectors/`
  diff; `qa` at milestone close.
