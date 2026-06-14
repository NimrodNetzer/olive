# ADR-0013: The remediation cycle — first department loop (ledger + builder)

**Status:** accepted (2026-06-15)

## Context
M1–M6 built the deterministic wall (M1–M5) and the advisory intelligence layer
(M6). What the VISION calls "the full security cycle" —
`Govern → Detect → Contain → Reproduce → Repair → Verify → Learn & strengthen` —
is implemented only through *Contain*. The back half (Reproduce → Repair →
Verify → Learn) has never been run end to end, yet it is the differentiator the
VISION leans on hardest: "Everyone detects and blocks. Almost nobody does
Reproduce → Repair → Verify."

Most of the loop already exists as separate pieces:

- The **`red-team` agent IS the Reproducer** — it already turns a bypass into an
  `evals/corpus/` case (`status: known-miss`).
- The **eval corpus + baseline regression gate** (`evals/run_evals.py` +
  `evals/baseline.json`, ADR-0011) **IS the Verifier** — deterministic, already
  the regression authority. Promoting a `known-miss` case to `active` and running
  `--update-baseline` **IS "Learn & strengthen."**
- **Structured incident objects** already exist: the SQLite `incidents` table
  (`store/events.py`) and the M6 `IncidentReport` (`intelligence/reporter.py`).

What is missing is (a) a **Builder** role that proposes a fix, and (b) a
deterministic, auditable, **human-gated** state machine that connects incident →
reproduction → fix → verification → learn without ever letting an LLM agent (or
an attacker steering one) modify the security system's own enforcement.

That last risk is the whole reason this ADR is conservative. VISION department 3
states the Builder "never makes unrestricted changes directly in production —
this is what stops an attacker from manipulating the security system into harming
its own company." This ADR makes that property structural, not a guideline.

## Decision

M7's first slice is **one vertical loop over a single incident**, built as a
deterministic state machine with two human-gated transitions and zero new
enforcement authority granted to any LLM.

### 1. Scope — first slice only
IN: the remediation cycle ledger, the `builder` agent, and an `olive cycle` CLI
that walks one incident through the loop. OUT (deferred within or after M7):
operating modes (Normal / Suspicious / Siege), the Command & Coordination
hierarchy (Commander / Supervisors), credential rotation, any auto-apply or
auto-deploy of a fix, and any fleet/cross-process coordination. One ledger plus
one builder agent demonstrates the loop without the org choreography.

### 2. `builder` agent — added; never touches prod
A new `.claude/agents/builder.md`. Given a confirmed weakness and the reproduced
corpus case, it **proposes a fix as a diff** (a new policy pattern, a `decode.py`
view, a sentinel-threshold tweak, a contextual rule) **plus** the corpus case
update. It **never applies a change to `src/` in production, never self-approves,
and never silently changes an enforcement threshold** — any threshold change is
flagged for `security-reviewer`. Its output is a patch + rationale, full stop. It
carries the same authorized-scope framing the `red-team` agent has.

### 3. No LLM verifier
Verification is **`qa` (already exists) + the deterministic `run_evals.py` gate**
(ADR-0011), which is already the regression authority. We do **not** add an LLM
`verifier` agent: an LLM in the verification path would be a soft violation of
ADR-0005 and of VISION department 4 ("a fix is complete only when independent
*tests* prove it — not because an agent says so"). The deterministic gate is that
independent test. The ledger's **Verify** transition is writable **only** from a
recorded gate result, never from an agent's assertion.

### 4. `olive cycle` CLI — the deterministic orchestrator
The loop is driven by a new CLI surface, not a standalone script (which would
escape the store/identity discipline) and not a pure agent-driven runbook (which
would put the approve/verify state transitions in an LLM's hands). `cli.py` is
already the composition root that owns DB lifecycle; `olive cycle` reuses it.

```
olive cycle open    --config c --incident INC-NNNN --case CASE-ID   # → reproduced
olive cycle propose --config c --cycle CYC-NNNN --patch fix.patch    # → fix-proposed
olive cycle verify  --config c --cycle CYC-NNNN                      # runs the gate → verified | rejected
olive cycle approve --config c --cycle CYC-NNNN --ca-pubkey k --token T  # → approved (capability-gated)
olive cycle learn   --config c --cycle CYC-NNNN                      # requires approval → learned
olive cycle show    --config c --cycle CYC-NNNN
```

The CLI is **deterministic at the enforce/verify/approve/learn steps**: `verify`
runs the real gate subprocess and records its real exit code (there is no flag to
inject a passing result); `approve` requires a cryptographically verified
capability token; `learn` refuses unless an approval is already recorded.

### 5. Remediation cycle ledger
A new `remediation_cycles` table with linear states and a strict
transition-authority table.

States: `reproduced → fix-proposed → verified → approved → learned`, plus a
terminal `rejected` reachable from `fix-proposed` or `verified`.

| Transition      | Set by                              | Constraint |
|-----------------|-------------------------------------|------------|
| → reproduced    | `olive cycle open`                  | requires an existing `incident_id` + a reproduced corpus case id |
| → fix-proposed  | `olive cycle propose`               | records the patch **hash**; no enforcement |
| → verified      | **deterministic gate only**         | written iff `run_evals.py` returned exit 0; never by an agent |
| → rejected      | gate fail, or human decline         | audited; terminal |
| → approved      | **human only**, capability-gated    | records `approved_by` from a verified `olive:remediate` token; no LLM may reach this (ADR-0005) |
| → learned       | `olive cycle learn`                 | **blocked unless `approved` is recorded**, then runs `--update-baseline` |

Persisted fields are **rule-3 safe — hashes + bounded text only**, never the diff
body or any raw payload:

```
cycle_id        TEXT PK   -- 'CYC-0001', single-statement-derived like incidents
incident_id     TEXT      -- the M6/breaker incident this cycle remediates (string ref only)
corpus_case_id  TEXT      -- the reproduced known-miss case (red-team output)
state           TEXT
patch_hash      TEXT      -- SHA-256 of the proposed diff, never the diff body
patch_summary   TEXT      -- bounded ≤200 chars, human-written one-liner
gate_detected   INTEGER   -- detected count at verify time
gate_false_pos  INTEGER   -- false-positive count at verify time
gate_passed     INTEGER   -- 0/1, the gate exit code
approved_by     TEXT      -- agent_id of the verified human approver (null until approved)
approved_at     TEXT
created_at      TEXT
updated_at      TEXT
```

The patch itself lives as a file / PR in version control; the ledger only
fingerprints it — mirroring how `incidents` stores bounded `evidence` and
`tool_baselines` stores only a declaration hash.

**Crucially, the ledger never applies a patch and never mutates the corpus or
`src/`.** A human applies the proposed patch on a normal dev branch, promotes the
corpus case to `active`, and the gate re-runs — outside the cycle tool. The
ledger records gate *results*; it never produces them by editing code. This keeps
the deterministic gate's independence (ADR-0011: "the baseline moves only by an
explicit, reviewable act") and removes any path by which the loop could rewrite
its own enforcement.

### 6. Human approval gate is mandatory
`approve` requires a CA-signed token carrying a **new, distinct** capability
`olive:remediate`, verified against the CA public key (mirroring `serve` and the
`olive:approve` / `olive:release` admin pattern). A new capability rather than
reusing `olive:approve`: approving a *security fix to ship* is a strictly larger
authority than releasing one held call, and the identity model already
establishes that capabilities do not imply one another. `learn` (the
`--update-baseline` lock-in) is refused unless an `approved` row exists. LLM
agents only propose and reproduce; they never reach `approved` or `learned`.

### 7. Open-core seam (ADR-0003)
The ledger lives on the **intelligence side** — `src/olive/intelligence/
remediation.py` — and owns its own `aiosqlite` access to the same DB file,
referencing the incident by `incident_id` **string only**. It never imports
`IncidentReport` into core, and the gateway core (`gateway/`, `store/`) never
imports the ledger. `cli.py`, the composition root, wires `olive cycle` to it
with a **local import inside the handler**, exactly as `serve_http` already does
for the HTTP/transport stack. The seam stays a clean cut: `src/olive/` enforces
with the remediation layer entirely absent.

## What stays out of scope here (honest boundaries)
- **Operating modes & Command/Coordination hierarchy** — a later slice within M7
  or deferred. This ADR builds the loop, not the org chart.
- **Auto-apply / auto-deploy of any fix** — permanently human-gated by design; a
  fix reaching production is always a human action in version control.
- **Durable approvals across the admin surface** — the cycle's approval is
  recorded in the ledger row itself (it must survive to gate `learn`); the
  in-memory `ApprovalRegistry` (ADR-0010) is unchanged and unrelated.
- **Credential rotation** (VISION dept 3 lists it) — touches live secrets;
  deferred explicitly.

## Consequences
- The loop nobody else runs is real, end to end, and fully auditable: every
  transition is reproducible from the ledger row, and the two consequential
  transitions (verify, approve→learn) cannot be reached by an LLM.
- **No new enforcement authority is granted to any LLM.** Verify is
  deterministic-gate-only; approve is human-and-capability-gated; learn is
  approval-gated. ADR-0005 is extended, not bent.
- The open-core seam (ADR-0003) is preserved and further exercised: the ledger is
  additive and removable, and core never imports it.
- A **malicious human operator** who holds `olive:remediate` and can write the DB
  can still approve a bad baseline change. This is a documented non-guarantee
  (see `THREAT_MODEL.md`), the same class as the existing "malicious operator with
  `olive:approve`" — the cycle narrows the blast radius (proposes diffs, re-tests,
  records who approved) but does not eliminate insider risk.

## Required doc updates
- `docs/ARCHITECTURE.md` — new "Remediation cycle ledger" component + the seam
  decision.
- `docs/THREAT_MODEL.md` — ledger integrity as a protected asset + the malicious-
  `olive:remediate`-operator non-guarantee.
- `docs/ROADMAP.md` — annotate M7's first slice (ledger + `builder`; modes + C&C
  deferred).
