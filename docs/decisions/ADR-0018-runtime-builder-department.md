# ADR-0018: The runtime Builder department — autonomous fix-proposals, never reach

**Status:** accepted (2026-06-16)

## Context

VISION department 3 (Builder / remediation) "responds to confirmed weaknesses:
proposes policy changes, fixes code, tightens validation, adds regression tests …
opens PRs, and re-tests the original attack" — but "never makes unrestricted
changes directly in production." ADR-0013 built the remediation *loop* (the
ledger + the build-time `builder` agent + the human-gated `olive cycle`) and
explicitly deferred runtime Builder *autonomy*. ADR-0016 added a runtime
Red-Team department that publishes `redteam-finding` objects onto the bus. Today
nothing connects those confirmed weaknesses to a proposed fix without a human
starting from scratch.

This ADR delivers the smallest real slice of runtime Builder autonomy: a runtime
**department** that reacts to confirmed weaknesses by producing an inert,
bounded *fix-proposal artifact* and publishing awareness of it — and stops
there. It adds propose-reach, never enforcement-reach.

The supervisor tier of VISION §5 (Command & Coordination: Commander → department
*supervisors* → specialists) remains **deferred**: with four flat departments the
deterministic Commander (ADR-0014) is already the coordination point, and a
supervisor layer over departments that have no specialists beneath them is
speculative generality. It lands when there are specialists to supervise.

The non-negotiable, per VISION dept 3, CLAUDE.md rule 2, and ADR-0005/0013: the
Builder NEVER applies to prod, NEVER self-approves, and a human gate is mandatory
before any fix ships. This ADR makes that structural, not a guideline.

> **ADR numbering:** `ADR-0017` is the accepted Agentic Command Center UI ADR.
> The runtime Builder department is therefore **ADR-0018**.

## Decision

### 1. A runtime Builder department, propose-only

A new `intelligence/builder_dept.py` (intelligence side). It subscribes to the
bus for **confirmed weaknesses with a concrete handle to fix** —
`redteam-finding` (ADR-0016, a confirmed sandbox bypass) and `reproduced`
(ADR-0013/0014, an incident reproduced as a committed corpus case). Per novel
weakness it produces a **fix-proposal artifact**: a bounded, structured intent
recording *what* should be fixed and a pointer to the triggering object. Its only
outputs are (a) a `builder_proposals` row and (b) a `fix-proposed` bus object
(the kind already exists, ADR-0014 §4). It does nothing else.

> **Scoping note (deviation from the design draft, recorded for audit):** the
> draft also named bare `detection` objects as a trigger. A bare `detection` has
> no committed corpus case yet (runtime auto-reproduction is deferred, ADR-0014),
> so a fix-proposal for it would be vague and un-actionable. Bare detections
> continue to flow to the Remediation department as *intents* (existing
> behaviour); they become Builder-actionable once a human/red-team reproduces
> them into a `reproduced`/corpus-backed object. The Builder triggers only on the
> two confirmed-weakness kinds above.

### 2. No enforcement-write path (ADR-0005/0013/0015/0016 carried over)

The department MUST NOT import `gateway.breaker`, `gateway.proxy`,
`gateway.upstreams`, or `mcp.ClientSession`, and MUST NOT call `breaker.trip`,
`breaker.set_mode`, `olive cycle`, or `--update-baseline`. It never writes to
`src/`, `policies/`, `evals/corpus/`, the decode layer, a baseline, or the
remediation ledger's consequential transitions. A test asserts the import set
(mirroring ADR-0016 §1) and that no proposal path reaches an enforcement call.
The only new line crossed vs. the build-time `builder` agent is *autonomy*
(unattended reaction to a finding), never *reach*.

### 3. The LLM-creative author stays build-time; proposals are inert data

The actual diff text remains authored by the build-time `.claude/agents/builder.md`
(ADR-0013 §2). The runtime department is pure deterministic orchestration: detect
a confirmed weakness, record a bounded proposal artifact derived only from the
already-bounded incident fields, and publish awareness. It NEVER interpolates LLM
output into an enforcement artifact (ADR-0005), and at runtime it authors **no
diff** — `patch_hash` is null on a runtime proposal. A proposal is inert until a
human walks the fix through `olive cycle`.

### 4. `builder_proposals` ledger — rule-3 safe

A new `builder_proposals` table, intelligence side, own `aiosqlite` on the same
DB file (the RemediationLedger / bus precedent, ADR-0013 §7). Fields are hashes +
bounded text + non-secret id refs only — never a diff body, never a raw payload:

    proposal_id     TEXT PK    -- 'PRP-NNNN', single-statement-derived
    object_id       TEXT       -- the triggering bus object id (string ref)
    incident_id     TEXT       -- the originating incident, if any (string ref)
    corpus_case_id  TEXT       -- the reproduced case, if any (string ref)
    finding_key     TEXT UNIQUE-- the dedup key (see §6); one proposal per weakness
    patch_hash      TEXT       -- null at runtime; the diff is authored build-time
    summary         TEXT       -- bounded <=200 chars, human-readable one-liner
    status          TEXT       -- 'proposed' (terminal here; promotion is olive cycle)
    created_at      TEXT

### 5. Human-gated promotion is unchanged (ADR-0013)

A proposal becomes a shipped fix ONLY through the existing `olive cycle` path: a
human commits the patch + promotes the corpus case (gate 1), then `verify` (the
deterministic eval gate, never an LLM) and `approve`→`learn` (a verified
`olive:remediate` token, gate 2). The Builder department feeds that pipeline; it
is not a participant in it. No LLM reaches `verified`, `approved`, or `learned`.

### 6. No self-trigger feedback loop; spam-bounded by novelty (ADR-0016 §7)

The department PUBLISHES `fix-proposed` but its own proposal MUST NOT trigger a
red-team campaign, another Builder run, or a mode change. It subscribes only to
`redteam-finding` and `reproduced` — never to `fix-proposed` — so a proposal can
never re-enter the department. `fix-proposed` is inert to escalation: it carries
`confidence=0.0`, and the Commander reads only `kind="detection"` (ADR-0016 §4,
unchanged), so a proposal cannot move the operating mode.

Frequency is bounded by **novelty dedup**: `finding_key` is `UNIQUE`, so a
weakness already proposed for yields no second proposal and no second bus object.
A steady state with no new confirmed weaknesses produces zero proposals. The
on-demand replay path (`run_once`) is **single-flight** (a re-entrant call is
skipped) and idempotent (dedup makes a re-run a no-op).

> **Anti-DoS note (deviation from the design draft, recorded for audit):** the
> draft named a "min-interval" floor by analogy to the ADR-0016 red-team
> *scheduler*. This department is **event-driven**, not scheduled — it has no
> timer to clamp. The honest spam bound for a reactive consumer is the novelty
> dedup (one proposal per distinct weakness) plus single-flight on the on-demand
> replay; there is no periodic campaign to rate-limit. A future event-rate
> throttle can be added if a pathological burst of *distinct* weaknesses is ever
> observed, but it is not part of this slice.

### 7. Bus auth: the existing per-process HMAC key, with a recorded boundary

The department signs/verifies `fix-proposed` objects with the existing
per-process HMAC bus key (ADR-0014 §4). This does NOT raise the bus's privilege:
no bus object this slice introduces crosses an enforcement seam without
independent re-verification (the eval gate and the `olive:remediate` token both
re-verify, off the bus). Per-department CA-signed bus identities (ADR-0014 §4's
named target) therefore remain a **parallel, non-gating** upgrade, recommended as
a separate ADR. **Boundary recorded for the future:** the moment any slice lets a
bus object directly drive an enforcement action without independent
re-verification, CA-signed bus identities become a hard prerequisite for it.

### 8. Open-core seam & wiring (ADR-0003)

`intelligence/builder_dept.py` imports core one-directionally (only the bus,
reporter, and `aiosqlite`); CORE NEVER IMPORTS IT. No new inward seam crossing —
the two crossings remain exactly `trip` and `set_mode`. Wired as an OPTIONAL
fourth department in `build_runtime_org` (off unless an opened `ProposalLedger`
is supplied), additive and removable: the gateway enforces identically with the
department absent. `olive builder-dept run` is the on-demand operator/CI trigger
(replays the bus history and proposes for any novel confirmed weakness).

## Scope — IN / OUT

**IN:** `intelligence/builder_dept.py` (`ProposalLedger` + `BuilderDepartment`:
subscribe to confirmed weaknesses, emit a bounded proposal, publish
`fix-proposed`); the `builder_proposals` table (rule-3 safe); novelty dedup +
single-flight on the replay path; optional `build_runtime_org` wiring +
`RuntimeOrg.builder`; an `olive builder-dept run` on-demand trigger; tests
(import-set exclusions; proposal never reaches `trip`/`set_mode`/`olive cycle`/
baseline; `fix-proposed` never moves the mode; proposal never re-triggers; dedup;
rule-3 ledger shape).

**OUT (deferred / forbidden):** the supervisor tier (Commander → supervisors →
specialists — deferred until specialists exist); any auto-apply / auto-open of an
`olive cycle` from a proposal (PERMANENTLY forbidden — ADR-0013 human gates);
credential rotation (touches live secrets, deferred as in ADR-0013); the
department calling `trip`/`set_mode`/`olive cycle`/baseline update (forbidden);
runtime LLM-creative diff generation outside the build-time agent (forbidden,
ADR-0005); per-department CA-signed bus identities (parallel, separate ADR);
durable/fleet proposals across restarts (same non-guarantee as mode/bus).

## Consequences

- VISION department 3 becomes real at runtime: a confirmed weakness is
  automatically turned into a bounded, auditable fix-proposal that feeds the
  existing human-gated loop — closing the gap between ADR-0016 findings and
  ADR-0013 remediation, without granting any LLM new authority.
- ADR-0005/0013/0015/0016 extended, not bent: deterministic department,
  propose-only, no enforcement-write path, human gates intact, one writer each
  for `trip`/`set_mode`, no self-trigger edge.
- ADR-0003 intact: core never imports the department; additive and removable; no
  new inward crossing.
- Residual risk (THREAT_MODEL): a bad autonomous proposal is inert until a human
  drives the eval gate + `olive:remediate` approval (the same insider class as
  ADR-0013); proposal-spam is bounded by novelty dedup + single-flight; the
  per-process bus-key reduction is inherited, not increased.

## Supersession note

ADR-0013/0014/0016 deferred "runtime Builder autonomy" and "the supervisor tier."
This ADR delivers the propose-only runtime Builder slice of the former; the
supervisor tier and any auto-apply remain future work.
