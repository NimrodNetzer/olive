# ADR-0015: The autonomous red-team engine — deterministic attack generation, offline first

**Status:** accepted (2026-06-15)

## Context
VISION's Red-Team department (#2) and "the full security cycle" require Olive to
attack its *own* gateway, surface bypasses, and feed them into the loop so it gets
harder to attack every round. ADR-0013 built the downstream half of that loop —
Reproduce (corpus), Repair (the `builder` agent), Verify (the eval gate),
Approve (`olive cycle`'s human gate), Learn (baseline promotion). What was missing
is the **engine that generates and runs attacks** and discovers new bypasses.

ADR-0013 and ADR-0014 deferred runtime Red-Team **autonomy**. This ADR delivers
the **offline, deterministic** engine only — operator-invoked tooling in the same
category as `evals/run_evals.py`. A scheduled / bus-driven runtime red-team
department remains deferred (gated on the supervisor tier).

## Decision

### 1. A deterministic attack-generation engine, offline CLI
`olive redteam run` (engine in `src/olive/redteam/`) applies reusable, pure
`AttackStrategy` mutators to seed malicious intents and runs every variant through
the **real pipeline** — `olive.cli.build_pipeline`, the exact path the gateway and
`run_evals.py` use, never a mock. A variant the pipeline *allows* (when it should
block) is a bypass. Deterministic and reproducible: same seeds + strategies →
same variants → same findings.

The first slice ships exactly the mutators that map to existing `known-miss`
corpus cases (base32→inj-0018, double-base64→inj-0020, chunked-base64→inj-0021,
capital-homoglyph→inj-0024), so every finding is checkable against committed
ground truth. Those four cases were backfilled with a `redteam_key` so the engine
correctly reports them as *already filed* rather than novel.

### 2. The deterministic / LLM line (extends ADR-0005 to attack generation)
Deterministic mutators may run **unattended** (CI/offline) and auto-*emit*
candidates. **LLM-creative / semantic attack generation stays the human-supervised
build-time `.claude/agents/red-team.md` agent** and may never write the corpus or
feed the CI gate. An LLM that generates attacks is still an LLM in a
security-critical pipeline; an attacker who poisoned its context could starve
coverage or flood noise. So: the engine in CI is pure deterministic code; the
creative red team stays advisory and human-curated.

### 3. The engine has no enforcement-write path (the anti-cheat guarantee)
The engine's only outputs are (a) a campaign report and (b) `known-miss` candidate
case dicts. It **never** writes a policy, a pattern, `inspectors/decode.py`, an
`active` corpus case, or `evals/baseline.json`. It has read-only authority over
detection: it imports the pipeline and *runs* it. Therefore "make Olive look
stronger by weakening detection" is structurally impossible from the engine — it
has no write path to any enforcement artifact. Reinforcing guarantees:

- **Real pipeline, proven live.** Before trusting any bypass, the engine runs each
  seed's *plain* trigger and requires it to be **blocked**; if plaintext slips
  through, it refuses to run (`RedTeamError`). A mock that "finds bypasses
  everywhere" cannot masquerade as the gateway.
- **A bypass is defined against the real verdict** (`Verdict.allowed`), the same
  field the eval runner uses — no separate judgement.
- **Separation of duties** (unchanged): the engine *finds*, the builder *proposes*,
  the deterministic gate *verifies*, the human *approves*. No single actor closes
  the loop.

### 4. Two human gates, unchanged
The engine produces backlog, not decisions:

```
olive redteam run        (deterministic, unattended, NO authority)
  → known-miss candidates (stdout / a quarantine dir; NEVER evals/corpus)
        [HUMAN GATE 1: review + commit a candidate as known-miss]
  → known-miss in corpus  (honest backlog; the ADR-0011 gate is NOT tripped)
  → builder proposes the fix the note names (diff, never applied)
  → olive cycle propose → verify (real gate) →
        [HUMAN GATE 2: olive cycle approve, olive:remediate token]
  → olive cycle learn → --update-baseline  (the only promotion to active)
```

The engine may only ever emit `status: known-miss` (never `active`, never a
baseline edit) and never calls `olive cycle`. The CLI refuses to `--emit` into
`evals/corpus`. Both promotions stay the existing human-gated acts (ADR-0013 §6,
ADR-0011 `--update-baseline`).

### 5. Iterative improvement is measured on existing artifacts
"Olive got stronger this round" is not a new metric: it is the existing
**baseline `detected` rose** *and* the engine's bypass count for a fixed
seed/strategy set *fell*. The campaign report prints `bypasses / variants /
novel / already-filed` so the leading indicator is visible, but the
`evals/baseline.json` count remains the single source of truth for "stronger" —
the engine never self-credits.

### 6. Placement & open-core seam (ADR-0003)
The engine lives in `src/olive/redteam/`, an intelligence-side sibling. It imports
core one-directionally (`olive.cli.build_pipeline`, `olive.config`,
`olive.gateway.context`) — allowed, exactly like `run_evals.py`. **Core never
imports it.** Wired in `cli.py` (`olive redteam`) via a local-import handler, like
`olive cycle`. Additive and removable: the gateway enforces with the engine absent.

### 7. Authorized-testing-only (VISION)
The engine targets **only** Olive's own `build_pipeline` in local/CI context. It
has no network egress, no external target, and no retaliation path — it mutates our
own trigger phrases against our own pipeline. This mirrors the constraint in
`.claude/agents/red-team.md`.

## Scope — IN / OUT

**IN:** `src/olive/redteam/` (the `AttackStrategy` abstraction, four seed-mapped
mutators, seed intents, the campaign runner over the real pipeline); bypass
detection via `Verdict.allowed`; dedup by `(intent, strategy)` `redteam_key`
against the committed corpus; the campaign report; emission of `known-miss`
candidate YAML to stdout or a quarantine dir (never the live corpus); the
`olive redteam` CLI; tests (pipeline-live anti-cheat, seeded bypass found,
candidate-is-always-known-miss).

**OUT (deferred / forbidden):** runtime / scheduled / bus-driven red-team
**autonomy** (deferred, gated on the supervisor tier); the engine writing the
corpus, `active` cases, or `baseline.json` (**permanently forbidden** — the
anti-cheat guarantee, not a deferral); LLM-creative attack generation in CI (stays
the human-supervised build-time agent); strategies beyond the seed-mapped set; any
engine→ledger automation (`olive cycle` stays human-driven).

## Consequences
- The self-improvement engine is real and reproducible; the iterative story is
  demonstrable end-to-end against the committed known-miss cases (the engine
  rediscovers the four filed gaps and finds new ones, e.g. the `system-override`
  encoded variants).
- ADR-0005 extended, not bent: no LLM in the CI attack path; the engine has
  read-only authority over detection.
- ADR-0011 intact: only `known-miss` is emitted; both promotions stay human-gated;
  the gate stays the regression authority.
- ADR-0003 intact: core never imports the engine.
- Residual risk (THREAT_MODEL): a malicious operator could commit a poisoned
  candidate, but it lands as inert `known-miss` and a fix still requires the gate +
  an `olive:remediate` approval — the same insider class ADR-0013 documents.

## Supersession note
ADR-0013/0014 deferred "runtime Red-Team autonomy." This ADR delivers the
**offline** half of that; runtime/scheduled autonomy remains future work.

## Required doc updates
- `docs/ARCHITECTURE.md` — new "Red-team engine" component + note core does not
  import it.
- `docs/ROADMAP.md` — M7: offline red-team engine delivered; runtime autonomy
  still deferred.
- `docs/EVALS.md` — red-team output is auto-*generated* but human-committed as
  `known-miss` (the `redteam_key` marker).
- `docs/THREAT_MODEL.md` — the engine has no enforcement-write path; the
  poisoned-candidate non-guarantee (same class as malicious-operator).
