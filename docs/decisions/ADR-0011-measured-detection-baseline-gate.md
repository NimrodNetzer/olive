# ADR-0011: Measured detection — metrics + a committed baseline regression gate

**Status:** accepted (2026-06-14)

## Context
EVALS.md commits Olive to a hard rule: *detection rate may never silently
drop*, and the eval runner is the CI regression gate. Through M4 the runner
(`evals/run_evals.py`) reported a per-category table and exited non-zero when an
`active` case stopped matching its `expected` verdict. That catches one
regression mode — an active case flipping — but **not** the quietest one:

- An `active` malicious case is **reclassified to `known-miss`** (or deleted).
  Detection silently drops, the run stays green, and nobody notices. "Known
  misses are honest" (EVALS.md rule 2) only holds if you cannot *grow* the
  known-miss set to dodge the gate.
- A change raises the **false-positive** count on benign hard negatives. The
  per-case expectations still match (the runner had no benign regression notion
  beyond an `allow` case flipping), but the *aggregate* posture degrades.

M5 ("the moat") is where measurement becomes the product, so the gate must
defend the **aggregate numbers**, not just per-case expectations. It also must
report the metrics EVALS.md promised but the runner did not yet emit: added
latency p50/p95 per direction.

## Decision
A **committed baseline** (`evals/baseline.json`) is the source of truth for the
floor the corpus must clear. The runner compares the live run against it and
fails closed on any backslide.

- `baseline.json` records, as integer counts (not percentages — percentages
  drift as the corpus grows and hide absolute loss):
  - `detected` / `malicious_total` — active malicious cases caught.
  - `false_positives` / `benign_total` — benign cases wrongly blocked.
  - `per_category` — detected/total per attack category.
- **Gate (exit 1) on any of:**
  1. a per-case regression (an `active` case not matching `expected`) — the M4
     behaviour, retained;
  2. `detected` **below** baseline — detection dropped, *however* it dropped
     (flip, reclassification to `known-miss`, or deletion). The baseline pins
     the absolute number of catches, so shrinking the active malicious set
     fails the gate just like a flip does;
  3. `false_positives` **above** baseline — benign hard negatives started
     tripping.
- The baseline only moves by an explicit, reviewable act: `python
  evals/run_evals.py --update-baseline` rewrites the file. Raising the floor (or
  consciously accepting a drop) is therefore a **diff in version control** that a
  human reviews — never a side effect of editing the corpus.
- **Latency** p50/p95 is measured per direction over the real pipeline runs and
  printed alongside detection/FP. It is *reported, not gated* — wall-clock on CI
  is too noisy to fail a build on, and a latency regression is a performance bug,
  not a silent detection loss. (A gate can be added later against a fixed
  budget if we pin a runner.)

## Why counts, not a percentage threshold
A "≥ 80% detection" style gate *rises* as you add catchable cases and *falls* as
you add hard known-misses, so honest corpus growth (rule 1: every mechanism
ships cases; rule 2: every bypass becomes a `known-miss` case) would fight the
gate. Pinning absolute `detected` lets the known-miss backlog grow freely — the
honest-backlog behaviour EVALS.md wants — while still catching any real loss of
a catch we already had.

## Consequences
- Adding a `known-miss` bypass case (red-team output) never trips the gate: it
  raises neither `detected` nor `false_positives`. Honest backlog stays cheap.
- Promoting a `known-miss` to `active` (a real detection win) requires
  `--update-baseline` to raise the floor, locking the win in against future
  regression. The runner already prints a `NOTE … promote to active` hint.
- The corpus stays single-payload and content-based; stateful detections
  (rug-pull, ADR-0009) remain verified by tests, not the corpus. M5 corpus
  rug-pull cases therefore exercise the *content* surface of a swapped
  declaration (does the new description trip inspection?), not the cross-session
  change signal.
- CI (`.github/workflows/ci.yml`) runs the unit/integration suite **and** the
  eval gate on every push; a silent detection drop now fails the build.
