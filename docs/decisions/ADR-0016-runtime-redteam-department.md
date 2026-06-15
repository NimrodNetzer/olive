# ADR-0016: The runtime Red-Team department — scheduled sandbox attacks, advisory findings

**Status:** accepted (2026-06-15)

## Context
VISION department 2 (Red-Team / attack-simulation) runs authorized simulations
against Olive's *own* environment "after important PRs, deployments, new agent
connections, permission changes, on schedule, and after every incident." ADR-0015
delivered the **offline, deterministic** engine (`olive redteam`) and explicitly
deferred *runtime/scheduled* autonomy; ADR-0013 and ADR-0014 deferred it too. This
ADR delivers the first real slice of that autonomy: a runtime **department** that,
on a trigger, runs the existing engine and publishes its bypass findings onto the
incident bus so they flow into the loop (Remediation records them; the org is
aware) — moving Olive toward the self-defending organization the VISION describes.

The whole risk in a *runtime* red-team is a single property: it must NEVER inject
attack payloads into real agent sessions or send them to real upstream tools/data.
A security system that attacks live traffic causes the harm it exists to prevent.
This ADR makes "sandbox only" a structural guarantee, not a promise.

## Decision

### 1. Sandbox-only, by construction (the safety guarantee)
The department's ONLY attack primitive is `redteam.engine.run_campaign`
(ADR-0015), reused unchanged. That function targets a fresh isolated pipeline
built from policy files (`build_pipeline(load_config(...))`) and runs our own
obfuscated seed triggers through it. It cannot receive or reach a `Proxy`, a
`ClientSession`, an upstream, or the live `CircuitBreaker` — there is no parameter
or import through which live traffic could enter.

Structural rule: the department module (`intelligence/redteam_dept.py`) MUST NOT
import `gateway.proxy`, `gateway.upstreams`, `mcp.ClientSession`, or the live
breaker, and MUST NOT receive any of them. It builds its own sandbox pipeline. A
test asserts the module's import set excludes those symbols. The department adds
scheduling + a bus publish — ZERO new attack capability over the offline engine.
The only new line crossed vs. ADR-0015 is *autonomy* (unattended trigger), never
*reach* (still only `build_pipeline`).

### 2. ADR-0015 anti-cheat carries over; no enforcement-write path
The department inherits the engine's guarantees: the pipeline is proven live
(plain trigger must block, else `RedTeamError`), and there is NO write path to any
enforcement artifact (policy, pattern, decode layer, `active` case, baseline,
ledger). Its only output is advisory: `redteam-finding` bus objects + (human-
reviewed) known-miss candidates. It can never weaken detection to fake a win.

### 3. Advisory-only; never enforces (ADR-0005)
The department is deterministic and publishes evidence only. It MUST NOT call
`breaker.trip` or `breaker.set_mode` (those remain the SentinelRunner's and the
Commander's sole authorities — one writer each, ADR-0014). It MUST NOT call
`olive cycle`. Publishing a finding is advisory; humans gate every promotion.

### 4. Findings are a distinct bus kind — a drill never escalates the mode
A finding is published as a new `IncidentObject` kind `"redteam-finding"`
(`source_dept="redteam"`), NOT `"detection"`. This is structural, not cosmetic:
the Commander escalates the operating mode from `kind="detection"` objects
(`commander._on_detection` → `target_mode`); a scheduled drill publishing
`"detection"` would force the fleet into Siege — a self-inflicted DoS. With a
distinct kind, the Commander never receives a finding for escalation, so a drill
CANNOT move the operating mode by construction. The Commander is left unchanged
in this slice (awareness is available via the `incident_events` audit table).

The envelope reuses `IncidentObject`, which structurally has no `content`/
`arguments` field, so rule 3 holds: a finding carries only `bypass.key` + a
bounded ≤200-char note (`attack_types=[category]`, `action="redteam-finding"`),
never the obfuscated payload, never a raw secret. `incident_id`/`corpus_case_id`
are None (a drill mints no store incident).

### 5. Remediation records a finding as an intent — human gates unchanged (ADR-0013)
`RemediationDepartment` also subscribes to `"redteam-finding"` and records it as a
remediation *intent awaiting reproduction* — it does NOT auto-open a ledger cycle
(a finding has no committed `corpus_case_id`). A finding becomes a committed
known-miss only by a human (gate 1); any fix/baseline change stays the human-gated
`olive cycle` path (gate 2). The runtime dept surfaces findings; humans promote.

### 6. Triggers — first slice IN / OUT
IN: (a) on-demand `run_once()` (the surface CI/CLI calls), and (b) a periodic
scheduler mirroring `SentinelRunner.start/stop` (`asyncio.create_task` loop,
cancel-on-stop). "After deploys/PRs" are EXTERNAL triggers: the in-process
component is only a trigger surface (`olive redteam-dept run`); the CI plumbing is
deferred. OUT: event-triggered "after every incident" (subscribe-and-rerun) is
deferred to a second slice — it is the only path with a feedback-loop / self-DoS
footgun, and must land only after the anti-DoS bounds prove out.

### 7. Anti-DoS / anti-feedback (structural)
- A finding cannot trigger a campaign: the department PUBLISHES but SUBSCRIBES to
  nothing; there is no path from a bus object back into `run_once()`.
- A drill never trips containment or moves the mode (§1, §3, §4).
- Frequency is bounded: a config min-interval floor + single-flight (no
  overlapping campaigns; skip a tick if one is in flight). Campaigns are finite
  and deterministic (`SEEDS × STRATEGIES`).
- Findings are deduped via `load_known_keys`; only `report.novel` is published, so
  a steady state with no new gaps produces zero bus traffic and no audit-row spam.

### 8. Composition & open-core seam (ADR-0003)
`intelligence/redteam_dept.py` lives on the intelligence side. It imports
`redteam.engine` (which imports core one-directionally, like `run_evals.py`) and
`intelligence.bus`; CORE NEVER IMPORTS IT. It is wired as an OPTIONAL third
department in `build_runtime_org` (default off: `redteam_interval=None`), so the
existing two-department wiring is unaffected and a deployment without red-team
scheduling pays nothing. No new inward seam crossing is added — the dept only
publishes; the two inward crossings remain `trip` and `set_mode`. Additive and
removable: the gateway enforces with the department entirely absent.

## Scope — IN / OUT
IN: `intelligence/redteam_dept.py` (wrap `run_campaign`, `run_once()`, scheduler);
the `"redteam-finding"` bus kind (rule-3 envelope, novel-only, deduped);
Remediation subscribing as an intent; optional `build_runtime_org` wiring +
`RuntimeOrg.start/stop`; an `olive redteam-dept run` CLI trigger; min-interval +
single-flight; tests (import-set excludes proxy/upstream/ClientSession; drill never
moves mode/trips; finding never re-triggers; rule-3 envelope).

OUT (deferred / forbidden): event-triggered autonomy (deferred); CI plumbing for
deploy/PR triggers (deferred); any auto-promotion of a finding to known-miss/
active/baseline/policy/decode (PERMANENTLY forbidden — ADR-0015 anti-cheat +
ADR-0013 gates); the dept calling `trip`/`set_mode`/`olive cycle` (forbidden);
new attack strategies or LLM-creative generation at runtime (stays the build-time
agent, ADR-0015 §2); durable/fleet scheduling across restarts (same non-guarantee
as mode/bus); the supervisor tier.

## Consequences
- VISION department 2 becomes real at runtime: scheduled simulations against
  Olive's own (sandboxed) detection, feeding findings into the loop — auditable
  via `incident_events`.
- The safety constraint is structural: the dept cannot reach live sessions/
  upstreams (it cannot import or be handed them), and a drill cannot escalate the
  mode or trip containment (distinct kind; no `trip`/`set_mode`).
- ADR-0005/0013/0014/0015 extended, not bent: deterministic; advisory-only; no
  enforcement-write path; human gates intact; one writer each for trip/set_mode.
- ADR-0003 intact: core never imports the dept; it is additive and removable.
- Residual risk (THREAT_MODEL): a misconfigured short interval is a self-DoS
  class, bounded by the min-interval floor + single-flight; the scheduler is
  in-memory/per-process (same non-guarantee as mode/bus).

## Supersession note
ADR-0013/0014/0015 deferred "runtime/scheduled Red-Team autonomy." This ADR
delivers the scheduled, sandbox-only slice of it; event-triggering, the supervisor
tier, and runtime Builder autonomy remain future work.

## Required doc updates
- `docs/ARCHITECTURE.md` — new "Runtime Red-Team department" component; correct the
  "does not exist yet" bullet (scheduled sandbox attacks now exist; the live
  gateway is still never attacked; event-trigger + supervisor tier deferred).
- `docs/ROADMAP.md` — M7: scheduled Red-Team department delivered; event-trigger +
  Builder autonomy + supervisors still deferred.
- `docs/THREAT_MODEL.md` — extend the ADR-0015 block: the runtime dept adds
  autonomy not reach (sandbox-only, no write path, findings cannot move mode/trip);
  the self-DoS bound + in-memory/per-process non-guarantee.
