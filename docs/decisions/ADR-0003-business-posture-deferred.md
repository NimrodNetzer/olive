# ADR-0003: Business posture deferred, split kept structural

**Status:** accepted (2026-06-12) — revisit after first external demos

## Context
Open-core (open gateway, commercial intelligence/fleet layer) is the proven
wedge in this market and the strongest credibility signal for a student-stage
founder; closed/stealth protects ideas longer. Not enough information to
choose yet.

## Decision
Defer the open vs. closed decision. Enforce one structural rule now so both
options stay viable: **the gateway core (`src/shieldwall/`) never imports
from intelligence/fleet layers.** Telemetry leaves through a queue;
quarantine signals return through the circuit breaker's narrow interface.
That seam is the potential open-core boundary.

## Revisit criteria
- Which channel produces traction: developer adoption vs. top-down sales.
- Whether open detection numbers (EVALS.md) are needed for credibility.
- Competitor moves in the open-source MCP gateway space.

## Consequences
- Slight discipline cost on every PR (layering check).
- No rewrite needed whichever way the decision goes.
