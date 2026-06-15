"""Operating mode - the fleet-wide enforcement posture (ADR-0014).

Pure core data, no intelligence imports (ADR-0003), the same posture as
`session.py`. The deterministic Security Commander (intelligence side) decides
the mode from the incident stream and delivers it through the circuit breaker's
narrow `set_mode` method - the second inward seam crossing, the same shape as
`trip`. Inline enforcement only ever *reads* this value; it never imports the
orchestration layer.

The mode tunes deterministic inline behavior the core already owns:

  - normal     - standard inspection, minimal holds.
  - suspicious - tighter containment threshold, more calls held, sentinels
                 watched more closely.
  - siege      - sensitive tools denied inline, new sessions held by default.

Mode shapes *how much* deterministic enforcement runs; it never lets an LLM
decide an action (ADR-0005).
"""

from __future__ import annotations

from enum import StrEnum


class OperatingMode(StrEnum):
    NORMAL = "normal"
    SUSPICIOUS = "suspicious"
    SIEGE = "siege"
