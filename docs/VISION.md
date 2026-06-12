# Vision

## The problem

Enterprises are moving from "an AI chatbot" to **fleets of agents** that read
files, query databases, send emails, write code, and call each other. Every
tool an agent can touch is attack surface, and the most dangerous direction is
the one almost everyone ignores: **content flowing back from tools into the
agent**. A poisoned document, a manipulated API response, or a malicious tool
description can silently re-program a legitimate, fully-authorized agent
mid-session. Perimeter security, SAST, and human code review do not see this
traffic at all.

## The 2-year thesis

By 2027:

1. Agent-to-tool traffic (largely MCP) becomes a first-class enterprise
   protocol, like HTTP was in 2000 — and gets its own firewall category.
2. Indirect prompt injection via tool responses remains structurally unsolved
   at the model level; enterprises will be forced to buy **runtime** controls.
3. Agent identity ("which agent, on whose behalf, with what authority, right
   now") becomes the new IAM problem. Nobody owns it yet.
4. Compliance regimes (EU AI Act enforcement, SOC2-for-agents expectations)
   start demanding **auditable decision trails** for autonomous actions.

Shield Wall is built so that when the market realizes it needs live protection
against agents, the solution already exists and speaks the native protocol.

## Competitive landscape — honest version

The space is real and already moving:

- **Acquired runtime-AI-security players**: Lakera → Check Point,
  Prompt Security → SentinelOne, Protect AI → Palo Alto,
  Robust Intelligence → Cisco. The market is validated; incumbents bought in.
- **Open-source MCP gateways exist** (multiple proxies/guardrail projects).
  A generic pattern-matching proxy is a *feature*, not a company.

## Differentiation — where Shield Wall wins

1. **MCP-native, drop-in.** A transparent proxy: point any MCP client at it,
   zero changes to agent or tool server. Five minutes to protected.
2. **Measured detection, not claimed detection.** A maintained attack corpus
   and eval harness producing detection-rate and false-positive numbers. Every
   incident and every red-team bypass becomes a regression case. Security
   products without numbers are marketing; the corpus itself is a moat.
3. **Behavioral session intelligence.** Not just per-message scanning —
   sequence-level analysis of what an agent is *doing* across a session versus
   its declared role and goal.
4. **Agent identity.** Cryptographically bound identity per agent/session from
   day one, growing toward "SPIFFE for agents."
5. **The full loop.** Everyone detects and blocks. Almost nobody does
   **Reproduce → Repair → Verify**: turn an incident into a reproducible
   attack case, feed it to the corpus, verify the fix. That closes the loop
   competitors leave open.

## Ideal customer profile

- **First (design partners):** engineering teams deploying MCP-based internal
  agents who are uneasy about what their agents can be tricked into doing.
- **Later (buyers):** security teams responsible for an agent fleet who need
  policy, containment, incident workflow, and audit evidence.

## Business posture — deliberately deferred

Open-core vs. closed is **not decided yet** (see ADR-0003). Decision criteria,
to be revisited after the first external demos:

- Which channel produces traction: developer adoption (favors open-core) or
  top-down security sales (favors closed)?
- Founder credibility needs: an open repo with measured detection numbers is
  the strongest possible signal for a student-stage founder.
- Competitor moves in the open-source MCP gateway space.

**Structural rule that keeps both options alive:** the core gateway
(`src/shieldwall/`) must never depend on the intelligence/fleet layers. The
split line — open gateway core vs. commercial intelligence, fleet management,
incident workflow, compliance reporting — must always be a clean cut.
