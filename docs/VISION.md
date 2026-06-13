# Vision

## The core insight

Every technological era creates a new attack surface, and therefore requires a
new defensive layer.

- Swords created the need for **shields**.
- Networks created the need for **firewalls**.
- Autonomous agents create the need for the **Agent Wall**.

As autonomous AI agents begin to communicate, use tools, access company data,
write code, make decisions, and run business processes, companies need a new
kind of defensive boundary. The goal is not another small security tool or a
portfolio project — it is a complete security layer for the agentic era: an
independent layer that protects a company's agents, tools, code, data, and
infrastructure from malicious, compromised, or simply unsafe autonomous agents.

The central promise:

> **Let companies use autonomous agents without giving up control.**

"Olive" is the product name; **Shield Wall** is the platform/architecture name.
The naming carries the resilience idea below — a system that recovers, learns,
and returns stronger.

## The problem

Enterprises are moving from "an AI chatbot" to **fleets of agents** that read
files, query databases, send emails, write code, and call each other. Every
tool an agent can touch is attack surface, and the most dangerous direction is
the one almost everyone ignores: **content flowing back from tools into the
agent**. A poisoned document, a manipulated API response, or a malicious tool
description can silently re-program a legitimate, fully-authorized agent
mid-session. Perimeter security, SAST, and human code review do not see this
traffic at all.

The security question is no longer just:

> Is this network request technically valid?

It is:

> *Who* is this agent, *who* authorized it, *what* is it trying to accomplish,
> *what* may it access, and does its behavior *match its role*?

## What the product protects against

The danger is not limited to obviously malicious external agents:

- External agents attempting to manipulate company agents
- Legitimate agents compromised by prompt injection
- Internal agents operating outside their assigned roles
- Agents attempting to gain additional permissions
- Agents extracting sensitive company information
- One agent manipulating or impersonating another
- Malicious content hidden inside files, websites, or API responses
- Compromised MCP servers or tools (including tool-description rug-pulls)
- Several individually harmless actions combining into one dangerous outcome
- Agents making serious mistakes without any malicious intent

## Where the Agent Wall lives

An independent layer between agents and protected company systems — and between
agents themselves:

```text
External agents, users and services
                 │
                 ▼
          THE AGENT WALL
   Identity • Policy • Inspection
 Monitoring • Isolation • Response
                 │
                 ▼
Company agents, tools, APIs, code and data
```

```text
Support Agent ──► Agent Wall ──► Customer Database
Coding Agent ───► Agent Wall ──► Git Repository
Finance Agent ──► Agent Wall ──► Financial Systems
External Agent ─► Agent Wall ──► Internal Agent
```

Every important agent action passes through this layer, which can rule the
action: **allowed · allowed-but-monitored · sanitized · held for inspection ·
sent for human approval · blocked · quarantined · reproduced later in a safe
environment.**

## Why a firewall is not enough

A traditional firewall examines address, port, protocol, and known traffic
patterns. The Agent Wall must answer semantic questions a firewall cannot:
which agent, verifiable identity, owning org/user, assigned role, current goal,
permitted tools and data, delegation source, consistency with declared purpose,
behavioral drift within a session, manipulation of other agents, influence from
untrusted content, and dangerous *combinations* of individually-allowed actions.

A malicious instruction can travel through perfectly valid HTTPS. The network
connection looks safe while the *meaning* of the interaction is dangerous. That
semantic layer is where the Agent Wall differs from an ordinary firewall.

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

Olive is built so that when the market realizes it needs live protection
against agents, the solution already exists and speaks the native protocol.

## The company of agents behind the wall

The complete system is not one large security agent. It is coordinated
**departments** of specialized agents, each with its own responsibilities and
supervisors, communicating through structured incident objects and events —
never through uncontrolled group chat.

**The architectural law that governs all of them:**

> **Agents provide intelligence. Deterministic systems enforce authority.**

An LLM may *conclude* "this behavior appears suspicious." Only the deterministic
enforcement system *decides* "this identity may not access payroll, ever." (See
the non-negotiable rules in `CLAUDE.md` and ADR-0005.)

### 1. Defensive department (always on)
Monitors interactions; verifies identity; inspects tool requests and responses;
detects injection, privilege escalation, abnormal behavior, and data
extraction; watches agent-to-agent traffic; restricts/quarantines suspicious
sessions; builds an incident timeline; escalates serious cases to humans.
Specialist sentinels: **Identity, Behavior, Prompt-Injection, Data-Leak,
Tool-Usage, Agent-Communication.** They produce evidence; deterministic systems
still enforce the hard boundaries.

### 2. Red-team / attack-simulation department
Authorized simulations against the company's *own* protected environment — never
unrelated systems, never retaliation. Runs after important PRs, deployments, new
agent connections, permission changes, on schedule, and after every incident or
fix. Tests impersonation, injection, exfiltration, privilege misuse, persistent
malicious memory, tool-description poisoning, unsafe action chains, wall bypass,
and whether a fix genuinely stops the original attack. **Every successful bypass
becomes a permanent eval case** so the weakness cannot silently return.

### 3. Builder / remediation department
Responds to confirmed weaknesses: proposes policy changes, fixes code, tightens
validation, reduces unnecessary permissions, adds regression tests, rotates
exposed credentials when appropriate, opens PRs, and re-tests the original
attack. **Never makes unrestricted changes directly in production** — this is
what stops an attacker from manipulating the security system into harming its
own company.

### 4. Verification department
Independently confirms a fix actually works: repeats the original attack, runs
the full corpus, checks regressions, measures false positives and latency,
confirms legitimate behavior still works, and rejects fixes that block normal
activity. A fix is complete only when *independent tests* prove it — not because
a Builder agent says so.

### 5. Command & coordination
Supervised, hierarchical, event-driven — not a free-for-all:

```text
                 Security Commander
                         │
       ┌─────────────────┼──────────────────┐
       ▼                 ▼                  ▼
Defense Supervisor  Red-Team Supervisor  Builder Supervisor
       │                 │                  │
  Specialists        Attack Agents       Fix Agents
                                            │
                                            ▼
                                       Verification
```

Departments communicate through structured, auditable incident objects:

```json
{
  "incident_id": "INC-2041",
  "source_agent": "external-vendor-agent",
  "target": "internal-support-agent",
  "risk": "possible privilege escalation",
  "confidence": 0.91,
  "evidence": ["unexpected request for customer database access"],
  "requested_action": "quarantine",
  "affected_assets": ["customer-database"]
}
```

## Operating modes — cooperation during an attack

- **Normal mode** — standard monitoring, normal permissions, scheduled
  simulations, minimal overhead.
- **Suspicious mode** — extra defensive agents activated, permissions
  temporarily reduced, more actions require approval, history re-analyzed,
  sensitive tools watched closely.
- **Siege mode** — suspicious sessions quarantined, sensitive tools disabled,
  tokens/credentials frozen when necessary, red team reproduces the attack in a
  sandbox, builders prepare emergency fixes, verifiers re-run the corpus, humans
  get a complete incident report.

The shield-wall metaphor: in calm periods each defender watches its own area;
under attack the whole system forms one coordinated defensive structure.

## The full security cycle

```text
Govern → Detect → Contain → Reproduce → Repair → Verify → Learn & strengthen
```

The deeper philosophy is not only defense but **adaptive resilience**: the
company should not merely survive an attack — it should understand it, repair
the weakness, and become harder to attack next time.

## Competitive landscape — honest version

The space is real and already moving:

- **Acquired runtime-AI-security players**: Lakera → Check Point,
  Prompt Security → SentinelOne, Protect AI → Palo Alto,
  Robust Intelligence → Cisco. The market is validated; incumbents bought in.
- **Open-source MCP gateways exist** (multiple proxies/guardrail projects).
  A generic pattern-matching proxy is a *feature*, not a company.

## Differentiation — where Olive wins

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
   competitors leave open — and it is the seed of the department company above.

## Ideal customer profile

Start narrow. The first clear problem to own:

> Protect coding and enterprise agents that connect through MCP to sensitive
> company tools and untrusted external content.

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
(`src/olive/`) must never depend on the intelligence/fleet layers. The split
line — open gateway core vs. commercial intelligence, fleet management, incident
workflow, compliance reporting — must always be a clean cut.

The local gateway may become the **adoption layer**; the organization-wide
management, intelligence, and control plane may become the **commercial
product**.

## Naming and the deeper meaning

The final *company* name is not yet decided. "Agent Wall" and "Shield Wall"
describe the product well but may be too generic as a company name. The deeper
direction is resilience: recovery, rebuilding, returning stronger after damage,
learning from every attack.

> Security should not only prevent damage. It should help the system recover,
> learn, and return stronger.

**Olive** fits this precisely: olive trees regrow from the roots after being cut
down or burned, live for millennia, and the olive branch signifies protection
and peace. Shield Wall can remain the platform/architecture name while the
resilience idea guides the eventual company name.

## One-sentence thesis, promise, mission

- **Thesis:** Every technological era creates a new attack surface and requires
  a new defensive layer. Networks created firewalls. Autonomous agents create
  the Agent Wall.
- **Promise:** Secure every agent action without preventing useful autonomy.
- **Mission:** Build the trusted security layer that lets companies adopt
  autonomous agents safely, recover intelligently from attacks, and become
  stronger after every incident.
