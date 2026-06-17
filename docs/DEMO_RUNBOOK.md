# Olive — UNIC Demo Runbook

6-minute scripted talk track for the UNIC Venture Studio screening (June 23–24, 2026).

---

## Pre-demo checklist (10 min before)

```bash
# 1. Verify tests pass — if this fails, stop and fix first
python -m pytest -q

# 2. Verify eval gate — all active attacks caught, 0 FP
python evals/run_evals.py

# 3. Kill anything on port 7799
netstat -ano | findstr :7799   # Windows
# or: lsof -i :7799            # Mac/Linux

# 4. Have the browser ready at a blank tab, font size up, zoom 110%
# 5. Turn off all notifications (Focus mode)
```

---

## Launch command

```bash
python demo/live_demo.py
```

This single command:
- Generates a fresh cryptographic CA and issues a signed agent token
- Starts `olive serve --ui` on port 7799
- Sends scripted MCP traffic through the gateway
- Fires a red-team drill automatically

Then open **http://127.0.0.1:7799/** in the browser.

---

## Talk track — 6 minutes

### 0:00 — OPENING (30 s)

> "Every company deploying AI agents has the same problem: the agent is trusted,
> but the content it retrieves isn't. A poisoned document, a manipulated API
> response, a malicious tool description — any of those can silently re-program
> a legitimate agent mid-session. Perimeter security doesn't see this traffic at all.
>
> Olive is a transparent MCP proxy that sits between an agent and its tools.
> Zero configuration for the agent. Every message inspected in both directions.
> Watch."

**[Run `python demo/live_demo.py` in the terminal. Point to the browser.]**

---

### 0:30 — IDLE GATEWAY (20 s)

> "This is the live Command Center. The three rooms on the left are Olive's
> internal departments — Defense, Remediation, Red Team. They're empty right now
> because nothing is happening. The gateway is alive; the departments are waiting."

*What to show:* The three dark SVG office scenes with no animated agents.
The spinning rings in the gateway center. The green live dot in the header.

---

### 0:50 — BENIGN TRAFFIC (40 s)

> "The demo agent is calling tools normally — reading a README, listing a
> directory, checking policy config. Watch the gateway."

*What to show:* The gateway center flashes green on each ALLOW decision.
The decision toast slides in from the top-right corner showing `ALLOW`.
The `allowed` counter increments.

> "Every decision is logged. That 'ALLOW' badge isn't a UI animation — it's
> a database write. I'll show you the audit trail at the end."

---

### 1:30 — FIRST BLOCK: PATH TRAVERSAL (45 s)

> "Now the agent tries to read `/etc/passwd`."

*What to show:*
- Gateway flashes red, glow expands
- Toast: `BLOCK — policy:deny-path-traversal`
- **Defense room lights up** — the agent figure materializes, arms type, eyes glow
- Status label reads `BLOCKING THREAT`
- Threats neutralized counter ticks up and pops

> "Defense activated. The policy inspector caught a path-traversal attempt.
> The agent is still running — only this call was blocked. The session stays open;
> the circuit breaker is counting."

---

### 2:15 — SECOND BLOCK: PROMPT INJECTION (45 s)

> "Next — a write call with a prompt-injection payload embedded in the content."

*What to show:*
- Another red flash
- Toast: `BLOCK — pattern:prompt-injection`
- Threats neutralized climbs again
- Trust panel (bottom-left): `demo-agent` score drops below 85% → `SUSPECT` badge turns yellow

> "The trust score just dropped to SUSPECT. This is zero-trust in action —
> not a static label assigned at login, but a live score computed from every
> decision made about this agent this session. Two bad calls in a row is the
> signal."

---

### 3:00 — FIRE DRILL: RED TEAM DEPT (60 s)

> "Now I'll run a fire drill. This is what a security operator does when they
> suspect the gateway is being probed — they launch an active red-team sweep."

**[Click the `FIRE DRILL` button in the browser — or let the demo script trigger it.]**

*What to show:*
- Colored bolt animates from Attack Theater → gateway → impact ring
- **Red Team room** lights up: `ATTACK LAUNCHED`
- Gateway flashes and rings expand
- After a moment: `REDTEAM FINDING` appears in the log

> "The Red Team department is running adversarial cases against the live gateway.
> Every finding that gets through becomes a new entry in the eval corpus —
> the CI gate runs it on the next push. The detection quality compounds."

*If a redteam-finding fires:*
- **Remediation room** primes: `ANALYZING INCIDENT`
- After analysis: `PATCH PROPOSED` card appears in the log

> "Remediation just proposed a fix. But nothing auto-deploys. A human with an
> `olive:remediate` token approves before any change goes in. The loop closes,
> but human intent is the gate."

---

### 4:00 — ESCALATION TO SIEGE (optional, if time allows) (30 s)

> "If we keep firing attacks — and enough sessions get quarantined — the
> Commander escalates to SIEGE mode. Watch the whole screen."

**[Click `AUTO DEMO` in the browser, which cycles all 4 attack categories]**

*What to show:*
- Background shifts from dark teal to red tint
- Header border pulses red
- Mode badge blinks `SIEGE`
- `FROZEN SESSIONS` count appears in header
- All three departments flashing simultaneously

> "The screen just changed mood. Every department is at maximum posture.
> This is Olive's SIEGE cascade — not just a badge change, a full operating-mode
> shift that tightens every threshold, freezes compromised sessions, and revokes
> their tokens."

---

### 4:30 — AUDIT TRAIL (30 s)

> "Switch to the LOG tab."

**[Click the LOG tab in the right panel]**

*What to show:*
- List of every event: decision type, rule, agent, timestamp
- Click one → full detail overlay

> "Every tile you've seen is backed by a SQLite row. The rule that fired.
> The agent ID. The SHA-256 hash of the payload — never the raw content,
> because the payload may contain secrets. Every decision is auditable.
> No silent passes, ever."

---

### 5:00 — CLOSING (60 s)

> "Let me zoom out. What you've seen:
>
> — A transparent proxy that inspects all MCP traffic without any changes
>   to the agent or the tool server.
>
> — Five attack types caught: path traversal, prompt injection, encoded bypass,
>   exfiltration, privilege escalation. 42 out of 42 active cases in CI. Zero
>   false positives.
>
> — A live trust score that degraded in real time based on behavior — not a
>   static role label.
>
> — A full Reproduce → Repair → Verify → Learn loop running inside the gateway.
>   The system gets harder to attack every time it's attacked.
>
> The market validated this in cash: Lakera, Prompt Security, Protect AI,
> Robust Intelligence — all acquired by Check Point, SentinelOne, Palo Alto,
> Cisco. The category is real. The question is what's defensible.
>
> Our moat is the eval corpus. It's compounding. CI won't let the system get
> silently weaker. No competitor publishes verifiable numbers. We do."

---

## Appendix A — If the demo script fails

```bash
# Option B: Manual startup
python -m olive.cli serve --ui \
  --config policies/default.yaml \
  --ca-pubkey ca.pem \
  --port 7799 \
  -- python demo/tools_server.py

# Then use the AUTO DEMO button in the browser to drive traffic
```

## Appendix B — To demo SIEGE mode reliably

The circuit breaker quarantines after 3 blocks per session (default).
SIEGE is declared after 3 quarantines total. To hit SIEGE in a controlled demo:

```bash
# Option 1: Use AUTO DEMO button twice in the browser
# Each auto-demo cycle fires all 4 attack categories via the operator endpoint

# Option 2: Reduce the threshold at startup
python -m olive.cli serve --ui \
  --config policies/default.yaml \
  --ca-pubkey ca.pem \
  --port 7799 \
  --max-blocks 1 \      # quarantine after 1 block per session
  -- python demo/tools_server.py
# Then two malicious calls → SUSPICIOUS; third quarantine → SIEGE
```

## Appendix C — Q&A cheat sheet

| Question | Answer |
|---|---|
| Does it work with any LLM? | Yes — Olive is protocol-layer (MCP), not model-specific. It works with Claude, GPT-4, Llama, or any agent that uses MCP. |
| What's the latency overhead? | Deterministic inspectors: sub-millisecond. LLM sentinel is async/advisory — it never blocks the fast path. |
| Can you turn off specific rules? | Yes — policies/default.yaml. Trust labels allow per-role inspection depth. |
| Does the agent know it's being proxied? | No. From the agent's perspective it's talking to a normal MCP server. |
| What about encrypted traffic? | Olive is on the server-side of the TLS termination — it sees plaintext MCP messages before re-encryption to the tool server. |
| Open source? | Core gateway is Apache-2.0. Commercial control-plane (fleet management, central policy) is the planned premium tier. Business model deliberately deferred until first external feedback. |
| Who is customer zero? | Any engineering team deploying internal agents who are uneasy about what agents can be tricked into doing. Bar-Ilan itself is a natural first design partner. |
