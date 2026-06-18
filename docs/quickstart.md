# Olive Quickstart — 5 minutes to protected

Olive is a transparent MCP proxy that sits between your agent and its tools,
inspects every tool call and response, and blocks or quarantines malicious
behavior with a full audit trail. Your agent and tool server need zero changes.

---

## 1. Install

```bash
pip install -e .          # from source (until published to PyPI)
# or: pip install olive   # once published
```

Verify:

```bash
olive --help
```

---

## 2. Generate your CA keypair

Olive uses RS256 JWTs to identify agents on the wire. Generate a local CA once:

```bash
olive ca init
# Writes ~/.olive/ca/ca.key (private, 0600) and ~/.olive/ca/ca.pub
```

Keep `ca.key` secret. `ca.pub` is safe to distribute — pass it to every gateway
instance with `--ca-pubkey`.

---

## 3. Write a policy file

A policy file declares who can call what. Save as `policies/my-policy.yaml`:

```yaml
agent_id: my-agent
organization: acme
role: customer-support
declared_goal: "answer customer questions"
db_path: olive.db

roles:
  customer-support:
    allowed_tools:
      - read_faq
      - search_kb
    forbidden_tools:
      - access_payroll
      - delete_record

injection_patterns:
  - "ignore previous instructions"
  - "disregard your system prompt"
  - "you are now"

upstream_trust: untrusted
```

See `policies/default.yaml` for a fully-commented example.

---

## 4. Issue an agent token

Every agent needs a signed token. Issue one per agent/session:

```bash
# Print the token to stdout — pipe it to your agent's environment
TOKEN=$(olive ca issue \
  --agent-id my-agent \
  --org acme \
  --role customer-support \
  --capabilities read_faq,search_kb \
  --ttl-hours 8)

echo $TOKEN
```

For operator capabilities (release quarantined sessions, approve held calls):

```bash
OPS_TOKEN=$(olive ca issue \
  --agent-id ops-human \
  --org acme \
  --role operator \
  --capabilities olive:release,olive:approve,olive:command \
  --ttl-hours 2)
```

---

## 5. Start the gateway

### stdio mode (wrap an existing MCP server)

```bash
olive run \
  --config policies/my-policy.yaml \
  -- python path/to/your/tools_server.py
```

Your MCP client connects to Olive over stdio; Olive proxies to the tool server.

### HTTP mode with live dashboard

```bash
olive serve \
  --config policies/my-policy.yaml \
  --ca-pubkey ~/.olive/ca/ca.pub \
  --host 127.0.0.1 \
  --port 8080 \
  --ui \
  -- python path/to/your/tools_server.py
```

Open `http://127.0.0.1:8080/` for the live Command Center dashboard.

Your agent connects to `http://127.0.0.1:8080/mcp` with:

```
Authorization: Bearer <token from step 4>
```

---

## 6. Try the demo

The fastest way to see Olive detecting attacks:

```bash
python demo/live_demo.py
# Opens http://127.0.0.1:7799/
```

The demo runs a real gateway in front of a demo tool server and fires a
sequence of allowed, blocked, and injection attacks. Watch the dashboard
update live.

---

## What Olive checks (automatically, no config needed)

| Surface | What's checked |
|---|---|
| Tool calls (outbound) | Policy allowlist, injection patterns, contextual rules |
| Tool responses (inbound) | Injection patterns, encoded/obfuscated attacks |
| Tool descriptions | Poisoning, rug-pull (description changed since last session) |
| Resources & prompts | Same as tool responses |
| Session behavior | Call rate anomalies, novel tool access, chain detection |

Detection rate on the eval corpus: **57/57 active cases caught, 0/24 false positives**.

---

## Common operations

### Release a quarantined session

```bash
curl -X POST http://127.0.0.1:8080/admin/release \
  -H "Authorization: Bearer $OPS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"organization": "acme", "agent_id": "my-agent", "session_id": "<sid>"}'
```

### Expose HTTP APIs as MCP tools (bridge)

Create `bridge.yaml`:

```yaml
tools:
  get_user:
    method: GET
    url: "https://api.yourservice.com/users/{user_id}"
    path_params: [user_id]
    headers:
      Authorization: "Bearer ${API_TOKEN}"
```

Add to your policy's `upstreams:`:

```yaml
upstreams:
  - name: internal-api
    command: [python, -m, olive.bridge.server, --config, bridge.yaml]
```

Olive spawns the bridge as a subprocess and inspects every response exactly
like any other upstream.

### Send decision events to your SIEM

```bash
olive serve \
  --config policies/my-policy.yaml \
  --ca-pubkey ~/.olive/ca/ca.pub \
  --ui \
  --webhook-url https://your-siem.example.com/events \
  --webhook-token $SIEM_TOKEN \
  -- python tools_server.py
```

Events are hashes only (no raw payloads) — rule 3 compliant.

---

## Next steps

- **Multi-agent setup**: each agent gets its own token; policy file controls which roles exist
- **Contextual rules**: lock an agent to specific resource IDs for a task — see `policies/contextual.yaml`
- **Fleet management**: run `olive control-plane` to aggregate multiple gateways
- **Operating modes**: Normal → Suspicious → Siege escalation is automatic; de-escalate with an `olive:command` token
- **Full architecture**: `docs/ARCHITECTURE.md`
- **Threat model**: `docs/THREAT_MODEL.md`
