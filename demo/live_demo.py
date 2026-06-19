"""Live dashboard demo — starts the gateway with --ui, opens the browser,
then drives a scripted sequence of benign and malicious traffic so every
department in the Command Center lights up.

Run:
    python demo/live_demo.py          # Windows / macOS / Linux
    ./quickstart.sh                   # one-command wrapper

Dashboard opens at http://127.0.0.1:7799

Attack scenario:
  Scene 1 — Legitimate work flows through Olive unimpeded.
  Scene 2 — A poisoned business document arrives in a tool response.
             Olive intercepts it before it reaches the agent.
  Scene 3 — Repeated blocks trip the circuit breaker; the session is
             quarantined. The operating mode escalates to SUSPICIOUS.
  Scene 4 — Operator triggers a red-team fire drill from the dashboard.
"""

from __future__ import annotations

import asyncio
import subprocess
import sys
import time
from pathlib import Path

# Force UTF-8 output on Windows consoles that default to a legacy codepage.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

ROOT = Path(__file__).parent.parent
CA_PEM = ROOT / "ca.pem"

BOLD   = "\033[1m"
DIM    = "\033[2m"
GREEN  = "\033[32m"
RED    = "\033[31m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
RESET  = "\033[0m"


def banner(text: str, char: str = "─") -> None:
    width = 62
    pad = max(0, (width - len(text) - 2) // 2)
    print(f"\n{DIM}{char * pad}{RESET} {BOLD}{text}{RESET} {DIM}{char * pad}{RESET}\n")


def step(n: int, label: str) -> None:
    print(f"  {CYAN}{n}.{RESET} {label}")


def result(status: str, label: str, detail: str = "") -> None:
    if status == "ALLOW":
        tag = f"{GREEN}[ ALLOW ]{RESET}"
    elif status == "BLOCK":
        tag = f"{RED}[ BLOCK ]{RESET}"
    else:
        tag = f"{YELLOW}[{status:^7}]{RESET}"
    suffix = f"  {DIM}{detail}{RESET}" if detail else ""
    print(f"      {tag}  {label}{suffix}")


def note(text: str) -> None:
    print(f"             {DIM}↳ {text}{RESET}")


def _setup_ca() -> bytes:
    from olive.identity.tokens import MockCA
    from cryptography.hazmat.primitives import serialization

    ca = MockCA()
    CA_PEM.write_bytes(ca.public_key_pem())
    return ca._private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


async def _traffic_loop(priv_pem: bytes) -> None:
    import httpx
    import jwt as pyjwt
    from datetime import datetime, timedelta, timezone
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    priv_key = load_pem_private_key(priv_pem, password=None)

    # Fresh session ID each run so a previously quarantined session from the
    # DB does not trip the circuit breaker before Scene 1 even starts.
    _run_ts = int(datetime.now(timezone.utc).timestamp())
    _session_id = f"sess-demo-{_run_ts}"

    def _token() -> str:
        now = datetime.now(timezone.utc)
        return pyjwt.encode(
            {
                "sub": "support-agent-7f3a",
                "org": "demo-company",
                "role": "customer-support",   # matches default.yaml
                "session_id": _session_id,
                "capabilities": [],
                "task_resources": [],
                "aud": "olive-gateway",
                "iat": now,
                "exp": now + timedelta(hours=1),
            },
            priv_key,
            algorithm="RS256",
        )

    banner("Waiting for gateway to be ready...")
    for _ in range(40):
        try:
            async with httpx.AsyncClient(timeout=2) as c:
                if (await c.get("http://127.0.0.1:7799/corpus")).status_code == 200:
                    print(f"  {GREEN}Gateway ready.{RESET}")
                    break
        except Exception:
            pass
        await asyncio.sleep(0.5)
    else:
        print(f"  {RED}Gateway did not come up — aborting.{RESET}")
        return

    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    auth_header = {"Authorization": f"Bearer {_token()}"}
    print(f"  Connecting MCP session as {BOLD}support-agent-7f3a{RESET} (role: customer-support)...")

    async with streamablehttp_client(
        "http://127.0.0.1:7799/mcp", headers=auth_header
    ) as (r, w, _):
        async with ClientSession(r, w) as sess:
            await sess.initialize()
            tools = await sess.list_tools()
            visible = [t.name for t in tools.tools]
            print(f"  Tools visible through gateway: {CYAN}{visible}{RESET}")

            async def call(tool: str, args: dict, label: str, detail: str = "") -> bool:
                res = await sess.call_tool(tool, args)
                blocked = res.isError
                result("BLOCK" if blocked else "ALLOW", label, detail)
                return blocked

            # ── Scene 1: normal work ──────────────────────────────────────────
            banner("Scene 1 — Legitimate work flows freely")
            print(
                f"  The agent handles normal customer-support tasks.\n"
                f"  Olive inspects every call and response — but lets clean\n"
                f"  traffic through with no interference.\n"
            )

            step(1, "Look up the FAQ for a customer question")
            await call("read_faq", {"topic": "return policy"},
                       "read_faq(return policy)")
            await asyncio.sleep(0.9)

            step(2, "Search the knowledge base")
            await call("search_kb", {"query": "shipping times"},
                       "search_kb(shipping times)")
            await asyncio.sleep(0.9)

            step(3, "Pull a customer order")
            await call("read_customer_order", {"order_id": "ORD-918"},
                       "read_customer_order(ORD-918)")
            await asyncio.sleep(0.9)

            step(4, "Read a clean internal document")
            await call("read_file", {"name": "safe_document.txt"},
                       "read_file(safe_document.txt)")
            note("Document content is clean — Olive passes it through")
            await asyncio.sleep(1.1)

            # ── Scene 2: inbound injection from a tool response ───────────────
            banner("Scene 2 — Poisoned document blocked inbound")
            print(
                f"  An attacker has uploaded a document that looks like a\n"
                f"  legitimate Q3 partner brief — but contains hidden instructions\n"
                f"  embedded inside the text.\n"
                f"\n"
                f"  The agent's tool call is ALLOWED (clean request).\n"
                f"  Olive catches the injection in the RESPONSE before the\n"
                f"  agent ever sees it.\n"
            )

            step(5, "Agent reads the partner brief (tool call is allowed)")
            blocked = await call(
                "read_file", {"name": "external_brief.txt"},
                "read_file(external_brief.txt)  ← clean outbound request",
            )
            if blocked:
                note("Inbound injection detected: \"IGNORE PREVIOUS INSTRUCTIONS\"")
                note("Agent never receives the document — incident logged")
            await asyncio.sleep(1.2)

            # ── Scene 3: policy block then circuit breaker ────────────────────
            banner("Scene 3 — Privilege escalation + circuit breaker")
            print(
                f"  The session now tries to access payroll — a tool it is\n"
                f"  explicitly forbidden from using. Two blocks trip the\n"
                f"  circuit breaker; the session is quarantined.\n"
            )

            step(6, "Escalation attempt — access payroll records (forbidden tool)")
            blocked = await call(
                "access_payroll", {"scope": "all_employees"},
                "access_payroll(all_employees)",
                "blocked by policy: forbidden_tools",
            )
            if blocked:
                note("Block 2 of 3 — upstream server never contacted")
            await asyncio.sleep(1.0)

            step(7, "Second escalation — same forbidden tool, different scope")
            blocked = await call(
                "access_payroll", {"scope": "executives"},
                "access_payroll(executives)",
                "blocked by policy: forbidden_tools",
            )
            if blocked:
                note("Block 3 of 3 — circuit breaker TRIPS → session QUARANTINED")
                note("Mode escalates: NORMAL → SUSPICIOUS")
            await asyncio.sleep(1.3)

            step(8, "Any further call from this session — denied instantly")
            await call(
                "read_faq", {"topic": "shipping"},
                "read_faq(shipping)  ← quarantined session",
                "denied before any inspection or upstream contact",
            )
            note("Operator must release with an olive:release token to resume")
            await asyncio.sleep(1.2)

    # ── Scene 4: red-team fire drill ─────────────────────────────────────────
    banner("Scene 4 — Red-team fire drill (sandbox only)")
    print(
        f"  The operator triggers the Red-Team department from the dashboard.\n"
        f"  It attacks only the sandboxed inspector pipeline — never live\n"
        f"  traffic. Any bypass it finds is published to the incident bus\n"
        f"  for the Builder department to propose a fix.\n"
    )

    async with httpx.AsyncClient(timeout=10) as c:
        step(9, "Fire drill round 1")
        r = await c.post(
            "http://127.0.0.1:7799/operator",
            json={"action": "run-campaign-request", "evidence": "demo fire drill — round 1"},
        )
        word = "triggered" if r.status_code == 200 else f"HTTP {r.status_code}"
        print(f"             {CYAN}Red-Team drill: {word}{RESET}")
        note("Watch the Command Center — department tiles animate, bus ticks")

    await asyncio.sleep(4)

    async with httpx.AsyncClient(timeout=10) as c:
        step(10, "Fire drill round 2 — escalation sweep")
        r = await c.post(
            "http://127.0.0.1:7799/operator",
            json={"action": "run-campaign-request", "evidence": "demo fire drill — round 2"},
        )
        word = "triggered" if r.status_code == 200 else f"HTTP {r.status_code}"
        print(f"             {CYAN}Red-Team drill: {word}{RESET}")

    banner("Demo complete", "═")
    print(f"  {GREEN}Dashboard:{RESET}   http://127.0.0.1:7799")
    print(f"  {GREEN}Audit DB:{RESET}    olive_events.db  (hashes + bounded excerpts only)")
    print(f"  {GREEN}Next:{RESET}        Click AUTO DEMO in the browser to push")
    print(f"             SUSPICIOUS → SIEGE and watch the cascade.")
    print(f"\n  {DIM}Press Ctrl+C to stop the gateway.{RESET}\n")


def _free_port(port: int) -> None:
    try:
        out = subprocess.check_output(
            ["netstat", "-ano"], text=True, stderr=subprocess.DEVNULL
        )
        for line in out.splitlines():
            if f":{port}" in line and "LISTENING" in line:
                parts = line.split()
                proc_id = int(parts[-1])
                if proc_id > 0:
                    subprocess.run(
                        ["taskkill", "/F", "/PID", str(proc_id)],
                        capture_output=True,
                    )
                    print(f"  Stopped previous server on port {port} (PID {proc_id})")
                    time.sleep(1)
                    break
    except Exception:
        pass


def main() -> None:
    banner("OLIVE — Live Demo", "═")
    print(f"  Zero-trust runtime security gateway for AI agents")
    print(f"  {DIM}story: DEMO.md  ·  setup guide: docs/quickstart.md{RESET}\n")

    _free_port(7799)

    print("  Generating CA keypair (ephemeral, demo-only)...")
    priv_pem = _setup_ca()
    print(f"  CA public key → {CA_PEM}")

    print("\n  Starting gateway with live Command Center on port 7799...")
    proc = subprocess.Popen(
        [
            sys.executable, "-m", "olive.cli", "serve",
            "--ui",
            "--config", "policies/default.yaml",
            "--ca-pubkey", str(CA_PEM),
            "--port", "7799",
            "--", sys.executable, "demo/tools_server.py",
        ],
        cwd=str(ROOT),
    )

    print(f"\n  {BOLD}{GREEN}Dashboard → http://127.0.0.1:7799{RESET}")
    print(f"  Open that URL now. Watch the agents animate as traffic flows.\n")

    try:
        asyncio.run(_traffic_loop(priv_pem))
        proc.wait()
    except KeyboardInterrupt:
        print(f"\n  {DIM}Stopping gateway...{RESET}")
        proc.terminate()
        proc.wait()
        print(f"  Done.\n")


if __name__ == "__main__":
    main()
