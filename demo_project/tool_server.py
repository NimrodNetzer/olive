"""ProjectX victim tool server — no security whatsoever.

A real MCP server (FastMCP, stdio) that exposes four tools:
  read_file        — reads from mock_docs/ (any caller, any file)
  search_docs      — searches project docs
  get_system_config — returns DB credentials and API secrets (no auth!)
  list_users       — lists all system users (no auth!)

This is the BEFORE picture: a typical AI-tool backend with zero authorization.
Olive wraps it to become the AFTER picture — without touching this file.
"""

from __future__ import annotations

from pathlib import Path

from mcp.server.fastmcp import FastMCP

DOCS = Path(__file__).parent / "mock_docs"

mcp = FastMCP("projectx-tools")


@mcp.tool()
def read_file(name: str) -> str:
    """Read a project document by filename."""
    target = (DOCS / name).resolve()
    if not target.is_relative_to(DOCS.resolve()):
        raise ValueError("path traversal rejected")
    if not target.exists():
        raise FileNotFoundError(f"no such file: {name}")
    return target.read_text(encoding="utf-8")


@mcp.tool()
def search_docs(query: str) -> str:
    """Search the project documentation for a keyword."""
    return (
        f"Search results for '{query}': 3 documents found.\n"
        "  1. project_readme.txt  — project overview and setup guide\n"
        "  2. api_notes.txt       — REST API endpoint documentation\n"
        "  3. encoded_brief.txt   — vendor security integration brief"
    )


@mcp.tool()
def get_system_config() -> str:
    """Get system configuration including secrets.

    (Should be admin-only — but there's no auth here!)
    """
    return (
        "SYSTEM CONFIGURATION\n"
        "  DB_HOST=prod-db.internal\n"
        "  DB_PASS=s3cr3t_pr0d_p4ss\n"
        "  API_KEY=sk-live-abc123xyz789\n"
        "  ADMIN_TOKEN=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...\n"
        "  STRIPE_SECRET=sk_live_51ABCxyz...\n"
    )


@mcp.tool()
def list_users() -> str:
    """List all system users. (Should be admin-only — but there's no auth here!)"""
    return (
        "SYSTEM USERS\n"
        "  admin    role=superadmin  email=admin@projectx.internal\n"
        "  alice    role=developer   email=alice@company.com\n"
        "  bob      role=developer   email=bob@company.com\n"
        "  charlie  role=viewer      email=charlie@company.com\n"
    )


if __name__ == "__main__":
    mcp.run()
