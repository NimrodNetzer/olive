"""Second demo MCP tool server - a separate 'records' service.

Used to demonstrate multi-upstream: one Olive gateway fronting two servers
(this one + tools_server.py), with tools namespaced `records.*` / `support.*`
and calls routed to the owning server. Demo scaffolding, NOT the product.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo-records")


@mcp.tool()
def lookup_customer(customer_id: str) -> str:
    """Look up a customer profile by id."""
    return (
        f"Customer {customer_id}: tier=gold, since=2021, open tickets=0, "
        "preferred contact=email."
    )


@mcp.tool()
def read_secret(name: str) -> str:
    """Read a secret value (restricted)."""
    # The gateway must block this before it ever runs for unauthorized roles.
    return f"SECRET({name}): [simulated sensitive value]"


if __name__ == "__main__":
    mcp.run()  # stdio
