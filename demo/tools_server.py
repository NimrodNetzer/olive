"""Demo MCP tool server - the upstream Olive protects.

A real MCP server (FastMCP, stdio). Simulates an internal tool surface:
FAQ, knowledge base, orders, payroll, and file reads - including a poisoned
external document. This is demo scaffolding, NOT the product.
"""

from __future__ import annotations

from pathlib import Path

from mcp.server.fastmcp import FastMCP

MOCK_FILES = Path(__file__).parent / "mock_files"

mcp = FastMCP("demo-tools")


@mcp.tool()
def read_faq(topic: str) -> str:
    """Read an internal FAQ entry by topic."""
    return (
        f"FAQ - {topic}: Returns are accepted within 30 days with proof of "
        "purchase. Refunds are processed to the original payment method "
        "within 5 business days."
    )


@mcp.tool()
def search_kb(query: str) -> str:
    """Search the internal knowledge base."""
    return (
        f"KB results for '{query}': Standard shipping takes 3-5 business days. "
        "Express shipping is available for orders over $50."
    )


@mcp.tool()
def read_customer_order(order_id: str) -> str:
    """Read a customer order by id."""
    return (
        f"Order {order_id}: 2x wireless headphones, status: shipped, "
        "carrier: DHL, ETA: 2 days."
    )


@mcp.tool()
def access_payroll(scope: str) -> str:
    """Access payroll records (restricted)."""
    # The gateway must block this before it ever runs for unauthorized roles.
    return f"PAYROLL DATA ({scope}): [simulated sensitive records]"


@mcp.tool()
def read_file(name: str) -> str:
    """Read a document from the shared drive."""
    target = (MOCK_FILES / name).resolve()
    if not target.is_relative_to(MOCK_FILES.resolve()):
        raise ValueError("path traversal rejected")
    if not target.exists():
        raise FileNotFoundError(f"no such document: {name}")
    return target.read_text(encoding="utf-8")


if __name__ == "__main__":
    mcp.run()  # stdio
