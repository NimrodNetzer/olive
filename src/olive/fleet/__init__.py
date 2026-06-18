"""Fleet layer — multi-gateway control plane (ADR-0024).

Lives on the intelligence side of the ADR-0003 seam: gateway core (gateway/,
store/, identity/) must never import from this package. A test asserts it.
"""
