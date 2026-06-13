"""HTTP transport - streamable HTTP with bearer-token identity enforcement.

This is where agent identity becomes load-bearing on the wire (ADR-0007): every
request must carry a CA-signed bearer token. The token is verified, mapped to
`IdentityClaims`, and the gateway enforces *as* that identity. No token / bad
token => 401 before the gateway is ever reached (fail closed).

The auth plumbing reuses the MCP SDK's bearer middleware; the verifier is ours
(MockCA RS256). A protected admin endpoint exposes reversible session release.
"""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager

from mcp.server.auth.middleware.auth_context import (
    AuthContextMiddleware,
    get_access_token,
)
from mcp.server.auth.middleware.bearer_auth import BearerAuthBackend, RequireAuthMiddleware
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.types import Receive, Scope, Send

from olive.identity.claims import IdentityClaims, claims_from_token
from olive.identity.tokens import IdentityError

# Capability a token must carry to use the admin release endpoint.
RELEASE_SCOPE = "olive:release"


class OliveTokenVerifier(TokenVerifier):
    """Verifies CA-signed bearer tokens. Returns None on any failure so the
    SDK's bearer backend rejects the request (fail closed)."""

    def __init__(self, public_key_pem: bytes) -> None:
        self._public_key_pem = public_key_pem

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            claims = claims_from_token(token, self._public_key_pem)
        except IdentityError:
            return None
        # scopes carry capabilities; claims carry the full identity so the
        # request handler can rebuild IdentityClaims without re-verifying.
        return AccessToken(
            token=token,
            client_id=claims.agent_id,
            scopes=list(claims.capabilities),
            subject=claims.agent_id,
            claims={
                "agent_id": claims.agent_id,
                "organization": claims.organization,
                "role": claims.role,
                "session_id": claims.session_id,
                "capabilities": list(claims.capabilities),
            },
        )


def identity_from_context() -> IdentityClaims | None:
    """Resolve the current request's verified identity from the auth contextvar.
    Returns None when unauthenticated (handlers then fail closed)."""
    token = get_access_token()
    if token is None or not token.claims:
        return None
    c = token.claims
    return IdentityClaims(
        agent_id=c["agent_id"],
        organization=c["organization"],
        role=c["role"],
        session_id=c["session_id"],
        capabilities=tuple(c.get("capabilities", ())),
        verified=True,
    )


class _McpAsgiApp:
    """Delegates to the session manager resolved from app state at request time
    (so the same app object works for the test lifespan and the CLI lifespan)."""

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        manager: StreamableHTTPSessionManager = scope["app"].state.session_manager
        await manager.handle_request(scope, receive, send)


async def _release(request: Request) -> JSONResponse:
    token = get_access_token()
    if token is None:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    if RELEASE_SCOPE not in (token.scopes or []):
        return JSONResponse(
            {"error": f"forbidden: requires '{RELEASE_SCOPE}' capability"}, status_code=403
        )
    session_id = request.path_params["session_id"]
    released = await request.app.state.gateway.release_session(session_id)
    return JSONResponse({"session_id": session_id, "released": released})


def build_http_app(
    public_key_pem: bytes,
    lifespan,
    *,
    mcp_path: str = "/mcp",
) -> Starlette:
    """Assemble the Starlette app: bearer auth on every request, the MCP
    endpoint behind RequireAuthMiddleware, and a capability-gated release
    endpoint. The caller's `lifespan` must set `app.state.session_manager` and
    `app.state.gateway` and run the session manager."""
    verifier = OliveTokenVerifier(public_key_pem)
    middleware = [
        Middleware(AuthenticationMiddleware, backend=BearerAuthBackend(verifier)),
        Middleware(AuthContextMiddleware),
    ]
    routes = [
        Route(mcp_path, endpoint=RequireAuthMiddleware(_McpAsgiApp(), [], None)),
        Route("/admin/release/{session_id}", endpoint=_release, methods=["POST"]),
    ]
    return Starlette(routes=routes, middleware=middleware, lifespan=lifespan)


def session_manager_for(server, *, json_response: bool = True) -> StreamableHTTPSessionManager:
    """Wrap a built MCP Server in a streamable-HTTP session manager."""
    return StreamableHTTPSessionManager(app=server, json_response=json_response, stateless=False)


def serving_lifespan(
    make_resources: Callable[[], AbstractAsyncContextManager[tuple]],
) -> Callable:
    """Build a Starlette lifespan from a factory that yields
    (session_manager, gateway). Keeps resource creation (upstream, store) out of
    this module so it stays transport-only."""

    @contextlib.asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        async with make_resources() as (session_manager, gateway):
            app.state.session_manager = session_manager
            app.state.gateway = gateway
            async with session_manager.run():
                yield

    return lifespan
