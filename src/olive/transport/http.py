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
from starlette.types import ASGIApp, Receive, Scope, Send

import hmac

from olive.identity.claims import IdentityClaims, claims_from_token, session_key
from olive.identity.tokens import IdentityError, RevokedTokenCache

# Capability a token must carry to use the admin release endpoint.
RELEASE_SCOPE = "olive:release"
# Capability a token must carry to approve a held call (ADR-0010).
APPROVE_SCOPE = "olive:approve"
# Capability a token must carry to revoke a JWT token (M9).
REVOKE_SCOPE = "olive:command"


_DASHBOARD_SKIP_PATHS = frozenset({"/mcp", "/admin/release", "/admin/approve", "/admin/revoke"})


class DashboardAuthMiddleware:
    """Gate the dashboard surface behind a static shared secret.

    Skipped paths are the MCP endpoint and the three exact admin routes — each of
    those has its own CA-token or capability check. Using an exact set (not a prefix)
    avoids a forward-looking hole where a new /admin/* route added without its own
    auth would become reachable without the dashboard token.

    Token comparison uses hmac.compare_digest (constant-time) to prevent a timing
    oracle on the secret."""

    def __init__(self, app: ASGIApp, token: str) -> None:
        self._app = app
        self._expected = f"Bearer {token}".encode()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] in ("http", "websocket"):
            path: str = scope.get("path", "")
            is_skipped = path in _DASHBOARD_SKIP_PATHS or path.startswith("/mcp/")
            if not is_skipped:
                headers = dict(scope.get("headers", []))
                auth = headers.get(b"authorization", b"")
                if not hmac.compare_digest(auth, self._expected):
                    if scope["type"] == "http":
                        body = b'{"error":"unauthorized"}'
                        await send({
                            "type": "http.response.start",
                            "status": 401,
                            "headers": [
                                (b"content-type", b"application/json"),
                                (b"content-length", str(len(body)).encode()),
                            ],
                        })
                        await send({"type": "http.response.body", "body": body, "more_body": False})
                        return
                    else:
                        await send({"type": "websocket.close", "code": 1008})
                        return
        await self._app(scope, receive, send)


class OliveTokenVerifier(TokenVerifier):
    """Verifies CA-signed bearer tokens. Returns None on any failure so the
    SDK's bearer backend rejects the request (fail closed)."""

    def __init__(
        self,
        public_key_pem: bytes,
        revocation: RevokedTokenCache | None = None,
    ) -> None:
        self._public_key_pem = public_key_pem
        self._revocation = revocation

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            claims = claims_from_token(token, self._public_key_pem)
        except IdentityError:
            return None
        # Revocation check (M9): a revoked jti is rejected even if the signature
        # and expiry are valid. Fail closed — revocation must be honoured.
        if self._revocation is not None and claims.jti:
            if self._revocation.is_revoked(claims.jti):
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
                # Carry the task binding so contextual resource rules (ADR-0010)
                # are enforceable on the wire, not just in-process.
                "task_resources": list(claims.task_resources),
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
        task_resources=tuple(c.get("task_resources", ())),
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
    # A session is the (org, agent, session_id) triple - all three appear in the
    # audit log, so an operator can identify the session to release.
    try:
        body = await request.json()
        org, agent, sid = body["organization"], body["agent_id"], body["session_id"]
    except (KeyError, TypeError, ValueError):
        return JSONResponse(
            {"error": "body must be {organization, agent_id, session_id}"}, status_code=400
        )
    released = await request.app.state.gateway.release_session(session_key(org, agent, sid))
    return JSONResponse(
        {"organization": org, "agent_id": agent, "session_id": sid, "released": released}
    )


async def _approve(request: Request) -> JSONResponse:
    token = get_access_token()
    if token is None:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    if APPROVE_SCOPE not in (token.scopes or []):
        return JSONResponse(
            {"error": f"forbidden: requires '{APPROVE_SCOPE}' capability"}, status_code=403
        )
    # The approval id is surfaced to the agent in the held response and to the
    # operator in the audit trail (ADR-0010).
    try:
        body = await request.json()
        approval_id = body["approval_id"]
    except (KeyError, TypeError, ValueError):
        return JSONResponse({"error": "body must be {approval_id}"}, status_code=400)
    approved = await request.app.state.gateway.approve_hold(approval_id)
    return JSONResponse({"approval_id": approval_id, "approved": approved})


async def _revoke(request: Request) -> JSONResponse:
    """Revoke a JWT token by jti (M9 — Siege Crisis Response). Requires the
    olive:command capability — the same scope that can force a mode change."""
    token = get_access_token()
    if token is None:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    if REVOKE_SCOPE not in (token.scopes or []):
        return JSONResponse(
            {"error": f"forbidden: requires '{REVOKE_SCOPE}' capability"}, status_code=403
        )
    try:
        body = await request.json()
        jti = body["jti"]
        org = body.get("organization", "")
        agent = body.get("agent_id", "")
        reason = str(body.get("reason", ""))[:200]
    except (KeyError, TypeError, ValueError):
        return JSONResponse({"error": "body must be {jti, organization?, agent_id?, reason?}"}, status_code=400)
    revocation: RevokedTokenCache | None = getattr(request.app.state, "revocation", None)
    store = getattr(request.app.state.gateway, "_store", None)
    if revocation is not None:
        revocation.revoke(jti)
    if store is not None:
        await store.revoke_token(jti, org, agent, reason or None)
    return JSONResponse({"jti": jti, "revoked": True})


def build_http_app(
    public_key_pem: bytes,
    lifespan,
    *,
    mcp_path: str = "/mcp",
    extra_routes: list | None = None,
    revocation: RevokedTokenCache | None = None,
    dashboard_token: str | None = None,
) -> Starlette:
    """Assemble the Starlette app: bearer auth context on every request, the MCP
    endpoint behind RequireAuthMiddleware, and capability-gated admin endpoints.
    The caller's `lifespan` must set `app.state.session_manager` and
    `app.state.gateway` and run the session manager.

    `extra_routes` (ADR-0020) are appended AS-IS, deliberately NOT wrapped in
    `RequireAuthMiddleware`: the co-mounted Command Center dashboard is read-only
    and its `POST /operator` is announce-only (ADR-0017 §5), so it is reachable
    without a bearer token. They are passed in by the composition root so this
    transport module never imports `olive.ui` (the layering rule, ADR-0003). The
    global auth-context middleware still runs but does not reject a request that
    carries no token; only `RequireAuthMiddleware` (on `/mcp`) rejects.

    `dashboard_token` (optional) gates the entire dashboard surface (everything
    except `/mcp` and `/admin/*`) behind a static shared secret via
    `DashboardAuthMiddleware`. No-op when None (preserves the current
    localhost-only dev UX)."""
    verifier = OliveTokenVerifier(public_key_pem, revocation=revocation)
    middleware = [
        Middleware(AuthenticationMiddleware, backend=BearerAuthBackend(verifier)),
        Middleware(AuthContextMiddleware),
    ]
    if dashboard_token:
        middleware.append(Middleware(DashboardAuthMiddleware, token=dashboard_token))
    routes = [
        Route(mcp_path, endpoint=RequireAuthMiddleware(_McpAsgiApp(), [], None)),
        Route("/admin/release", endpoint=_release, methods=["POST"]),
        Route("/admin/approve", endpoint=_approve, methods=["POST"]),
        Route("/admin/revoke", endpoint=_revoke, methods=["POST"]),
        *(extra_routes or []),
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


def serving_lifespan_with_org(
    make_resources: Callable[[], AbstractAsyncContextManager[tuple]],
) -> Callable:
    """Like `serving_lifespan`, but the factory yields
    `(session_manager, gateway, org, ui_state)` (ADR-0020). `ui_state` is a dict of
    attributes to set on `app.state` for the co-mounted dashboard (e.g. `broker`,
    `bus`, `corpus`). The runtime org's background tasks are started AFTER the
    session manager is running and stopped on shutdown — neither blocks the serve
    loop. `org`/`ui_state` may be falsy, in which case this behaves like the bare
    lifespan (so one code path serves both the demo and a plain run)."""

    @contextlib.asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        async with make_resources() as (session_manager, gateway, org, ui_state):
            app.state.session_manager = session_manager
            app.state.gateway = gateway
            for key, value in (ui_state or {}).items():
                setattr(app.state, key, value)
            async with session_manager.run():
                if org is not None:
                    org.start()
                try:
                    yield
                finally:
                    if org is not None:
                        await org.stop()

    return lifespan
