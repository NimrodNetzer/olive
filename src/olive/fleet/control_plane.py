"""Control plane HTTP application (ADR-0024).

Lightweight Starlette app launched via `olive control-plane`. All endpoints
require a bearer token carrying the `olive:fleet` capability (a distinct scope
that does not imply olive:command, olive:approve, or any other capability).

Endpoints:
  POST /fleet/heartbeat          — receive gateway heartbeat; return commanded mode
  POST /fleet/push               — receive batched event/incident summaries
  GET  /fleet/gateways           — list registered gateways (liveness)
  GET  /fleet/events             — recent events across all gateways
  GET  /fleet/incidents          — recent incidents across all gateways
  GET  /fleet/mode               — commanded mode per gateway
  POST /fleet/mode               — (admin) set commanded mode for all gateways
  GET  /fleet/policy/{role}      — serve role policy YAML from local policies dir

The dashboard read path (GET endpoints) is read-only by construction — no
GET handler mutates state. POST /fleet/mode requires the same olive:fleet
capability the gateway push does; a narrower olive:fleet-admin could be
introduced later without changing the gateway client.
"""

from __future__ import annotations

from pathlib import Path

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Route

from olive.fleet.registry import GatewayRegistry
from olive.identity.claims import claims_from_token
from olive.identity.tokens import IdentityError

_FLEET_CAP = "olive:fleet"


def _verify_fleet(request: Request, ca_pubkey: bytes) -> str | None:
    """Verify bearer token; return agent_id if valid with olive:fleet, else None."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    try:
        claims = claims_from_token(auth[len("Bearer "):], ca_pubkey)
    except IdentityError:
        return None
    if _FLEET_CAP not in claims.capabilities:
        return None
    return claims.agent_id


def build_control_plane_app(
    registry: GatewayRegistry,
    ca_pubkey: bytes,
    policies_dir: Path,
) -> Starlette:
    """Assemble the control plane Starlette application."""

    def _auth(handler):
        """Decorator: verify olive:fleet token before any endpoint runs."""
        async def wrapper(request: Request) -> Response:
            caller = _verify_fleet(request, ca_pubkey)
            if caller is None:
                return JSONResponse({"error": "unauthorized"}, status_code=401)
            request.state.caller = caller
            return await handler(request)
        wrapper.__name__ = handler.__name__
        return wrapper

    @_auth
    async def heartbeat(request: Request) -> Response:
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "invalid JSON"}, status_code=400)
        gateway_id = body.get("gateway_id", "").strip()
        if not gateway_id:
            return JSONResponse({"error": "gateway_id required"}, status_code=400)
        org_id = body.get("org_id", "")
        reported_mode = body.get("current_mode", "normal")
        commanded_mode = await registry.record_heartbeat(gateway_id, org_id, reported_mode)
        return JSONResponse({"gateway_id": gateway_id, "commanded_mode": commanded_mode})

    @_auth
    async def push(request: Request) -> Response:
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "invalid JSON"}, status_code=400)
        gateway_id = request.headers.get("X-Gateway-ID", "")
        events = body.get("events", [])
        incidents = body.get("incidents", [])
        if events:
            await registry.record_events(gateway_id, events)
        if incidents:
            await registry.record_incidents(gateway_id, incidents)
        return JSONResponse({"received": len(events) + len(incidents)})

    @_auth
    async def list_gateways(request: Request) -> Response:
        return JSONResponse(await registry.list_gateways())

    @_auth
    async def fleet_events(request: Request) -> Response:
        return JSONResponse(await registry.recent_events())

    @_auth
    async def fleet_incidents(request: Request) -> Response:
        return JSONResponse(await registry.recent_incidents())

    @_auth
    async def fleet_mode_get(request: Request) -> Response:
        gateways = await registry.list_gateways()
        return JSONResponse([
            {
                "gateway_id": g["gateway_id"],
                "commanded_mode": g["commanded_mode"],
                "reported_mode": g["reported_mode"],
                "last_heartbeat": g["last_heartbeat"],
            }
            for g in gateways
        ])

    @_auth
    async def fleet_mode_set(request: Request) -> Response:
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "invalid JSON"}, status_code=400)
        mode = body.get("mode", "").lower()
        if mode not in ("normal", "suspicious", "siege"):
            return JSONResponse({"error": f"invalid mode {mode!r}"}, status_code=400)
        await registry.set_fleet_mode(mode, issued_by=request.state.caller)
        return JSONResponse({"mode": mode, "status": "commanded"})

    async def fleet_mode_router(request: Request) -> Response:
        if request.method == "GET":
            return await fleet_mode_get(request)
        return await fleet_mode_set(request)

    @_auth
    async def fleet_mode_gateway(request: Request) -> Response:
        gateway_id = request.path_params["gateway_id"].strip()
        if not gateway_id:
            return JSONResponse({"error": "gateway_id required"}, status_code=400)
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "invalid JSON"}, status_code=400)
        mode = body.get("mode", "").lower()
        if mode not in ("normal", "suspicious", "siege"):
            return JSONResponse({"error": f"invalid mode {mode!r}"}, status_code=400)
        found = await registry.set_gateway_mode(
            gateway_id, mode, issued_by=request.state.caller
        )
        if not found:
            return JSONResponse({"error": f"gateway '{gateway_id}' not found"}, status_code=404)
        return JSONResponse({"gateway_id": gateway_id, "mode": mode, "status": "commanded"})

    @_auth
    async def policy(request: Request) -> Response:
        role = request.path_params["role"]
        # Reject anything that isn't a safe identifier — no path traversal.
        if not role.replace("-", "").replace("_", "").isalnum():
            return PlainTextResponse("invalid role name", status_code=400)
        path = policies_dir / f"{role}.yaml"
        if not path.exists():
            return PlainTextResponse("policy not found", status_code=404)
        return PlainTextResponse(path.read_text(encoding="utf-8"), media_type="text/yaml")

    return Starlette(routes=[
        Route("/fleet/heartbeat", heartbeat, methods=["POST"]),
        Route("/fleet/push", push, methods=["POST"]),
        Route("/fleet/gateways", list_gateways, methods=["GET"]),
        Route("/fleet/events", fleet_events, methods=["GET"]),
        Route("/fleet/incidents", fleet_incidents, methods=["GET"]),
        Route("/fleet/mode", fleet_mode_router, methods=["GET", "POST"]),
        Route("/fleet/mode/{gateway_id}", fleet_mode_gateway, methods=["POST"]),
        Route("/fleet/policy/{role}", policy, methods=["GET"]),
    ])
