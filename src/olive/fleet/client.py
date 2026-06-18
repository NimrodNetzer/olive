"""Fleet client — gateway-to-control-plane HTTP integration (ADR-0024).

Fire-and-forget event push, heartbeat with mode piggyback, and policy fetch
with local-disk fallback. All three paths share one httpx.AsyncClient but are
independent: a push failure never blocks the heartbeat.

The event push queue is drop-on-full: a slow or unavailable control plane
never stalls the gateway fast path. Dropped entries are counted (not silently
lost) to keep them observable (CLAUDE.md rule 4 spirit).

http:// URLs are rejected unless `allow_insecure=True` (fail-closed, ADR-0024 §3).
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

import httpx

_log = logging.getLogger(__name__)

_MAX_PUSH_BATCH = 50
_PUSH_LOOP_INTERVAL = 2.0  # seconds between push drain attempts


class FleetClientError(Exception):
    """Configuration error (e.g. http:// without allow_insecure)."""


class FleetClient:
    """Async HTTP client for gateway → control-plane communication."""

    def __init__(
        self,
        base_url: str,
        gateway_id: str,
        org_id: str,
        token: str,
        max_queue_size: int = 500,
        allow_insecure: bool = False,
    ) -> None:
        if base_url.startswith("http://") and not allow_insecure:
            raise FleetClientError(
                f"Fleet client refuses plaintext URL {base_url!r}. "
                "Use https:// or pass allow_insecure=True explicitly."
            )
        self.gateway_id = gateway_id
        self.org_id = org_id
        self._base_url = base_url.rstrip("/")
        self._headers = {
            "Authorization": f"Bearer {token}",
            "X-Gateway-ID": gateway_id,
            "X-Org-ID": org_id,
        }
        self._queue: asyncio.Queue[dict] = asyncio.Queue(maxsize=max_queue_size)
        self.dropped = 0  # observable: drops counted, not silently lost
        self._push_task: asyncio.Task | None = None
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            headers=self._headers,
            timeout=httpx.Timeout(5.0),
            verify=not allow_insecure,
        )

    async def open(self) -> None:
        """Start the background push drain loop."""
        self._push_task = asyncio.ensure_future(self._push_loop())

    async def close(self) -> None:
        """Cancel the push loop and close the HTTP client."""
        if self._push_task is not None:
            self._push_task.cancel()
            try:
                await self._push_task
            except asyncio.CancelledError:
                pass
        await self._client.aclose()

    def enqueue_event(self, summary: dict) -> None:
        """Drop-on-full: never blocks. summary must contain no raw payloads (rule 3)."""
        try:
            self._queue.put_nowait({"_kind": "event", **summary})
        except asyncio.QueueFull:
            self.dropped += 1
            _log.warning("fleet event queue full — dropped (total=%d)", self.dropped)

    def enqueue_incident(self, summary: dict) -> None:
        """Drop-on-full: never blocks. summary must contain no raw payloads (rule 3)."""
        try:
            self._queue.put_nowait({"_kind": "incident", **summary})
        except asyncio.QueueFull:
            self.dropped += 1
            _log.warning("fleet incident queue full — dropped (total=%d)", self.dropped)

    async def heartbeat(self, current_mode: str) -> str | None:
        """POST /fleet/heartbeat with the current operating mode.

        Returns the `commanded_mode` string if the control plane wants to change
        the mode, else None. Raises on any network or protocol error so the
        caller can count consecutive failures (ADR-0024 §2).
        """
        payload = {
            "gateway_id": self.gateway_id,
            "org_id": self.org_id,
            "current_mode": current_mode,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        resp = await self._client.post("/fleet/heartbeat", json=payload)
        resp.raise_for_status()
        data = resp.json()
        commanded = data.get("commanded_mode")
        return commanded if commanded and commanded != current_mode else None

    async def fetch_policy(self, role: str) -> str | None:
        """GET /fleet/policy/{role}. Returns YAML string or None on any failure."""
        try:
            resp = await self._client.get(f"/fleet/policy/{role}")
            resp.raise_for_status()
            return resp.text
        except Exception as exc:  # noqa: BLE001
            _log.warning("fleet policy fetch for role=%r failed: %s", role, exc)
            return None

    async def _push_loop(self) -> None:
        """Background drain: batch up to _MAX_PUSH_BATCH items from the queue and
        POST them. Failures are logged and items are discarded (not re-queued) to
        avoid unbounded memory growth on a persistently unreachable control plane."""
        while True:
            await asyncio.sleep(_PUSH_LOOP_INTERVAL)
            if self._queue.empty():
                continue
            batch: list[dict] = []
            while not self._queue.empty() and len(batch) < _MAX_PUSH_BATCH:
                batch.append(self._queue.get_nowait())
            events = [i for i in batch if i.get("_kind") == "event"]
            incidents = [i for i in batch if i.get("_kind") == "incident"]
            try:
                resp = await self._client.post(
                    "/fleet/push", json={"events": events, "incidents": incidents}
                )
                resp.raise_for_status()
            except Exception as exc:  # noqa: BLE001
                _log.warning(
                    "fleet push failed for batch of %d item(s): %s", len(batch), exc
                )
