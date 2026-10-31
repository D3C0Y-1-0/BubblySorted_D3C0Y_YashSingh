"""Where the agents get their view from: Elasticsearch first, the in-memory buffer as fallback.

Elasticsearch sees every event across Guard restarts and over any window. When it is down or
slow (2 s), the agents fall back to the last 1,000 events in the Guard's buffer and the
dashboard says so. Either way the agents get the same event dicts.
"""

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from .config import Elk
from .events import EventBus

TIMEOUT_S = 2.0
MAX_HITS = 5000


class EventSource:
    def __init__(self, bus: EventBus, elk: Elk, client: httpx.AsyncClient | None = None) -> None:
        self.bus = bus
        self.elk = elk
        self._client = client  # created on first use: building one loads an SSL context
        self.status = "off" if not elk.enabled else "offline"  # off | online | offline

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=TIMEOUT_S)
        return self._client

    async def window(
        self, seconds: float, actions: list[str] | None = None
    ) -> tuple[list[dict[str, Any]], str]:
        """Events of the last `seconds`, oldest first, and where they came from."""
        if self.elk.enabled:
            try:
                events = await self._search(seconds, actions)
                self.status = "online"
                return events, "elastic"
            except (httpx.HTTPError, ValueError, KeyError):
                self.status = "offline"
        return self._buffer(seconds, actions), "buffer"

    async def _search(self, seconds: float, actions: list[str] | None) -> list[dict[str, Any]]:
        filters: list[dict] = [{"range": {"@timestamp": {"gte": f"now-{int(seconds)}s"}}}]
        if actions:
            filters.append({"terms": {"event.action": actions}})
        body = {
            "size": MAX_HITS,
            "sort": [{"@timestamp": "asc"}],
            "query": {"bool": {"filter": filters}},
        }
        url = f"{self.elk.elastic_url.rstrip('/')}/{self.elk.index}/_search"
        response = await self.client.post(url, json=body)
        response.raise_for_status()
        return [hit["_source"] for hit in response.json()["hits"]["hits"]]

    def _buffer(self, seconds: float, actions: list[str] | None) -> list[dict[str, Any]]:
        cutoff = (datetime.now(UTC) - timedelta(seconds=seconds)).isoformat(timespec="milliseconds")
        return [
            e
            for e in self.bus.recent()
            if e.get("@timestamp", "") >= cutoff
            and (not actions or e.get("event.action") in actions)
        ]

    async def ping(self) -> str:
        if not self.elk.enabled:
            self.status = "off"
            return self.status
        try:
            response = await self.client.get(self.elk.elastic_url)
            self.status = "online" if response.status_code < 500 else "offline"
        except httpx.HTTPError:
            self.status = "offline"
        return self.status

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
