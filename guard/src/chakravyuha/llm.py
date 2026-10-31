"""A small Groq client (OpenAI-compatible chat completions) for the agents.

The key comes from GROQ_API_KEY (the same name the main Hedwig settings use) and the model
from CHAKRA_MODEL, else HEDWIG_MODEL, else qwen/qwen3-32b. Every call has a short timeout and
any failure returns None, so the rule versions take over and the demo never waits on it.
"""

import json
import os
import re
from typing import Any

import httpx

URL = "https://api.groq.com/openai/v1/chat/completions"
DEFAULT_MODEL = "qwen/qwen3-32b"
THINK = re.compile(r"<think>.*?</think>", re.S)


class LLM:
    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        client: httpx.AsyncClient | None = None,
        timeout: float = 4.0,
    ) -> None:
        self.api_key = api_key if api_key is not None else os.environ.get("GROQ_API_KEY", "")
        self.model = (
            model or os.environ.get("CHAKRA_MODEL") or os.environ.get("HEDWIG_MODEL")
            or DEFAULT_MODEL
        )  # fmt: skip
        self._client = client
        self.timeout = timeout
        self.last_ok: bool | None = None  # None until the first call

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self.timeout)
        return self._client

    async def json(self, system: str, user: str) -> dict[str, Any] | None:
        """One chat call that must answer a JSON object. None on any failure."""
        if not self.enabled:
            return None
        body = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "temperature": 0.2,
            "max_tokens": 800,
            "response_format": {"type": "json_object"},
        }
        try:
            response = await self.client.post(
                URL, json=body, headers={"authorization": f"Bearer {self.api_key}"}
            )
            response.raise_for_status()
            text = response.json()["choices"][0]["message"]["content"] or ""
            data = json.loads(THINK.sub("", text).strip())
            self.last_ok = isinstance(data, dict)
            return data if isinstance(data, dict) else None
        except (httpx.HTTPError, KeyError, IndexError, ValueError, TypeError):
            self.last_ok = False
            return None

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
