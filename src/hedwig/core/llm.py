"""Groq client. Every agent is one JSON-only call to the configured Qwen model."""

import json
import re
import time
from pathlib import Path

import httpx
from pydantic import BaseModel, ValidationError

from hedwig import settings
from hedwig.core import audit

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
TIMEOUT = 90
# Groq counts a request's max output against the per-minute budget and refuses one that asks for
# more than the budget ("Request too large"), so every call states a modest limit of its own.
MAX_TOKENS = 900
RATE_RETRIES = 3
MAX_WAIT = 30


class AgentError(Exception):
    """The model call failed or its answer did not match the schema. Counts as a failed attempt."""


def _json_object(text: str) -> dict:
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S).strip()
    fenced = re.match(r"^```(?:json)?\s*(.*?)\s*```$", text, flags=re.S)
    return json.loads(fenced.group(1) if fenced else text)


def _retry_after(response: httpx.Response) -> float:
    try:
        return min(float(response.headers.get("retry-after", "5")), MAX_WAIT)
    except ValueError:
        return 5.0


def chat[T: BaseModel](
    root: Path, agent: str, system: str, user: str, schema: type[T], max_tokens: int = MAX_TOKENS
) -> T:
    key = settings.get("groq_api_key")
    if not key:
        raise AgentError("groq_api_key is not set, run: hedwig config")
    model = settings.get("model")
    body = {
        "model": model,
        "temperature": 0,
        "max_tokens": max_tokens,
        "response_format": {"type": "json_object"},
        "reasoning_format": "hidden",  # "raw" is rejected together with JSON mode
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }
    started = time.monotonic()
    status, usage = "ok", {}
    try:
        for attempt in range(RATE_RETRIES + 1):
            response = httpx.post(
                GROQ_URL, json=body, headers={"Authorization": f"Bearer {key}"}, timeout=TIMEOUT
            )
            if response.status_code != 429 or attempt == RATE_RETRIES:
                break
            time.sleep(_retry_after(response))  # the per-minute budget refills; wait and retry
        response.raise_for_status()
        data = response.json()
        usage = data.get("usage") or {}
        return schema.model_validate(_json_object(data["choices"][0]["message"]["content"]))
    except httpx.HTTPStatusError as err:
        status = f"http {err.response.status_code}"
        if err.response.status_code == 404 and "model" in err.response.text:
            raise AgentError(
                f"Groq has no model '{model}'. Set a valid one: "
                f"hedwig config set model {settings.KEYS['model'].default}"
            ) from err
        raise AgentError(
            f"Groq returned {err.response.status_code}: {err.response.text[:200]}"
        ) from err
    except (httpx.HTTPError, KeyError, IndexError, ValueError, ValidationError) as err:
        status = type(err).__name__
        raise AgentError(f"{agent} gave no usable answer: {err}") from err
    finally:
        audit.record(
            root,
            "agent_call",
            agent=agent,
            model=model,
            seconds=round(time.monotonic() - started, 2),
            tokens=usage.get("total_tokens"),
            status=status,
        )
