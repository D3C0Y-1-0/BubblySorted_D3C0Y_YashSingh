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


class AgentError(Exception):
    """The model call failed or its answer did not match the schema. Counts as a failed attempt."""


def _json_object(text: str) -> dict:
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S).strip()
    fenced = re.match(r"^```(?:json)?\s*(.*?)\s*```$", text, flags=re.S)
    return json.loads(fenced.group(1) if fenced else text)


def chat[T: BaseModel](root: Path, agent: str, system: str, user: str, schema: type[T]) -> T:
    key = settings.get("groq_api_key")
    if not key:
        raise AgentError("groq_api_key is not set, run: hedwig config")
    model = settings.get("model")
    body = {
        "model": model,
        "temperature": 0,
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
        response = httpx.post(
            GROQ_URL, json=body, headers={"Authorization": f"Bearer {key}"}, timeout=TIMEOUT
        )
        response.raise_for_status()
        data = response.json()
        usage = data.get("usage") or {}
        return schema.model_validate(_json_object(data["choices"][0]["message"]["content"]))
    except httpx.HTTPStatusError as err:
        status = f"http {err.response.status_code}"
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
