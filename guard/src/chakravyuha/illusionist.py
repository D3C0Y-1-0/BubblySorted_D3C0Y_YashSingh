"""The Illusionist: builds the decoy bank's content before the demo, never during a request.

    uv run --project guard chakravyuha illusion [--seed 7]

Writes guard/decoy/bank.json. Without GROQ_API_KEY (or if the model fails) it uses the plain
generator in decoy.py. With a key, the model invents customer names, merchants and support
tickets, which are checked and slotted into the same structure, so the decoy answers the same
routes with the same shapes either way. Honeytoken placeholders ({{api_key}}, ...) are placed
by code, never by the model, and are filled per trapped client at serve time.
"""

import argparse
import asyncio
import json
import random
import re
from pathlib import Path
from typing import Any

from .decoy import DATA_FILE, default_dataset, fake_iban
from .llm import LLM

SAFE = re.compile(r"[^\w .,'&()\-:/!?€]")


def clean(value: Any, limit: int = 80) -> str:
    """Model output is untrusted too: plain short text only, no placeholders or markup."""
    return SAFE.sub("", str(value)).replace("{", "").replace("}", "").strip()[:limit]


def merge(dataset: dict[str, Any], invented: dict[str, Any], seed: int) -> dict[str, Any]:
    rng = random.Random(seed)
    names = [clean(n, 40) for n in invented.get("customers", []) if clean(n, 40)][:12]
    for customer, name in zip(dataset["customers"], names, strict=False):
        customer["name"] = name
        customer["account"] = fake_iban(rng)
    merchants = [clean(m, 40) for m in invented.get("merchants", []) if clean(m, 40)]
    history = dataset["services"]["transaction"]["routes"]["GET /transactions"]["body"]
    for row in history["transactions"]:
        if merchants and "to" in row:
            row["to"] = rng.choice(merchants)
            row["memo"] = f"Card payment {row['to']}"
    tickets = invented.get("tickets", [])
    if isinstance(tickets, list) and tickets:
        dataset["tickets"] = [
            {"subject": clean(t.get("subject", ""), 80), "body": clean(t.get("body", ""), 400)}
            for t in tickets[:8]
            if isinstance(t, dict)
        ]
    return dataset


async def build(seed: int, llm: LLM | None = None) -> tuple[dict[str, Any], str]:
    dataset = default_dataset(seed)
    llm = llm or LLM()
    if not llm.enabled:
        return dataset, "rules"
    answer = await llm.json(
        "You write believable fake data for a demo bank's decoy. Reply with one JSON object: "
        '{"customers": [12 full names], "merchants": [10 shop names], "tickets": '
        '[{"subject": ..., "body": ...} x 5 everyday support tickets]}. No real people.',
        "Generate the data for a German retail bank.",
    )
    await llm.aclose()
    if not answer:
        return dataset, "rules (the model did not answer)"
    return merge(dataset, answer, seed), "ai"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="chakravyuha illusion", description=__doc__)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--out", type=Path, default=DATA_FILE)
    args = parser.parse_args(argv)
    dataset, how = asyncio.run(build(args.seed))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(dataset, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"illusionist: wrote {args.out} ({how})")
    return 0
