"""A stand-in for the transaction service until the real bank exists (phase B1).

Run: uv run --project guard python guard/tools/stub_bank.py   (listens on 127.0.0.1:9001)
Demo user: demo / demo-pass. Fake data only.
"""

import asyncio
import json

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, StreamingResponse
from starlette.routing import Route


async def login(request: Request) -> JSONResponse:
    body = await request.body()
    try:
        data = json.loads(body) if body else {}
    except ValueError:
        data = {}
    if data.get("username") == "demo" and data.get("password") == "demo-pass":
        return JSONResponse({"ok": True, "user": "demo"})
    return JSONResponse({"ok": False, "error": "invalid credentials"}, 401)


async def balance(request: Request) -> JSONResponse:
    return JSONResponse({"account": "DE00 0000 0000 0042", "balance": 1234.56, "currency": "EUR"})


async def stream(request: Request) -> StreamingResponse:
    async def chunks():
        for i in range(5):
            yield f"chunk {i}\n".encode()
            await asyncio.sleep(0.5)

    return StreamingResponse(chunks(), media_type="text/plain")


async def echo(request: Request) -> JSONResponse:
    body = await request.body()
    return JSONResponse(
        {
            "method": request.method,
            "path": request.url.path,
            "bytes": len(body),
            "x-forwarded-for": request.headers.get("x-forwarded-for"),
        }
    )


app = Starlette(
    routes=[
        Route("/health", lambda r: JSONResponse({"status": "ok"})),
        Route("/login", login, methods=["POST"]),
        Route("/balance", balance),
        Route("/stream", stream),
        Route("/{path:path}", echo, methods=["GET", "POST", "PUT"]),
    ]
)

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=9001, log_level="warning")
