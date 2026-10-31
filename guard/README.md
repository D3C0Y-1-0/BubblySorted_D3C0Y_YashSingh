# Hedwig Chakravyuha (Guard)

Runtime protection for the demo bank, as described in `chakravyuhaPLAN.md` (based on
`plan/guardPLAN.md`).

This is a secondary track. Everything for it lives in this folder: code, tests, deploy
files and the demo bank. It does not edit anything outside `guard/`.

```sh
uv run --project guard chakravyuha            # Guard on :8080, dashboard on 127.0.0.1:8090
uv run --project guard python guard/tools/stub_bank.py   # stand-in bank on :9001 until B1
uv run --project guard pytest guard/tests     # tests
```

Everything runs on one machine and listens on `127.0.0.1` only. The browser on the laptop is
the real user (`127.0.0.1`, allowlisted); attack scripts send from `127.0.0.2` and up.

Environment (or `guard/.env`): `CHAKRA_TOKEN` (events endpoint and dashboard controls),
`CHAKRA_SECRET` (optional; otherwise a key is kept in `guard/data/secret.key`).

Ring 3 (challenge): a client without a valid `hw_session` cookie gets `403` with a proof-of-work
puzzle (an HTML page that solves it for browsers; JSON plus the `X-Hedwig-Challenge` and
`X-Hedwig-Difficulty` headers for scripts). Find a nonce so `sha256(token + ":" + nonce)` starts
with that many zero bits and `POST /__hedwig/challenge` `{"token", "nonce"}` to get a cookie
bound to your IP (`chakravyuha.challenge.solve` does it in Python). A service with
`challenge: false` skips the puzzle and needs `X-API-Key` (or a bearer token) matching the
environment variable named by its `api_key_env`.
