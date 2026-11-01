# Chakravyuha — quick guide

A demo "bank" with a guard in front of it. Attackers have to pass **seven rings** to get in;
the ones that are clearly attacking get pulled into a **fake bank (the decoy)** and watched.
Everything runs on this one laptop.

---

## 1. Run it

Two separate things have to be running: the **bank** (in Docker) and the **Guard** in front of
it (on your machine). Start them in this order, from the repo root:

```bash
# 1. start the bank + ELK (Docker), on 127.0.0.1 only.
#    First run builds the images, so it takes a few minutes. Drop --build on later runs.
docker compose -f guard/deploy/docker-compose.yml up -d --build

# 2. start the Guard and its dashboard (runs on your machine, not in Docker)
uv run --project guard chakravyuha
```

Leave the Guard running in that terminal. If you only start one of the two, see "If it breaks".

Then open in a browser:

| URL | What |
|---|---|
| http://127.0.0.1:8080 | **The bank** (what a user sees). Sign in with `demo` / `demo-pass` |
| http://127.0.0.1:8090 | **The live dashboard** — the seven rings and every attacker as a dot |
| http://127.0.0.1:15601 | **Kibana** — search the full history (dashboard: "Hedwig Chakravyuha") |

Every Docker port is published on `127.0.0.1` in the **1xxxx range** on purpose, so nothing here clashes
with what other projects keep on 8080, 5432, 6379 or 9200. Bank services: 19100 (web) and
19101 to 19104. Postgres 15432, Redis 16379, Qdrant 16333, Elasticsearch 19200, Logstash 15000
(API 19600), Kibana 15601. Only the Guard (8080) and its dashboard (8090) run on your machine.

Stop everything:

```bash
# Ctrl-C the chakravyuha process, then:
docker compose -f guard/deploy/docker-compose.yml down
```

---

## 2. What to do

1. **Be a normal user.** Open http://127.0.0.1:8080, sign in. Your browser quietly solves a
   puzzle (ring 3) and sails through to the bank. On the dashboard your dot reaches the centre.
2. **Attack it.** Run the scripts in `guard/tools/attacks/` (each pretends to be a different
   attacker from its own address) and watch the dashboard react:

   ```bash
   uv run --project guard python guard/tools/attacks/scanner.py       # pokes at /admin, /.env ...
   uv run --project guard python guard/tools/attacks/bruteforce.py    # guesses the password
   uv run --project guard python guard/tools/attacks/distributed.py   # many IPs at once
   ```
3. **Watch.** The dashboard shows dots stopping on the ring that caught them, the alert level
   rising, campaigns the Scout named, and a red banner if a honeytoken is used.
4. **Reset** to a clean slate (empties logs, clears traps/bans; restart the Guard after):

   ```bash
   uv run --project guard python guard/tools/demo_reset.py
   ```

> The browser at `127.0.0.1` is on the allowlist — it is never trapped or banned, so you can
> keep using the bank while attacks run. Attackers use other addresses (`127.0.0.2`, `.3`, …).

---

## 3. The layers, in plain terms

**The bank** (`guard/bank/`) — four small services with fake money: `transaction` (payments),
`account`, `support`, `notifications`, plus the `web` home page. Each one is deliberately built
with a known-vulnerable library so Hedwig has something to find.

**The Guard** (the seven rings) — every request passes all seven, every time:

| Ring | Name | In one line |
|---|---|---|
| 1 | Gate | Is this address banned or already trapped? |
| 2 | Flood | Too many requests too fast → slow them down, then block |
| 3 | Challenge | Solve a quick puzzle to prove you're a real browser |
| 4 | Route | Only real pages exist; poking at `/admin`, `/.env` is scored |
| 5 | Login | Too many failed logins → trip and trap |
| 6 | Inspection | Scan for attack payloads (e.g. Log4Shell), bad uploads, phishing |
| 7 | Maze | The **decoy bank** — trapped attackers end up here |

Each ring adds **suspicion points**. Enough points and you get slowed, then trapped. A clear
attack (an attack payload, a brute-force trip) traps you at once.

**The decoy (ring 7)** — a fake bank that looks real. A trapped attacker keeps "using the bank"
but every answer is fake, so they waste time while we watch. Planted fake credentials
(**honeytokens**) sit inside it; if anyone ever uses one, that's a certain break-in — the alarm
fires and every linked address is banned.

**The agents** (run every few seconds, off to the side):
- **Scout** — spots patterns one address can't show, e.g. 500 different IPs each trying the same
  username once, and names it a "campaign".
- **Commander** — raises the alert level (`calm → alert → siege`), which tightens every ring.
- **Illusionist** — builds the fake bank's contents before the demo.

They work on plain rules by default; with a Groq API key they also explain decisions in words.

**ELK** (Elasticsearch, Logstash, Kibana) — the record keeper. Every decision is shipped off and
stored so you can search the whole attack afterwards in Kibana. If it's down, the Guard doesn't
even slow down.

**The dashboard** — the live picture: the rings, a dot per client coloured by suspicion, the
numbers, the campaigns, the agent feed, and honeytoken alarms.

**Hedwig link** — when ring 6 catches an attack, it writes a line into that service's log, so
`hedwig scan guard/bank` then reports that service as actually attacked.

---

## 4. If it breaks

The bank (Docker) and the Guard (native) are separate, so you need **both** up. The error tells
you which one is missing:

| What you see at :8080 | Meaning | Fix |
|---|---|---|
| **502 Bad Gateway** | Guard is up, but the bank behind it is down | `docker compose -f guard/deploy/docker-compose.yml up -d` |
| **Can't connect / refused** | the Guard itself isn't running | `uv run --project guard chakravyuha` |
| **403 with a "checking your browser" page** | normal — ring 3 is solving its puzzle | wait a moment; it passes on its own |

Check what's running:

```bash
docker compose -f guard/deploy/docker-compose.yml ps   # the bank containers
curl http://127.0.0.1:8080/__hedwig/health             # the Guard (200 = up)
```

Start the bank, wait until the containers are healthy, then start the Guard.
