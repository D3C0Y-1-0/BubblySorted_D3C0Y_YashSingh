# Hedwig Guard: runtime protection for the demo bank (local, over the hotspot, with ELK)

Status: planned, not started. Being built in parallel to the main Hedwig phases.

## Why this exists
Our mentor wants Hedwig to **prevent phishing, DDoS, brute force and malware on the deployed services**, not only scan their code. Today Hedwig finds weaknesses in dependencies and decides what to do about them. It has no runtime defence. The Guard adds one: it sits in front of the bank services, blocks attacks as they arrive, records every attack in ELK, and reports each blocked incident to the project manager.

It feeds the rest of Hedwig. Every attack the Guard sees can be written in the form Hedwig's evidence ladder already reads (level 3 for an attack attempt, level 4 for signs of compromise), so a service under real attack ranks higher and can be taken down when its policy allows.

The Guard is independent of the fixing pipeline (Phase 3 in `plan/claudesPLAN.md`). It can be built now, in parallel.

## Where it runs: locally, reachable from the tablet over the hotspot
The bank runs on the demo laptop with Docker Compose, not on Render. The laptop and the tablet are both on the phone hotspot, and the tablet browses `http://<laptop hotspot IP>:8080`. Only the Guard's port is exposed on the hotspot. The bank services sit on an internal Compose network that only the Guard can reach.

## How it fits the repo (read this first)
Done and released so far: the CLI and interactive app, `init`, `scan`, `status`, `explain`, `replay`, `simulate-attack`, risk scoring, tree-sitter reachability, the evidence ladder and the policy gate (Phases 0 to 2). Still to come on the main track: the multi-agent fixer, reports and dashboard, GitHub App, takedown, Claude plugin and the bank.

**Keep the Guard in its own files** so the two tracks do not collide:
- New package `src/hedwig/guard/` and new `src/hedwig/cli/guard_cmd.py`.
- New `deploy/guard/` (Guard Dockerfile), `deploy/docker-compose.yml` and `deploy/elk/` (Logstash pipeline, index template, Kibana dashboard).
- New tests in `tests/guard/`.

**Shared files, edit as little as possible** (rebase often, these are where conflicts happen):
| File | What the Guard adds |
|---|---|
| `src/hedwig/cli/main.py` | two lines: import `guard_cmd` and call `guard_cmd.register(app)`, the same way `scan_cmd.register(app)` works |
| `src/hedwig/cli/shell.py` | handlers and `COMMANDS` entries for `/guard-sync`, `/feeds`, `/watch-domains` and `/elk-detect`. The `guard` server itself is not an app command because it is long-running |
| `src/hedwig/settings.py` | new keys in `KEYS`: `abuse_ch_key`, `guard_token`, `smtp_host`, `smtp_port`. `smtp_user`, `smtp_pass` and `pm_email` already exist. Environment variables override the file |
| `pyproject.toml` | an optional extra `guard = ["starlette", "uvicorn"]`. The CLI install stays light. Do not change the version; release bumps are done by whoever releases |
| `README.md` | a short Guard section |

**Do not touch `src/hedwig/ui/*`** (the UI team owns it).

**Existing code to reuse:**
- `src/hedwig/core/evidence.py`: `RULES` holds the attack patterns (JNDI, JWT alg none, YAML tags, path traversal, prototype pollution), `COMPROMISE` the compromise markers, and `write_attack` shows the access-log line format that `read_log` understands. The Guard blocks the same patterns, and `guard-sync` writes lines in that shape.
- `src/hedwig/config.py` (`load_project` reads `.hedwig.yml`) and `engine.resolve_services`. Both ignore unknown keys, so the new `guard:` blocks in `.hedwig.yml` are safe.
- `src/hedwig/settings.py` for keys and environment overrides.
- `httpx` is already a dependency.

**Conventions:** Python 3.12, `uv`, `ruff` (line length 100). Tests are minimal on purpose: only where the system could fail or what we present, as few as possible. Pushes to `main` run CI. A push to the `release` branch publishes a GitHub Release, so work on a branch and merge by pull request.

## Decisions
From the team's answers:
- **Gateway in front.** One Python service, the Guard, is the only entry point. The bank services are not published, so only the Guard can reach them. One codebase protects Java, Rust, PHP and Node services alike.
- **Local deployment on the hotspot** (see above), not Render.
- **Phishing:** request and response checks, plus threat-feed URL blocking, plus a lookalike-domain watch.
- **Malware:** upload and payload inspection, plus known-bad file hashes. No file-integrity watch (that needs a sidecar inside each container).
- **Block by default, then report to the PM.** A per-service `mode: monitor` turns blocking off.
- **Full ELK, including Logstash.** Guard to Logstash to Elasticsearch, with Kibana for dashboards.
- **The Guard blocks instantly, ELK adds more** (next section).

## What "immediately" can honestly mean
- **The Guard blocks in milliseconds.** It counts failed logins per IP in memory and bans the IP on the 8th failure. For 500 passwords from one IP, 8 reach the app and 492 get a 403 without reaching it.
- **ELK cannot block that fast.** Kibana alert rules run at most once a minute by default. A small detector querying Elasticsearch every 3 seconds is the fastest practical option: events appear in Elasticsearch about 1 to 2 seconds after the Guard emits them, so a pattern is caught roughly 3 to 5 seconds after it crosses a threshold.
- **ELK's real value is what the Guard cannot see:** one account attacked with 500 passwords from 500 different IPs, one attempt each. No per-IP counter ever trips. ELK sees all of them together and tells the Guard to ban the IPs and throttle that account.
- Logstash, Kibana and the dashboards also give the mentor a visible, searchable record of every attack.

## How it works
```
tablet / attacker --hotspot--> [Guard :8080] --> transaction, account, support, notifications (internal only)
                                  |  events (TCP json_lines)         ^
                                  v                                  | POST /__hedwig/ban
                              [Logstash] --> [Elasticsearch] <-- [detector, every 3 s]
                                                   ^
                                               [Kibana :5601]  (laptop screen only)
```
- The Guard is built on Starlette, uvicorn and httpx.
- Routing is by path prefix, one per service: `/transaction/...` goes to the service named `transaction`. Upstream addresses come from environment variables set in `docker-compose.yml`, for example `HEDWIG_UPSTREAM_TRANSACTION=http://transaction:8080`.
- **Client IP:** the connection address. No proxy sits in front, so `X-Forwarded-For` is ignored unless trusted proxies are configured. On Linux, Docker keeps real client IPs. Docker Desktop on Mac or Windows hides them, so there the Guard must run natively on the host.
- Fail open: if a rule crashes, the request goes through and a `guard-error` event is recorded. Availability beats a false block.
- Responses are streamed. Only HTML responses up to 512 KB are buffered for inspection. Request bodies up to 10 MB are buffered for inspection, and larger ones get 413.
- **Elasticsearch and Kibana are bound to 127.0.0.1 only.** A local demo setup has no login on them, so they must not be reachable from the hotspot.
- **Resources:** about 4 GB of RAM for the stack (Elasticsearch heap 1 GB, Logstash 512 MB). On Linux, `vm.max_map_count=262144` must be set for Elasticsearch. Pin one Elastic version for all three components (verify the current one when building).

## Config (`.hedwig.yml`)
Everything has safe defaults, so no config is needed to start. Overrides:
```yaml
guard:                          # top level
  mode: block                   # block | monitor
  domains: [bank.example]       # brands to watch for lookalikes
services:
  transaction:
    guard:
      rate: 20                  # requests per second per IP, burst 2x
      login_paths: [/login]
      redirect_hosts: [bank.example]
      uploads: false            # or a list of allowed extensions
```
Connection settings for ELK come from environment variables (set by Compose): `HEDWIG_LOGSTASH` (host:port), `HEDWIG_ELASTIC_URL`, and `HEDWIG_GUARD_TOKEN` for the ban endpoint.

## Default rules
| Threat | Rule | Action |
|---|---|---|
| DDoS (layer 7) | per-IP token bucket (default 20 req/s); a global in-flight cap; "under attack" mode halves limits when total traffic jumps; slow-request and header-size limits; health path excluded | 429, repeated offenders banned 5 min (403) |
| Brute force | 8 responses of 401 or 403 from one IP on a login path within 60 s; a success resets the count | ban 5 min |
| Phishing: open redirect | a `next`/`redirect`/`url`/`return`... parameter holding an absolute or `//` URL to a host not allowed; also a 30x `Location` to a foreign host | 403 |
| Phishing: injected form | HTML response containing a password field in a form that posts to a foreign host | response replaced by 502 |
| Phishing: clickjacking | add `X-Frame-Options` and `frame-ancestors` headers if missing | headers added |
| Phishing: feed URLs | request carries a URL from the phishing/malware feeds | 403 |
| Malware: uploads | file extensions not allowed, executable magic bytes (MZ, ELF), the EICAR test string, webshell code (`eval(base64_decode`, `Runtime.getRuntime().exec`, `cmd.exe /c`...) | 403 |
| Malware: hashes | SHA-256 of an uploaded file in the local blocklist or the MalwareBazaar feed (the blocklist ships with the EICAR hash for demos) | 403 |
| Malware: injected script | obfuscated inline script in an HTML response (`eval(atob(`, `document.write(unescape(`) | response replaced by 502 |
| Attack payloads | the patterns Hedwig already uses for evidence (`${jndi:`, path traversal, `__proto__`, JWT `alg:none`, YAML object tags), reused from `core/evidence.py` | 403 |
| Lookalike domains | typo, homoglyph, hyphen and TLD variants of each watched domain that resolve in DNS, with a page check for password forms | reported (cannot be blocked from here) |

## Events
Every event is one JSON object in Elastic Common Schema style:
| Field | Meaning |
|---|---|
| `@timestamp` | when |
| `source.ip` | client address |
| `url.path`, `http.request.method`, `http.response.status_code` | the request and its answer |
| `service` | which bank service the prefix routes to |
| `event.category` | `ddos`, `bruteforce`, `phishing`, `malware` or `lookalike` |
| `event.action` | `login_failed`, `blocked`, `ban`, `flagged` or `guard-error` |
| `rule` | which rule fired |
| `user.name` | the username attempted on a login path |
| `hedwig.password_fp` | a short keyed hash of the password tried, so ELK can count distinct passwords. **The password itself is never logged** |

Events go to stdout as JSON, into a 1,000-entry ring buffer served at `GET /__hedwig/events` (bearer token), to the ELK shipper, and to the PM notifier.

## ELK pipeline
- **Shipper:** a background queue in the Guard sends events to Logstash over TCP (json_lines). A slow or stopped Logstash never delays a request. The queue holds 10,000 events, drops the oldest, and counts the drops.
- **Logstash:** a `tcp` input, then filters that parse the user agent (tablet vs a script), add GeoIP for public addresses only, drop anything sensitive and tag the dataset. It writes to `hedwig-guard-YYYY.MM.DD` through an index template that types `source.ip` as `ip` and the other fields as keywords.
- **Kibana:** a dashboard committed as `deploy/elk/kibana/dashboard.ndjson`, imported automatically by a setup container. Panels: attempts over time, allowed vs blocked, distinct passwords tried, top source IPs, bans timeline, and a breakdown by category.
- **Detector:** a background task in the Guard (also runnable as `hedwig elk-detect`) queries Elasticsearch every 3 seconds. When a rule fires it calls the Guard's `POST /__hedwig/ban` (bearer token) with the IPs, a duration and a reason.

### Detector rules
| Rule | Fires when, in the last 60 s | Action |
|---|---|---|
| Distributed brute force | 30 or more failed logins for one `user.name` from 10 or more distinct IPs | ban those IPs for 15 min and throttle that username to 1 attempt per 10 s for 5 min |
| Password spraying | one `password_fp` tried against 15 or more usernames from 3 or more IPs | ban those IPs for 15 min |

Throttling an account can slow a real user down while it is under attack. It is a throttle, not a lockout, and the numbers are configurable.

### Demo-only switch
To test the distributed case from one laptop, the Guard accepts an `X-Hedwig-Test-IP` header as the client IP **only** when `HEDWIG_GUARD_DEMO=1`. It is off by default and must never be on when real users are connected.

## Reporting to the PM
- **Notifier:** the first unreported event starts a 30-second timer, then one digest email goes out and a 5-minute cool-down starts. A flood of 10,000 blocks therefore sends one email, not 10,000. The digest lists counts by category and rule, top IPs, the time range, what was banned and until when, next steps, and a link to the Kibana dashboard for that time range.
- **Transport:** SMTP through the existing settings (`smtp_user`, `smtp_pass`, plus new `smtp_host` and `smtp_port`, default Gmail on 587 with an app password). Failure to send never affects proxying.
- **Recipient:** `pm_email` (default `yash1812ys@gmail.com`).
- **PDF:** the LaTeX/PDF report is Phase 4 of the main plan and `tectonic` is too heavy for the Guard image. The Guard sends an HTML digest now. `hedwig report` builds the PDF from pulled events once Phase 4 exists.

## Build phases
| Phase | What | Done when |
|---|---|---|
| G1 | Proxy core: config loading, routing, client IP, security headers, event model and sinks (stdout, ring buffer), `/__hedwig/health`, `/__hedwig/events` (bearer token), `hedwig guard` command, `deploy/guard/Dockerfile` | The Guard proxies GET, POST, streaming and large bodies to a stub upstream unchanged. The health path is not rate limited. The events endpoint refuses a wrong token. |
| G2 | DDoS and brute-force rules, and login events with `user.name` and `hedwig.password_fp` | One IP flooding gets 429s, then a ban, while a second IP is unaffected. Traffic under the limit is never blocked. Ten failed logins ban the IP, and a successful login resets the count. No password appears in any event. |
| G3 | Phishing request/response checks and feed URLs (`hedwig feeds update`, cached like advisories) | An open-redirect request, a foreign-host `Location`, and an injected password form are each blocked. The headers are added. A feed URL is blocked offline using bundled sample entries. |
| G4 | Malware: uploads, hashes, scripts and payload patterns | An EICAR upload, a webshell upload, an `.exe` upload and a `${jndi:` request are each blocked. A clean upload passes. A hash on the blocklist is blocked. |
| G5 | Lookalike-domain watch: permutation generator, DNS and page check, a background task in the Guard, and `hedwig watch-domains <domain>` | For a test domain the generator makes the expected variants. A mocked DNS answer for a variant with a password form is reported. The task survives a DNS failure. |
| G6 | PM digest over SMTP | A burst of 500 blocks sends exactly one email. The digest contains the counts, top IPs and the Kibana link. An email failure leaves proxying working. |
| G7 | Hedwig link: `hedwig guard-sync <url> --token ...` pulls events into the service's log, so `scan`, `status` and the decision see attack evidence | After attacks through the Guard, `hedwig status` shows evidence 3 for that service. |
| G8 | Local stack: `deploy/docker-compose.yml` (Guard, a stub login service until the bank exists, Elasticsearch, Logstash, Kibana), `make demo-up`, and `make demo-ip` which prints the tablet URL | `make demo-up` brings everything up. The tablet on the hotspot loads the page through the Guard. Elasticsearch and Kibana answer on the laptop but not on the hotspot address. |
| G9 | ELK pipeline: the Guard's shipper, the index template, the Logstash pipeline, the Kibana dashboard import and `POST /__hedwig/ban` | Guard events appear in Kibana within 3 seconds. Stopping Logstash does not slow or break requests, and the drop counter rises. `/__hedwig/ban` refuses a wrong token. |
| G10 | Detector and the two rules, plus the demo-only test-IP header | The test case below passes. |

Suggested order: G1, G2, G6, G3, G4, G5, G8, G9, G10, G7. G6 early makes a first visible result: attack, block, email.

Note for G7: only payload attacks map to evidence lines (they match `evidence.RULES`). Rate-limit and brute-force events do not have an evidence rule today, so they appear in the digest and in Kibana but not in the evidence level unless a rule is added to `core/evidence.py`.

## Test case: "someone tries to login using 500 different passwords"
- **Single IP, 500 passwords:** the Guard bans the IP on the 8th failure (well under 1 second). 8 attempts reach the app and 492 get 403. Kibana shows 500 events, 8 allowed and 492 blocked, the ban event, and 500 distinct password fingerprints, all within about 5 seconds of the burst. A PM digest arrives.
- **Distributed, 500 passwords from 500 IPs, one attempt each:** no Guard counter trips. The detector rule fires within about 5 seconds of crossing 30 failures from 10 IPs, bans the IPs seen, throttles the account, and later attempts are blocked.
- **The tablet keeps working during both attacks:** it can still load the bank page and log in with the demo user from its own IP.

The bank needs a `POST /login` on the transaction service for this (fake users only: 401 for a bad password, 200 for the demo user). Until the bank exists, the stub login service in Compose provides it.

## Files
New package `src/hedwig/guard/`:
- `app.py`: the ASGI proxy
- `config.py`: guard settings from `.hedwig.yml` and the environment
- `limits.py`: rate limiting, bans, brute force, account throttle
- `phishing.py`, `malware.py`: the rules above
- `events.py`: event model, ring buffer, sinks
- `shipper.py`: the Logstash queue
- `detector.py`: the Elasticsearch queries and rules
- `notify.py`: the digest and SMTP
- `feeds.py`: feed download and cache
- `lookalike.py`: domain variants and checks

New `src/hedwig/cli/guard_cmd.py` with `guard`, `guard-sync`, `feeds update`, `watch-domains` and `elk-detect`.

New `deploy/docker-compose.yml`, `deploy/guard/Dockerfile`, `deploy/elk/` (Logstash pipeline, index template, Kibana dashboard and setup script).

## Out of scope
- Volumetric network floods, Cloudflare or WAF integration, TLS inspection.
- File-integrity watching and process monitoring (needs a sidecar).
- Counters shared across several Guard instances.
- Automatic domain takedown requests (the report names the registrar and the next steps).
- The PDF report (Phase 4).
- Kibana alert rules (they run at most once a minute, so the detector does this job).

## Verification
- **Minimal tests (about 10):** rate limit then ban, brute-force count reset, no password in any event, open redirect, injected form, EICAR and webshell upload, digest sends once, lookalike variants, detector rule A on canned Elasticsearch results, and a fail-open check. All run against a small stub upstream, offline, with DNS, email and Elasticsearch mocked.
- **Use cases on the local stack:**
  1. a flood from one IP while a second IP keeps working
  2. the 500-password test case, single IP, then distributed
  3. an open redirect and an upload with the EICAR file
  4. a `${jndi:` request, then `hedwig status` showing evidence 3
  5. the PM digest email arriving after a burst
- **Rehearsal:** repeat use cases 1 and 2 with the tablet on the hotspot as the legitimate user.

## Consequences for the main plan (not applied yet)
Moving the demo off Render affects `plan/claudesPLAN.md`, and nobody has edited it for this yet:
- **Phase 6:** the "Render executor" becomes a local Docker executor. Takedown is `docker compose stop <service>`, resume is start, deploy and rollback recreate the container from a tagged image.
- **Phase 5:** GitHub Actions cannot reach a laptop behind a hotspot, so workflows that act on the bank need a **self-hosted runner on the laptop**. The terminal-first flow already runs locally.
- **Phase 8 and `docs/bank-contract.md`:** replace "deployed on Render" with "runs with `docker compose up` and is reachable from the tablet on the hotspot through the Guard only", and add `POST /login` on the transaction service.

## Needed before building
- A laptop with Docker and at least 8 GB RAM free, with `vm.max_map_count=262144` set (Linux).
- A Gmail app password for the PM email (the `smtp_user` and `smtp_pass` settings), unless the team prefers another provider.
- A rehearsal check that the tablet can reach the laptop's hotspot IP (some hotspots isolate devices from each other).
- A free abuse.ch Auth-Key (optional, for the hash and URL feeds).
- The domain to watch for lookalikes (for the demo, any domain the team controls).

## Appendix: if we deploy on Render later
Facts checked in the docs, kept for later:
- **Private services** have no public URL and are reachable only by other services in the same region and workspace. A blueprint wires them with `fromService` and `property: hostport`.
- **DDoS:** Render's edge stops network-level (layer 3/4) floods. Application-level abuse still reaches the app, and Render has no rate-limit setting.
- **Client IP:** the leftmost `X-Forwarded-For` value can be forged. Trust `CF-Connecting-IP` instead, and confirm which headers arrive on first deploy.
- **Email:** Render blocks outbound SMTP (port 25 everywhere, and 25/465/587 on free web services), so use an HTTPS email API.
- **Several instances** each keep their own counters, so a shared store (Render Key Value) would be needed.

## Sources
- Render private networking: https://render.com/docs/private-network
- How Render handles DDoS attacks: https://render.com/articles/how-render-handles-ddos-attacks
- Client IP on Render (community thread): https://community.render.com/t/accessing-client-ips-in-a-node-express-app/36282
- Render blocks SMTP ports: https://render.com/changelog/free-web-services-will-no-longer-allow-outbound-traffic-to-smtp-ports
- Render log streams (syslog over TLS): https://render.com/docs/log-streams
- Kibana alerting minimum schedule interval: https://www.elastic.co/docs/deploy-manage/production-guidance/kibana-alerting-production-considerations
- OpenPhish community feed terms: https://github.com/openphish/public_feed
