# Hedwig demo script (for the judges)

Everything runs on this one laptop. Four things to show, in this order, about 15 minutes total:

1. **The bank and the dashboard** (2 min): what is running, and what the Guard and Hedwig watch.
2. **A live attack** (5 min): one script runs every attack; the dashboard and the mail show it.
3. **A vulnerable PR gets merged** (6 min): Hedwig takes the service down, fixes it, brings it
   back, mails the PM — and the dashboard shows the agents working, step by step, as it happens.
4. **A fresh repo from the terminal** (2 min, if there is time): `/scan` and `/fix` on any repo.

Ten rehearsal branches (`test1`..`test10`) exist so step 3 can be repeated for each judge or
each run without resetting anything by hand; `tools/demo_prs.py` has one command per step.

## 0. Before the demo (once)

```sh
# update Hedwig to the latest release (>= 2.1.0), then check the tools
curl -fsSL https://github.com/D3C0Y-1-0/BubblySorted_D3C0Y_YashSingh/releases/latest/download/install.sh | sh

# tools: docker, git, gh (GitHub CLI), uv, node/npm, mvn/java (for the transaction tests)
gh auth login                       # the account that owns the demo repo
hedwig config                       # Groq key, SMTP user + app password, PM list (already saved)
hedwig doctor                       # every tool, and the email line, should be green
```

`pm_email` is a list: yash1812ys@, anirudh.vineet8@, titanparth.2801@, prathamtsec@gmail.com. The
Guard reads the same settings, so one place sets up every email.

First PDF only: Hedwig downloads its PDF engine (tectonic) once, so run `hedwig report maven-log4j`
somewhere with internet **before** you go on stage.

**Make the ten rehearsal branches once**, after the latest release is pushed:

```sh
uv run python tools/demo_prs.py create simple verified --count 10
uv run python tools/demo_prs.py status          # 20 open PRs, test1..test10
```

Each run of step 3 below uses one branch `test{i}` (1 to 10) and leaves the rest untouched, so
you never have to recreate anything between judges. `tools/demo_prs.py reset <i>` puts one branch
back to a fresh, unmerged pair of PRs if you want to redo a run on the same number.

## 1. Start the bank (two terminals, from the repo root)

```sh
# terminal 1: the bank in Docker (4 services, web page, postgres, redis, qdrant, ELK)
docker compose -f guard/deploy/docker-compose.yml up -d --build      # first time: ~10 minutes (ELK images are big), do it before the demo

# terminal 2: the Guard (the defence in front of the bank) and its dashboard
uv run --project guard chakravyuha
```

| Open | What |
|---|---|
| http://127.0.0.1:8080 | the bank (demo / demo-pass) |
| http://127.0.0.1:8090 | **the dashboard**: architecture, infrastructure, vulnerabilities, agents at work, live attack view |
| http://127.0.0.1:15601 | Kibana (button "Open Kibana" on the dashboard) |

Fill the dashboard with a scan of the bank:

```sh
cd guard/bank && hedwig scan && cd ../..        # or the "Rescan" button on the dashboard
```

Two of the dashboard's own buttons do real work (email, a full rescan) and need the value of
`CHAKRA_TOKEN` typed into the **Token** field under Controls first: **Rescan** and **Generate and
email SOC report**. Without it, or with the wrong value, they fail with 401 and say so on the
button itself. **Clear** (on the Agents at work panel, to drop one run's logs) needs no token —
it only deletes a local file, so it clears instantly.

Reset to a clean slate any time: `uv run --project guard python guard/tools/demo_reset.py` (restart the Guard).

All Docker ports are in the 1xxxx range (bank 19100-19104, Kibana 15601, Elasticsearch 19200, postgres
15432, redis 16379, qdrant 16333), so nothing on this laptop should clash and no container needs to be
stopped first. Only the Guard (8080) and its dashboard (8090) use common ports.

## 2. Story: a live attack, one script (5 min)

Keep the dashboard on screen. In a terminal:

```sh
uv run --project guard python guard/tools/attacks/full_attack.py
```

It runs every attack in order, building from reconnaissance to a full breach, and prints a
one-line summary of each stage at the end. What to say, stage by stage:

1. **Scanner**: well-known paths a real bank never serves (`/wp-admin`, `/.env`, ...). Ring 4
   answers them, scoring the client up toward the trap threshold.
2. **Flood**: a burst of requests from one address, past the per-IP rate limit (ring 2) and into
   a ban — the dot on the event log turns to "banned" within the burst.
3. **Brute force**: one address, many passwords, one username (ring 5); a few attempts later it
   "succeeds" inside the decoy, which looks just like the real bank to the attacker.
4. **Log4Shell payload**: a `${jndi:...}` lookup string, the classic probe. Ring 6 catches it,
   traps the client, and appends the hit to the service's own log — click the **transaction**
   tile afterward, or run `hedwig scan`, and the Log4Shell CVE now shows "attack seen in logs".
5. **Distributed brute force**: hundreds of addresses, one attempt each, so no per-address
   counter trips. The Scout names the campaign, the alert level rises, and the **service tile
   shows the red warning symbol** (click it for that service's report).
6. **Malware and ransomware** are pushed through the ticket attachment route. Ring 6 catches the
   test virus, the ransomware commands, the ransom note, the `.locked` file, the zip with an
   executable and the macro document. The attacker is **drawn into the decoy bank (the
   honeypot)**, which says "stored" to everything. It finds a planted API key there and uses it:
   the **honeytoken alarm** bans it and emails the PM immediately.
7. **Reports**: the PM digest (about 30 seconds after the first stop) names each attacker with
   local timestamps; the **SOC report PDF** (timeline, indicators, planted-file hashes, ATT&CK
   techniques, actions) is written and emailed. On the dashboard, the dot colours show the
   attack type, and "Open Kibana" shows every event.

Run one stage on its own any time: `--only flood,payload`, or everything except the slow ones
with `--skip distributed,malware`.

## 3. Story: a vulnerable PR gets merged (6 min)

Pick the next unused branch number `i` (1 to 10; `tools/demo_prs.py status` shows what each one
has done so far). Switch the bank checkout to it and start the watcher:

```sh
git fetch && git checkout test{i}                      # a clean checkout: no uncommitted changes
cd guard/bank && hedwig watch --branch test{i}          # leave it running; it ignores older commits
```

**a. The bot.** Comment the bot on both PRs at once: `uv run python tools/demo_prs.py comment {i}`
(or type `/hedwig scan` on either PR on GitHub yourself). The bot replies with the vulnerabilities
the PR introduces. The `hedwig` check only fails on a high-or-above finding, so the **verified**
(transaction) PR's check turns red; the **simple** (notifications) one stays green — its advisories
are medium and low, and a plain version bump already fixes them, which is the point to make.

**b. The simple one (notifications, a version bump fixes it).** Force the merge — these branches
stay unprotected on purpose, so a red check (on the other PR) would not have blocked it either:

```sh
uv run python tools/demo_prs.py merge {i} simple        # gh pr merge --merge --admin
```

Within about 10 to 20 seconds the watcher prints the incident: notifications is taken down
(`docker compose stop`), the dependency is bumped, a **fix PR** appears on GitHub, the service is
rebuilt and brought back, and the PM gets a PDF with the timeline. On the dashboard: a red
**"Incident: notifications is down"** banner appears, the tile goes grey, and the new **"Agents
at work"** panel fills in live — plan, fixer, tester, run (tests + old-vs-new build), verifier,
reporter, publish (the PR link), act (merged) — each step timestamped as it finishes. When it is
done the banner clears and the tile goes green again.

**c. The verified one (transaction, about 17 changed lines).** Same forced merge, on the other PR:

```sh
uv run python tools/demo_prs.py merge {i} verified
```

SnakeYAML 1.33 has a known remote-code-execution bug; its new test (a YAML file must not be able to
create objects) **fails** until the code is fixed. The agents bump to SnakeYAML 2.x, edit the
constructors, re-run the tests (green), the fix PR opens, transaction is rebuilt and comes back up.
The "Agents at work" panel shows the Fixer step naming the files it edited; show the diff of the
fix PR itself — it is a small, reviewed change.

Timing, on a laptop with the free model tier: the simple fix takes about a minute; the transaction
one about three minutes (the agents edit the code, Maven re-runs the tests, Docker builds the old and
new images and compares them). While it runs, talk over the dashboard panel; `/dash` in another
terminal shows the same steps in the TUI.

**d. Reset for the next judge:** `uv run python tools/demo_prs.py reset {i}` puts branch `test{i}`
back to a fresh, unmerged pair of PRs — or just move on to `test{i+1}`, already waiting.

## 4. Story: fix a fresh repo (terminal, 2 min, if there is time)

Use any git repo that has a GitHub `origin` (a new throwaway repo is best).

```sh
cd ~/some-repo
hedwig                         # opens the app
/scan                          # ranked findings, with why each ranks where it does
/fix                           # (or /fix <service>) bump + adapt code + verify, then the PR
```

What to point at: the steps (plan, fixer, run, verifier, publish), the PR that appears on GitHub
immediately (a normal PR if verified, a draft labelled `hedwig:unverified` if the tests could not
run), and the PM email with the PDF. `/dash` shows all of it live: press Enter on an alert to open
its code tree, `/` to filter, `s` `v` `r` `x` for quick filters.

## 5. Handy

| Need | Command |
|---|---|
| which test<N> branches exist, and their PRs | `uv run python tools/demo_prs.py status` |
| comment the bot on both of branch i's PRs | `uv run python tools/demo_prs.py comment <i>` |
| force-merge one of branch i's PRs | `uv run python tools/demo_prs.py merge <i> simple\|verified` |
| reset branch i for another run | `uv run python tools/demo_prs.py reset <i>` |
| make the ten branches again from scratch | `uv run python tools/demo_prs.py clean --delete-base --count 10 && uv run python tools/demo_prs.py create simple verified --count 10` |
| run one attack stage only | `uv run --project guard python guard/tools/attacks/full_attack.py --only flood` |
| take a service down / up by hand | `hedwig down transaction` / `hedwig up transaction` (or `/down`, `/up`) |
| the SOC report again | `cd guard/bank && hedwig soc-report --since 30m --email` |
| watch what Hedwig did | the **Agents at work** and **Hedwig activity** panels on the dashboard, or `.hedwig/audit.jsonl` |
| stop everything | Ctrl-C the Guard, `docker compose -f guard/deploy/docker-compose.yml down` |

## 6. If something goes wrong

- **No email arrives**: `hedwig doctor` shows the email line; `hedwig config show`. Gmail needs a 16
  character app password. A failed send is printed, never silent.
- **`/fix` says gh is not logged in**: `gh auth login`. Without it the fix stays on a local branch.
- **The watcher does nothing**: you must be on the matching `test{i}` branch in `guard/bank`, and
  `hedwig watch --branch test{i}` must be running with that same number. It ignores commits older
  than when it started.
- **Tests fail with "Permission denied: ./mvnw"**: `chmod +x guard/bank/transaction/mvnw`.
- **Dashboard tiles all say down**: the Docker stack is not up yet (`docker compose ... ps`).
- **No "Agents at work" panel appears**: it only shows while a run exists; give the watcher a few
  seconds after the merge, or check it is running in its own terminal.
- **`hedwig scan` does not show "attack seen in logs" after the attack script**: the bank's
  `*/logs/` directories must be writable by you, not root — a stale `docker compose up` from
  before the `user: "1000:1000"` fix can leave them root-owned; `docker compose ... up -d --build
  --no-deps transaction account support notifications` recreates them correctly.
- **The model is slow or rate limited**: calls retry on their own; each agent step can take up to a
  minute on the free tier.
- **A live demo needs the model key**: `hedwig config set groq_api_key <key>`.
