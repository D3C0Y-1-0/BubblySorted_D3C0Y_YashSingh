# Hedwig demo script (for the judges)

Everything runs on this one laptop. Three stories, about five minutes each:

1. **Fix a fresh repo from the terminal** and get the PR on GitHub.
2. **Someone merges vulnerable code**: Hedwig takes the service down, fixes it, brings it back, mails the PM.
3. **A live attack** (distributed brute force, then malware and ransomware): the Guard traps the attacker in a fake bank, bans it, and the PM and SOC get reports.

## 0. Before the demo (once)

```sh
# tools: docker, git, gh (GitHub CLI), uv, node/npm, mvn/java (for the transaction tests)
gh auth login                       # the account that owns the demo repo
hedwig config                       # Groq key, SMTP user + app password, PM list (already saved)
hedwig doctor                       # every tool, and the email line, should be green
```

`pm_email` is a list: yash1812ys@, anirudh.vineet8@, titanparth.2801@, prathamtsec@gmail.com. The
Guard reads the same settings, so one place sets up every email.

First PDF only: Hedwig downloads its PDF engine (tectonic) once, so run `hedwig report maven-log4j`
somewhere with internet **before** you go on stage.

## 1. Start the bank (two terminals, from the repo root)

```sh
# terminal 1: the bank in Docker (4 services, web page, postgres, redis, qdrant, ELK)
docker compose -f guard/deploy/docker-compose.yml up -d --build      # first time: several minutes

# terminal 2: the Guard (the defence in front of the bank) and its dashboard
uv run --project guard chakravyuha
```

| Open | What |
|---|---|
| http://127.0.0.1:8080 | the bank (demo / demo-pass) |
| http://127.0.0.1:8090 | **the dashboard**: architecture, infrastructure, vulnerabilities, live attack view |
| http://127.0.0.1:5601 | Kibana (button "Open Kibana" on the dashboard) |

Fill the dashboard with a scan of the bank:

```sh
cd guard/bank && hedwig scan && cd ../..        # or the "Rescan" button on the dashboard (token: CHAKRA_TOKEN)
```

Reset to a clean slate any time: `uv run --project guard python guard/tools/demo_reset.py` (restart the Guard).

## 2. Story 1: fix a fresh repo (terminal, 4 min)

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

## 3. Story 2: a vulnerable PR gets merged (6 min)

Create the two demo PRs on a `test` branch (never on `main`):

```sh
uv run python tools/demo_prs.py create          # PR "simple" (notifications) + PR "verified" (transaction)
```

Switch the bank checkout to `test` and start the watcher:

```sh
git fetch && git checkout test
cd guard/bank && hedwig watch --branch test     # leave it running
```

**a. The bot.** On either PR on GitHub, comment `/hedwig scan` (or `:hedwig scan`). The bot replies
with the vulnerabilities the PR introduces.

**b. The simple one (notifications, a version bump fixes it).** Merge that PR into `test` on GitHub.
Within about 20 seconds the watcher prints the incident: notifications is taken down
(`docker compose stop`), the dependency is bumped, a **fix PR** appears on GitHub, the service is
rebuilt and brought back, and the PM gets a PDF with the timeline. Show the dashboard tile go down and
come back, the incident log, and the PDF.

**c. The verified one (transaction, about 17 changed lines).** Merge the second PR into `test`.
SnakeYAML 1.33 has a known remote-code-execution bug; its new test (a YAML file must not be able to
create objects) **fails** until the code is fixed. The agents bump to SnakeYAML 2.x, edit the
constructors, re-run the tests (green), the fix PR opens, transaction is rebuilt and comes back up.
Show the diff of the fix PR: it is a small, reviewed change.

(You can also merge locally instead: `git merge origin/demo/simple-notifications && git push origin test`.)

## 4. Story 3: a live attack (5 min)

Keep the dashboard on screen. In a terminal:

```sh
uv run --project guard python guard/tools/attacks/full_attack.py
```

What happens, and what to say:

1. **Distributed brute force**: hundreds of addresses, one password each, so no per-address counter
   trips. The Scout names the campaign, the alert level rises, the **service tile shows the red
   warning symbol** (click it for that service's report).
2. **Malware and ransomware** are pushed through the ticket attachment route. Ring 6 catches the
   test virus, the ransomware commands, the ransom note, the `.locked` file, the zip with an
   executable and the macro document. The attacker is **drawn into the decoy bank (the honeypot)**,
   which says "stored" to everything. It finds a planted API key there and uses it: the **honeytoken
   alarm** bans it and emails the PM immediately.
3. **Reports**: the PM digest (about 30 seconds after the first stop) names each attacker with UTC
   timestamps; the **SOC report PDF** (timeline, indicators, planted-file hashes, ATT&CK techniques,
   actions) is written and emailed. On the dashboard, the dot colours show the attack type, and
   "Open Kibana" shows every event.

## 5. Handy

| Need | Command |
|---|---|
| take a service down / up by hand | `hedwig down transaction` / `hedwig up transaction` (or `/down`, `/up`) |
| the SOC report again | `cd guard/bank && hedwig soc-report --since 30m --email` |
| remove the demo PRs and branches | `uv run python tools/demo_prs.py clean --delete-base` |
| watch what Hedwig did | the **Hedwig activity** panel on the dashboard, or `.hedwig/audit.jsonl` |
| stop everything | Ctrl-C the Guard, `docker compose -f guard/deploy/docker-compose.yml down` |

## 6. If something goes wrong

- **No email arrives**: `hedwig doctor` shows the email line; `hedwig config show`. Gmail needs a 16
  character app password. A failed send is printed, never silent.
- **`/fix` says gh is not logged in**: `gh auth login`. Without it the fix stays on a local branch.
- **The watcher does nothing**: you must be on the `test` branch in `guard/bank`, and the PR must be
  merged **into `test`**. It ignores commits older than when it started.
- **Tests fail with "Permission denied: ./mvnw"**: `chmod +x guard/bank/transaction/mvnw`.
- **Dashboard tiles all say down**: the Docker stack is not up yet (`docker compose ... ps`).
- **The model is slow or rate limited**: calls retry on their own; each agent step can take up to a
  minute on the free tier.
- **A live demo needs the model key**: `hedwig config set groq_api_key <key>`.
