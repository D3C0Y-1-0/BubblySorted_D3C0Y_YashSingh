# Hedwig: Phased Implementation Plan

## Context

The repo has only `PS.md` and `plan/initialize.md`, which hold the team's design for **Hedwig**. Hedwig is a threat early-warning engine with three surfaces: a CLI/terminal dashboard, GitHub Actions and a Claude Code plugin. This plan turns the design into build phases. Each phase has acceptance conditions, and the scope is cut to what the demo needs.

Changes from the team plan (from both files and your answers):
1. **Strict engine.** Every finding goes into the response pipeline, whatever its severity. Nothing is ignored. Severity only sets the order and what the report says.
2. **Response flow.** The agent fixes the issue with a version bump plus code migration and runs black-box verification. On a pass it auto-merges, if `.hedwig.yml` allows that. On a fail it takes the service down on Render, if allowed. Otherwise it leaves the PR for a human and emails the PM.
3. **Code edits come from Groq-hosted models**: `openai/gpt-oss-120b` as primary, `qwen/qwen3-32b` as fallback. Claude is not used for code edits.
4. **PM report is LaTeX → PDF**, emailed to the hardcoded PM `yash1812ys@gmail.com`. WeasyPrint is dropped.
5. **The bank is built last.** Earlier phases test against small fixture projects. Phase 0 sets the conditions the bank must meet (the Bank Contract), and Phase 8 builds the bank against them.

Cut to avoid overengineering:
- tree-sitter: import detection uses regex per language, plus Python `ast`.
- NVD and the GitHub Advisory DB: OSV already carries CVSS.
- LLM-drafted characterization tests.
- Symbol-level reachability.
- A GitHub App: a fine-scoped PAT is enough.
- SQLite: an on-disk JSON cache is enough.
- Syft/cdxgen.

## Decision rule (deterministic, `core/policy.py`)

```
for each finding on service S (all severities):
  if evidence >= 4 and "takedown" in S.allow      -> TAKEDOWN (suspend on Render), email PM
  elif "open_fix_pr" not in S.allow               -> NOTIFY (email PM), service flagged
  else:
    fix = agent: minimal version bump -> run tests -> if failing or major bump, LLM edits call sites (max 2 attempts)
    verdict = black_box_verify(fix)
    open PR with verdict in body
    if verdict.pass:
        if "auto_merge_if_verified" in S.allow    -> gh pr merge --auto -> Render deploy -> smoke test
                                                     -> on smoke fail: rollback (if "rollback" allowed)
        else                                      -> PR labelled hedwig:needs-review, email PM
    else:
        if "takedown" in S.allow                  -> TAKEDOWN, PR left as draft
        else                                      -> PR labelled hedwig:verification-failed, email PM
```
The LLM never decides. It only produces a patch, and the gate above decides. `--dry-run` prints the plan and does nothing.

**Black-box verification** (`core/verify.py`). All three steps must pass:
1. The service's `test_cmd`.
2. A differential HTTP replay. Build and run the old and new Docker images, replay `hedwig.requests.json`, then diff the status codes and the top-level JSON keys.
3. A re-scan of the new lockfile, which must show no new finding and the target finding gone.

## Layout

```
pyproject.toml                # uv, Python 3.12, entrypoint `hedwig`
src/hedwig/
  config.py                   # .hedwig.yml Pydantic models
  core/models.py              # Package, Advisory, Finding, Decision, Verdict
  core/inventory.py           # parsers: package-lock.json, Cargo.lock, composer.lock, pom.xml, requirements.txt
  core/advisories.py          # OSV querybatch + vuln detail, CISA KEV, EPSS; JSON cache in .hedwig/cache; fixture loader
  core/reachability.py        # import-level: Python ast, regex for JS/PHP/Java/Rust
  core/evidence.py            # log rules -> evidence level 0-4
  core/score.py               # risk score + reasoning line
  core/policy.py              # decide() as above
  core/fix.py                 # minimal version selection, manifest edit, lockfile regen
  core/llm.py                 # Groq client (OpenAI-compatible, JSON mode)
  core/verify.py              # black-box verification
  core/render.py              # Render API: deploy, suspend, resume, rollback
  core/report.py              # Jinja2 -> .tex -> tectonic -> PDF; SMTP email
  core/audit.py               # append-only JSONL audit log
  cli/main.py                 # Typer commands, all with --json
  cli/dash.py                 # Textual dashboard
.github/workflows/            # hedwig-pr-guard, hedwig-watch, hedwig-respond, hedwig-report
plugin/                       # Claude Code plugin + MCP server
fixtures/                     # cached advisories, replay advisories, mini projects, expected results
bank/                         # Phase 8
```

---

## Phase 0: Skeleton, fixtures, Bank Contract

- uv project, ruff, pytest, CI workflow (`ruff check && pytest`).
- `fixtures/projects/`: tiny runnable projects used in place of the bank until Phase 8:
  - `node-lodash`: Express app with `lodash@4.17.15`, `/health`, one test, Dockerfile, `hedwig.requests.json`.
  - `py-yaml`: `PyYAML==5.3.1` with `yaml.load` (reachable). A `safe_load` copy covers the unreachable case.
  - `broken-after-bump`: a project whose tests fail on the fixed version. Used to test the verify-fail → takedown path.
  - Lockfile-only fixtures for Maven (`log4j-core 2.14.1`), Cargo (`regex 1.5.4`) and Composer (`phpmailer` with a known CVE).
- `fixtures/advisories/`: cached OSV/KEV/EPSS responses so tests run offline. Replay advisories `log4shell.json` and `jsonwebtoken.json` list their affected versions explicitly, so matching is a set-membership check.
- `docs/bank-contract.md`: the Phase 8 conditions, copied from the section at the end of this plan.

**Done when:** `uv run hedwig --help` works. `uv run pytest` and `ruff check` pass in CI. Every fixture project's tests pass on its seeded version. The bank contract doc is committed.

## Phase 1: Core engine (`scan`, `status`, `explain`)

- Inventory parsers for the five manifest/lockfile types. Maven covers direct deps only.
- Advisory lookup: OSV `querybatch` gives the list of vulns, and vuln details give CVSS and fixed versions. KEV comes from the JSON feed and EPSS from its API. All are cached, and `--offline` uses the cache/fixtures only.
- Score: `risk = exploitability × impact × criticality × confidence`. Each factor is 0–1, and criticality maps critical/high/medium/low to 1.0/0.75/0.5/0.25. The result maps to a severity band. Every finding carries a reasoning string listing the factors that raised it.
- `hedwig scan <path|git-url>` prints a ranked Rich table plus a summary like "N raw advisories → M findings". `hedwig status` reads `.hedwig.yml` and gives a per-service summary. `hedwig explain <id>` and `hedwig init` are also in this phase. Every command supports `--json`.

**Done when:**
- `hedwig scan fixtures/... --offline --json` reports CVE-2021-44228 (log4j-core 2.14.1, fixed 2.17.1), CVE-2022-24713 (regex 1.5.4, fixed 1.5.5), the phpmailer CVE and lodash 4.17.15 advisories. Each finding has score, severity, reasoning and fixed version, and all are asserted in pytest against `fixtures/expected/*.json`.
- Log4Shell's reasoning line includes "actively exploited (KEV)".
- An online `hedwig scan` on a clone of OWASP NodeGoat and WebGoat finishes in under 60s with a ranked list. Precision is recorded in `fixtures/expected/<repo>.json`.

## Phase 2: Policy gate, replay, reachability, evidence

- `config.py`: Pydantic schema for `.hedwig.yml` with `tier`, `language`, `path`, `test_cmd`, `log_path`, `health_url`, `render_service_id` and `allow` (a subset of `open_fix_pr`, `auto_merge_if_verified`, `rollback`, `takedown`).
- `reachability.py`: is the vulnerable package imported in the service's source? This only adjusts confidence and never removes a finding.
- `evidence.py`: level 0 = version present, 1 = reachable, 2 = KEV, 3 = attack pattern in log (regexes such as `\$\{jndi:`, JWT `alg":"none`, path traversal), 4 = compromise marker in log (a simulated outbound connection or unexpected process line).
- `hedwig simulate-attack <service> [--compromise]` appends a level-3 or level-4 line to the service's `log_path`.
- `hedwig replay <advisory>` loads the fixture advisory into the same pipeline as live feeds and prints the decision.
- `policy.decide()` follows the decision rule above.

**Done when:**
- A table-driven pytest covers every branch of the decision rule: evidence ≥4 with and without takedown, no `open_fix_pr`, verify pass with and without auto-merge, verify fail with and without takedown.
- A low-severity finding still produces a non-empty action (strictness test).
- `py-yaml` (uses `yaml.load`) scores higher than the `safe_load` copy, and both still appear.
- `simulate-attack node-lodash` raises evidence to 3, and `--compromise` raises it to 4.
- `hedwig replay log4shell --dry-run --json` on the Maven fixture returns the expected decision.

## Phase 3: Fix agent and black-box verification (local)

- `fix.py`: pick the smallest fixed version greater than the current one, in the same major if possible, else the smallest major bump. Version comparison is a numeric tuple compare. Edit the manifest and regenerate the lockfile with `npm install pkg@v --package-lock-only`, `cargo update -p pkg --precise v`, `composer update pkg`, a pom.xml edit or a requirements.txt edit.
- `llm.py`: Groq via the OpenAI-compatible SDK, `GROQ_API_KEY`. Input: the advisory summary, the files that import the package (from reachability) and the test failure output. Output: JSON `{files:[{path, new_content}], rationale}`. Advisory text sits inside a clearly delimited data block and is never treated as instructions. Only files already in the input set can be written. Falls back to qwen if gpt-oss fails.
- `verify.py`: the three-step black-box check.
- `hedwig fix <service> [--dry-run]` works on a branch locally and prints the diff and verdict.

**Done when:**
- `hedwig fix node-lodash` bumps lodash to the smallest fixed 4.x, and the tests, differential replay and re-scan all pass. Verdict = pass.
- `hedwig fix broken-after-bump` calls the LLM. If the tests still fail after 2 attempts, verdict = fail and the failing step is named.
- The LLM output schema is validated. A response that writes outside the allowed files is rejected (unit test with a mocked Groq response).
- Re-scan confirms the target finding is gone.

## Phase 4: GitHub tool, PM report and email

- `hedwig-pr-guard.yml` (on `pull_request` touching manifests/lockfiles): scans the diff, posts or updates one PR comment (owl, risk, reasoning, safe version) and fails the check when a finding is introduced.
- `hedwig-report.yml` (on `pull_request: closed` + merged with a failing pr-guard check): logs the override to the audit log, builds the PDF (what was merged, why it's risky, safe version, who merged) and emails it. Then it dispatches `hedwig-respond`, since the strict engine fixes it too.
- `hedwig-watch.yml` (on `schedule`, `workflow_dispatch` with an `advisory` input for replay, `repository_dispatch`): scans every service and dispatches `hedwig-respond` per finding.
- `hedwig-respond.yml`: runs `hedwig respond <service> <finding>`, which runs Phase 3 and then executes the decision. Opens the PR via `gh`, labels it, runs `gh pr merge --auto --squash` when allowed and emails the report after every autonomous action.
- `report.py`: Jinja2 `.tex` template → `tectonic` → PDF. SMTP (Gmail app password) to `yash1812ys@gmail.com`, hardcoded in one constant.
- `audit.py`: JSONL appended to `.hedwig/audit.jsonl` on a `hedwig-state` branch (avoids branch protection on main), which the dashboard and `status` read.
- Secrets: `HEDWIG_TOKEN` (fine-scoped PAT), `GROQ_API_KEY`, `SMTP_USER`, `SMTP_PASS`, `RENDER_API_KEY`.

**Done when** (on a sandbox GitHub repo holding the fixture projects, with pr-guard as a required check):
- A PR that adds `lodash@4.17.15` gets a Hedwig comment and a red check. Admin merge-override triggers the report, a PDF arrives at `yash1812ys@gmail.com`, and an audit line is written.
- `workflow_dispatch` on watch with `advisory=…` produces a fix PR with the verdict in its body. With `auto_merge_if_verified` the PR merges after checks; without it the PR gets the `hedwig:needs-review` label.
- The PDF compiles locally with `hedwig report <service>`.

## Phase 5: Render deploy, smoke, rollback, suspend

- `render.py` uses the Render REST API: trigger deploy, suspend, resume, list deploys and roll back to the previous live deploy. **Check the exact endpoints in current Render docs before coding.**
- After auto-merge: wait for the deploy, hit `health_url` and the replay routes, and roll back if the smoke test fails and `rollback` is allowed.
- Takedown = suspend. `hedwig resume <service>` handles the human resume path. Every call is audited.

**Done when:**
- Unit tests with a mocked HTTP client (respx) cover deploy, suspend, resume and rollback.
- On one real throwaway Render service (the `node-lodash` fixture): a verify-fail on a takedown-allowed config suspends it (health stops responding), `hedwig resume` brings it back, and a forced smoke failure triggers rollback.
- Each of these actions appears in the audit log.

## Phase 6: Terminal dashboard (`hedwig dash`)

Textual app containing:
- Owl header in three states (watching/alert/asleep), estate risk gauge, feed freshness and a clock.
- A service card per service (tier, health, risk colour).
- An alert feed (severity, evidence level, reason) and a detail pane (score breakdown, reachability, fixed version, decision).
- An action timeline with time-to-action.
- Keys: `Enter`, `f` fix, `t` takedown (dry-run first, then confirm), `a` approve, `r` replay, `/` filter, `?` help.

It refreshes from local state plus `hedwig-state` audit every few seconds. No sparklines or diff view unless time permits.

**Done when:** a Textual `Pilot` test boots the app on fixture state and asserts cards and alerts render, `r` replay adds an alert, and `t` shows a dry-run before acting. A manual run shows a status change within one refresh of an action. A screen recording is saved.

## Phase 7: Claude Code plugin

- `plugin/`: plugin manifest and a Python MCP server (stdio) that shells out to `hedwig … --json`, with tools `scan`, `status`, `explain`, `propose_fix` (runs `hedwig fix --dry-run`) and `replay`.
- Slash commands `/hedwig:scan`, `/hedwig:status`, `/hedwig:fix`.
- A skill covering how to read a finding, the evidence ladder and `.hedwig.yml`.
- A `remediator` subagent definition.
- A PostToolUse hook on manifest edits that runs `hedwig scan --json` on the file and warns on a critical finding.

**Done when:** the plugin installs locally. Each MCP tool returns valid JSON on a fixture (pytest calls the server functions directly). `/hedwig:scan` works in a Claude Code session. Editing a fixture `package.json` to `lodash@4.17.15` triggers the hook warning.

## Phase 8: Demo bank (later), built to the Bank Contract

Build the bank here. It is done when **every condition below** passes.

**Per service** (transaction/Java, account/Rust, support/PHP, notifications/Node; optional Python reachability service):
1. Lives under `bank/<service>/` with a pinned manifest and lockfile containing the seeded version: log4j-core 2.14.1 / regex 1.5.4 / phpmailer pre-fix release / lodash 4.17.15 + jsonwebtoken 8.5.1. Each version is checked on osv.dev.
2. The vulnerable package is **imported** in source, for reachability. User input **never** reaches the vulnerable path (for example, log4j logs only constants and runs with `-Dlog4j2.formatMsgNoLookups=true`), and the data is fake.
3. `GET /health` → `200 {"status":"ok"}`.
4. `test_cmd` passes offline in under 60s on the seeded version.
5. A `Dockerfile` and `hedwig.requests.json` with ≥3 recorded requests. The differential replay passes old vs old, so there are no false diffs.
6. Writes access logs (path, headers, body) to its `log_path`, so `simulate-attack` lines and real requests are both detected.

**Estate:**
7. `.hedwig.yml` at the repo root:
   - transaction: critical, `[open_fix_pr, auto_merge_if_verified, rollback]`
   - account: high, `[open_fix_pr]`
   - support: medium, `[open_fix_pr]`
   - notifications: low, `[open_fix_pr, auto_merge_if_verified, takedown]`
8. `docker compose up` starts all services, the gateway and the tablet page. `make demo-reset` restores seeded versions, clears logs and resumes suspended services.
9. Tablet page: one tile per service. A tile greys out when its service's health fails, and the others keep working.
10. Each service is deployed on Render as a Docker web service with a health check path on an always-on instance.

**Expected Hedwig outcomes:** a pytest e2e file plus a live run.

| Check | Expected |
|---|---|
| `hedwig scan bank/ --json` | All seeded CVEs found, each with reasoning |
| `hedwig replay log4shell` → respond | Fix PR on transaction, verify pass, auto-merged, deployed, smoke OK. Money transfer works with no downtime |
| account finding | Fix PR opened, `hedwig:needs-review`, not merged |
| PR adding vulnerable phpmailer to support | pr-guard red. Admin merge → PDF emailed to PM, then a fix PR opened |
| `simulate-attack notifications --compromise` + `replay jsonwebtoken` | Evidence 4 → notifications suspended on Render, only the offers tile greys out |
| `hedwig dash` after the above | transaction patched, notifications asleep, account/support awaiting human |

---

## Verification (overall)

- Every phase: `uv run ruff check && uv run pytest` green in CI, with offline fixtures and no network in unit tests.
- Phases 4–5: live run on the sandbox repo and a throwaway Render service, with the received PDF email as evidence.
- Phase 8: the expected-outcomes table above, run end-to-end once on Render and once on local docker-compose as the demo-day fallback.
