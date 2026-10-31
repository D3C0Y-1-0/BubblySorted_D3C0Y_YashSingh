# Hedwig

Developer-native cyber threat early warning. Hedwig reads threat intelligence, works out which
threats matter to your services, and responds inside limits your team has approved.

```
     /\
    /  \         /\/\         /\/\
    |  |        /  \ \_______/ /  \
    |  |       |  .---.   .---.   |
    |  |       | ( (@) ) ( (@) )  |
  __|  |__     |  '---'  <>'---'  |   ,==========,
 [__====__]    |~~~~~~~~~\/~~~~~~~|  / \   /\   / \
    ||||       /~~~~~~~~~~~~~~~~~~\ |   \ /  \ /   |
    ||||      /~~~/ ,,,,,,,, \~~~~~\|    \\  //    |
  ~~~||||~~~~/~~~~/ ,,,,,,,,,, \~~~~\\    \\//    /
 ~~~~~~||~~~|~~~~~|  ,,,,,,,,,,  |~~~|\    ||    /
  ~~~~~~~~~~|~~~~~|  ,,,,,,,,,,  |    '\   \/   /'
    ~~~~~~~~ \~~~~~\  ,,,,,,,,  /      '-.____.-'
       ~~~~~~~\~~~~~'-.______.-'
               _/|\_      _/|\_
```

## Install

Linux / macOS:

```sh
curl -fsSL https://github.com/D3C0Y-1-0/BubblySorted_D3C0Y_YashSingh/releases/latest/download/install.sh | sh
```

Windows (PowerShell):

```powershell
irm https://github.com/D3C0Y-1-0/BubblySorted_D3C0Y_YashSingh/releases/latest/download/install.ps1 | iex
```

Open a new terminal, `cd` into the folder that holds your services, and run:

```sh
hedwig
```

This opens the Hedwig app. Type `/` to see the commands:

| Command | What it does |
|---|---|
| `/init` | Create `.hedwig.yml` for the current folder. Each subfolder with a manifest is one service |
| `/scan [path\|git-url]` | Find known vulnerabilities, ranked by risk. Add `--offline`, `--json`. Defaults to this folder |
| `/status` | Findings per service in this folder |
| `/explain <id>` | Reasoning, score factors and the recommended fix for one finding |
| `/simulate-attack <service>` | Write an attack request to the service's log. Add `--compromise` for a sign of compromise |
| `/fix <service>` | Fix the service's vulnerable packages: bump, adapt the code, verify, push the branch and open a PR on GitHub (a draft when verification failed or could not run), then do what `.hedwig.yml` allows. Add `--package NAME`, `--dry-run`, `--no-pr`, `--no-email` |
| `/down <service>`, `/up <service>` | Stop and start one service of the local Docker Compose bank (`docker compose stop` / `start`) |
| `/report <service\|run-id>` | PDF report for the project manager. Add `--email` |
| `/dash` | Terminal dashboard: the service architecture with live Docker status, alerts with expandable call sites, a reports table and the Guard's attack reports. Keys: `f` fix, `t` take down, `u` start, `a` approve, `e`/`c` expand/collapse, `1` `2` `3` tabs, `/` filter, `?` help |
| `/config` | Store your Groq API key (saved to `~/.hedwig/config.toml`). Also `/config show` and `/config set <key> <value>` |
| `/doctor` | Check git, docker, npm, cargo, composer, mvn, tectonic |
| `/clear`, `/help`, `/exit` | Clear the screen, list commands, leave |

Every command also works directly: `hedwig init`, `hedwig scan`, `hedwig status`, `hedwig explain <id>`, `hedwig simulate-attack <service>`, `hedwig fix <service>`, `hedwig down <service>`, `hedwig up <service>`, `hedwig report <target>`, `hedwig dash`, `hedwig config`, `hedwig doctor`, `hedwig --version`.
`init` always works on the folder you run it from.

### Fixing and reporting

`fix` needs a Groq key (`/config`), `git`, and for the old-vs-new comparison `docker`. To open the pull request it needs the GitHub CLI (`gh auth login`) and a GitHub `origin`; without them the fix stays on a local branch. It works in
git worktrees under `.hedwig/work/`, never in your working copy, and writes everything to
`.hedwig/runs/<run-id>/` (`diff.patch`, `cases.json`, `verdict.json`, `review.json`, `pr.md`).
Every agent call and decision goes to `.hedwig/audit.jsonl`. `report` builds the PDF with `tectonic`, which Hedwig downloads once into `~/.hedwig/bin` on first
use (the first report needs internet). `--email` sends it to `pm_email` and needs `smtp_user` and
`smtp_pass`: for Gmail that is a 16-character app password (myaccount.google.com/apppasswords).
`/fix` emails the PM report once when it finishes; add `--no-email` to skip it.

Run the install command again to update. The repo must be public for these links to work.

### Catching a vulnerable merge

- **The bot:** comment `/hedwig scan` on a pull request and the `hedwig-pr` workflow replies with the
  vulnerabilities the PR introduces and sets a `hedwig` status on it. It runs from the default
  branch, so the workflow file has to be merged into `main` first. `hedwig pr-check` does the same
  scan by hand.
- **The watcher:** `hedwig watch` (run it in the folder with `.hedwig.yml`) checks every PR merged
  into the project, whether or not the bot was asked. If a PR introduced vulnerable packages it
  takes the affected service down (`docker compose stop`, when the service allows `takedown`),
  fixes it with the minimal change, opens the fix PR, merges it into your local `main`, rebuilds
  and restarts the service, and emails the PM a PDF with a UTC timeline. If your local checkout
  cannot take the merged code (a conflict, a different branch) it stops, takes nothing down and
  says so in the report.
- **Demo:** `uv run python tools/demo_prs.py create` opens one PR per bank service, each adding a
  package with a known advisory; `clean` removes them.

### Malware and ransomware

- **Through the bank (the Guard):** uploads and request bodies are inspected for malware and ransomware
  (test virus, webshells, executables, ransomware commands, ransom notes, `.locked`-style files,
  zips holding executables, macro documents). The attacker is drawn into the decoy bank and the PM
  gets an email naming each attacker with UTC timestamps. Try it with
  `uv run --project guard python guard/tools/attacks/malware.py` (harmless stand-ins only).
- **Through the dependencies:** a known malicious package is flagged critical in scans and in the PR
  bot's comment. If nothing uses it, `hedwig fix` removes it instead of bumping it. Possible
  typosquats and dropper-like install scripts are reported for a human.

## Releasing

Bump `version` in `pyproject.toml`, merge `main` into `release` and push. The `release` workflow
lints, tests, builds, and publishes a GitHub Release with the wheel and installers attached. It
fails if the `v<version>` tag already exists.

## Plan

See `plan/claudesPLAN.md`. Bank contract: `docs/bank-contract.md`.
