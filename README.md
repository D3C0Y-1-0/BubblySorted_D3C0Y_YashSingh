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
| `/replay <advisory>` | Inject a known advisory (`log4shell`, `jsonwebtoken`) and show what Hedwig would do. Add `--dry-run`, `--json` |
| `/simulate-attack <service>` | Write an attack request to the service's log. Add `--compromise` for a sign of compromise |
| `/fix <service>` | Fix the service's vulnerable packages: bump, adapt the code, verify, then do what `.hedwig.yml` allows. Add `--package NAME`, `--dry-run` |
| `/report <service\|run-id>` | PDF report for the project manager. Add `--email` |
| `/dash` | Terminal dashboard: services, alerts, fix runs. Keys: `f` fix, `t` takedown, `a` approve, `r` replay, `/` filter, `?` help |
| `/config` | Store your Groq API key (saved to `~/.hedwig/config.toml`). Also `/config show` and `/config set <key> <value>` |
| `/doctor` | Check git, docker, npm, cargo, composer, mvn, tectonic |
| `/clear`, `/help`, `/exit` | Clear the screen, list commands, leave |

Every command also works directly: `hedwig init`, `hedwig scan`, `hedwig status`, `hedwig explain <id>`, `hedwig replay <advisory>`, `hedwig simulate-attack <service>`, `hedwig fix <service>`, `hedwig report <target>`, `hedwig dash`, `hedwig config`, `hedwig doctor`, `hedwig --version`.
`init` always works on the folder you run it from.

### Fixing and reporting

`fix` needs a Groq key (`/config`), `git`, and for the old-vs-new comparison `docker`. It works in
git worktrees under `.hedwig/work/`, never in your working copy, and writes everything to
`.hedwig/runs/<run-id>/` (`diff.patch`, `cases.json`, `verdict.json`, `review.json`, `pr.md`).
Every agent call and decision goes to `.hedwig/audit.jsonl`. `report` needs `tectonic` for the PDF;
`--email` needs `smtp_user` and `smtp_pass` (Gmail by default, app password).

Run the install command again to update. The repo must be public for these links to work.

## Releasing

Bump `version` in `pyproject.toml`, merge `main` into `release` and push. The `release` workflow
lints, tests, builds, and publishes a GitHub Release with the wheel and installers attached. It
fails if the `v<version>` tag already exists.

## Plan

See `plan/claudesPLAN.md`. Bank contract: `docs/bank-contract.md`.
