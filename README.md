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

Open a new terminal, then:

```sh
hedwig config    # store your Groq API key (saved to ~/.hedwig/config.toml)
hedwig doctor    # check git, docker, npm, cargo, composer, mvn, tectonic
hedwig --version
```

Run the install command again to update. The repo must be public for these links to work.

## Releasing

Bump `version` in `pyproject.toml`, merge `main` into `release` and push. The `release` workflow
lints, tests, builds, and publishes a GitHub Release with the wheel and installers attached. It
fails if the `v<version>` tag already exists.

## Plan

See `plan/claudesPLAN.md`. Bank contract: `docs/bank-contract.md`.
