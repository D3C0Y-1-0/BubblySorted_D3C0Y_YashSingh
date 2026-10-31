"""Hedwig the owl, drawn in ASCII (ASCII only, so it renders in Windows consoles)."""

from rich.console import Group
from rich.table import Table
from rich.text import Text

ART = r"""
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
""".strip("\n").splitlines()

SHIELD_COL = 37
BODY_COL = 13

STYLES = {
    "s": "grey70",  # sword blade
    "g": "gold1",  # gold: hilt, shield rim
    "b": "dark_orange3",  # brown feathers and arm
    "c": "wheat1",  # cream belly
    "k": "grey23",  # glasses and eyes
    "r": "red",  # scarf and cape
    "o": "orange1",  # beak and feet
    "y": "yellow",  # shield emblem
    " ": "",
}


def _code(row: int, col: int, ch: str) -> str:
    if ch == " ":
        return " "
    if ch == "~":
        return "r"
    if col >= SHIELD_COL:
        return "y" if ch in "\\/|" and 7 <= row <= 11 and col >= SHIELD_COL + 3 else "g"
    if col < BODY_COL:
        if row <= 4:
            return "s"
        return "g" if row in (5, 6) else "b"
    if ch == ",":
        return "c"
    if ch in "()@":
        return "k"
    if ch in "<>":
        return "o"
    if row >= 14:
        return "o"
    return "b"


def mascot() -> Text:
    text = Text(no_wrap=True)
    for row, line in enumerate(ART):
        for col, ch in enumerate(line):
            text.append(ch, style=STYLES[_code(row, col, ch)])
        text.append("\n")
    text.rstrip()
    return text


def banner() -> Table:
    from hedwig import __version__

    title = Text.assemble(
        ("HEDWIG\n", "bold gold1"),
        ("threat early warning\n", "italic"),
        (f"v{__version__}", "dim"),
    )
    grid = Table.grid(padding=(0, 3))
    grid.add_row(mascot(), Group(Text("\n\n\n"), title))
    return grid
