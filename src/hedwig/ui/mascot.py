"""Hedwig the owl, drawn as pixel art with half-block characters.

Each art string is one row of pixels; each letter is a colour from PALETTE and "." is
transparent. Two pixel rows are packed into one terminal row with the upper half block,
so the owl renders as solid colour rather than line strokes.
"""

from rich.console import Console, ConsoleOptions, RenderResult
from rich.style import Style
from rich.table import Table
from rich.text import Text

PALETTE = {
    "K": "#2b160d",  # outline
    "B": "#a65a2e",  # brown feathers
    "D": "#74391b",  # dark brown (knuckles)
    "C": "#f7dfb9",  # cream
    "c": "#e6c193",  # cream shade
    "W": "#ffffff",  # eye white
    "E": "#1a0d06",  # pupil
    "O": "#f7a21b",  # beak and feet
    "R": "#e23a2c",  # scarf and cape
    "Q": "#a3201a",  # dark red folds
    "G": "#f5bd2a",  # gold
    "H": "#b9800f",  # dark gold
    "S": "#a9adb8",  # steel
    "L": "#eef0f5",  # light steel
    "N": "#6e3b1f",  # shield wood
}

# Full mascot: sword, glasses, scarf, cape and shield. 39 cols x 16 rows.
HERO = (
    ".....KK................................",
    "....KLSK...............................",
    "....KLSK...............................",
    "....KLSK...............................",
    "....KLSK...KK................KK........",
    "....KLSK..KBBK..KKKKKKKKKK..KBBK.......",
    "....KLSK..KBBBKKBBBBBBBBBBKKBBBK.......",
    "....KLSK.KBBBBBBBBBBBBBBBBBBBBBBK......",
    "....KLSKKBBBCCCCCCCBBBBCCCCCCCBBBK.....",
    "....KLSKKBBCKKKKKCCCCCCCCKKKKKCBBK.....",
    "..KKKKKKKKBKWWWWWKCCCCCCKWWWWWKBBK.....",
    ".KHGGGGGGHKKWWEEWKKKKKKKKWWEEWKKKK.....",
    "..KKKKKKKKBKWEEEWKCCOOCCKWEEEWKBBK.....",
    "..KKKKKKKKBKWWWWWKCCOOCCKWWWWWKBBK.....",
    ".KBDBDBDBBKCKKKKKCCCRRCCCKKKKKCBBK.....",
    ".KBBBBBBBBKCCCCCCCCCCCCCCCCCCCCBK......",
    "..KBBBBBBBKGRRRRRRRRRRRRRRRRRRRRQK.....",
    "...KBBBBBBKRRRRRRRRRRRRRRRRRRRRQQK.....",
    "....KBBBBBBBBBcCCCCCCCCCCCCcBKKKKKKKKKK",
    ".....KBBBBBBBcCCCCCCCCCCCCCCcKGGGGGGGGK",
    "....KRKBBBBBcCCCCCCCCCCCCCCCCKGNNNNNNGK",
    "...KRRRQKBBBcCCCCCCCCCCCCCCCCKGGNNNNGGK",
    "..KRRRQRKBBBcCCCCCCCCCCCCCCCCKGNGGGGNGK",
    ".KRRRQRRKBBBcCCCCCCCCCCCCCCCCKGNNGGNNGK",
    "KRRRQRRRKBBBBcCCCCCCCCCCCCCCcKGNNGGNNGK",
    "KRRQRRRRRKBBBBcCCCCCCCCCCCCcBKGNNNNNNGK",
    ".KKRQRRRRKBBBBBccCCCCCCCCccBBBKGNNNNGK.",
    "...KKQRRRRKBBBBBBccccccccBBBBBKGNNNNGK.",
    ".....KKQRR.KKBBBBBBBBBBBBBBBBKKKGNNGK..",
    ".......KKR...KOOOKKKKKKKKOOOK...KGGK...",
    "............KOOOOOK....KOOOOOK...KK....",
    "............KOKOKOK....KOKOKOK.........",
)

# Head and scarf only. 26 cols x 8 rows.
BUST = (
    "...KK................KK...",
    "..KBBK..KKKKKKKKKK..KBBK..",
    "..KBBBKKBBBBBBBBBBKKBBBK..",
    ".KBBBBBBBBBBBBBBBBBBBBBBK.",
    "KBBBCCCCCCCBBBBCCCCCCCBBBK",
    "KBBCKKKKKCCCCCCCCKKKKKCBBK",
    "KBBKWWWWWKCCCCCCKWWWWWKBBK",
    "KKKKWWEEWKKKKKKKKWWEEWKKKK",
    "KBBKWEEEWKCCOOCCKWEEEWKBBK",
    "KBBKWWWWWKCCOOCCKWWWWWKBBK",
    "KBBCKKKKKCCCRRCCCKKKKKCBBK",
    ".KBCCCCCCCCCCCCCCCCCCCCBK.",
    "KQRRRRRRRRRRRRRRRRRRRRRRQK",
    "KQQRRRRRRRRRRRRRRRRRRRRQQK",
    "KBBBBBcCCCCCCCCCCCCcBBBBBK",
    ".KKKKKKKKKKKKKKKKKKKKKKKK.",
)

# Tiny badge owl. 16 cols x 7 rows.
MINI = (
    "..KK........KK..",
    ".KBBKKKKKKKKBBK.",
    "KBBBBBBBBBBBBBBK",
    "KBKKKBBBBBBKKKBK",
    "KKWEWKKKKKKWEWKK",
    "KKWEWKCOOCKWEWKK",
    "KBKKKCCOOCCKKKBK",
    "KBCCCCCCCCCCCCBK",
    "KQRRRRRRRRRRRRQK",
    ".KBcCCCCCCCCcBK.",
    "..KBcCCCCCCcBK..",
    "...KKKKKKKKKK...",
    "....KOK..KOK....",
)


def _pixel_text(art: tuple[str, ...]) -> Text:
    rows = list(art)
    if len(rows) % 2:
        rows.append("." * len(rows[0]))
    text = Text(no_wrap=True)
    for top_row, bottom_row in zip(rows[::2], rows[1::2], strict=True):
        for top, bottom in zip(top_row, bottom_row, strict=True):
            fg, bg = PALETTE.get(top), PALETTE.get(bottom)
            if fg:
                text.append("▀", Style(color=fg, bgcolor=bg))
            elif bg:
                text.append("▄", Style(color=bg))
            else:
                text.append(" ")
        text.append("\n")
    text.rstrip()
    return text


class Mascot:
    """Renders pixel art, or nothing when the output can't encode block characters."""

    def __init__(self, art: tuple[str, ...] = HERO) -> None:
        self.art = art

    def __rich_console__(self, console: Console, options: ConsoleOptions) -> RenderResult:
        if options.encoding.lower().startswith("utf"):
            yield _pixel_text(self.art)


def mascot(art: tuple[str, ...] = HERO) -> Mascot:
    return Mascot(art)


def banner() -> Table:
    from hedwig import __version__

    title = Text.assemble(
        ("HEDWIG\n", "bold #f5bd2a"),
        ("threat early warning\n", "italic"),
        (f"v{__version__}", "dim"),
    )
    grid = Table.grid(padding=(0, 3))
    grid.add_column()
    grid.add_column(vertical="middle")
    grid.add_row(mascot(), title)
    return grid
