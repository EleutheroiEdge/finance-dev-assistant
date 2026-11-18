"""Rows with a mark inside a number for the figure-source corpus's --edge-spellings profile (figure_source_corpus.py).

A visible look-alike of a grouping or decimal mark, a currency sign, bracket or percent sign, or a dash or minus sign,
written inside a number, beside a space, a hidden mark or a quoted break, an exponent mark or its sign, a grouping or
decimal mark, or right before the digits it may start. Each row is drawn from the values given, so what a correct
reading lists, or the code that must refuse the file, is known from the draw. Every value is made up.
"""

from __future__ import annotations

from collections.abc import Callable
from decimal import Decimal
import random

# Visible look-alikes of a grouping or decimal mark that no reading takes for one.
LOOK_ALIKES = ("\u00b7", "\u201a", "\ufe50", "\u3001", "\u060c", "\u2032", "\u00b4", "`", "\uff07", "\u02bc",
               "\u02b9", "\u02bb", "\u02c8", "\u2024", "\u2219", "\ua78c")
# Signs that stand beside amounts and are marks inside one: currency signs, a full-width bracket, percent signs.
SIGNS = ("\u20ac", "\u00a3", "\u20b9", "\uff08", "\uff09", "\u066a", "\u2030")
# Dashes and minus signs, which part two numbers except as an exponent's sign.
DASHES = ("\u2212", "\u2013", "\u2010", "\ufe63", "\uff0d")
# Marks that show as nothing or as a space that groups no digits.
# A filler and a modifier letter, which look like letters but part nothing (beyond a comma beside a sign).
FILLED = ("\u3164", "\u02bc")
# Before digits beside a look-alike: a hidden mark, a thin and a no-break space.
BEFORE_DIGITS = ("\u200b", "\u2009", "\u00a0")
HIDING = ("\u200b", "\u2060", "\u00ad", "\u2008", "\u3000")


def look_alike_row(rng: random.Random, whole: str, fraction: str, mark: str, delimiter: str | None, eol: str,
                   row: Callable[[str], str]) -> tuple[str, str, list[tuple[Decimal, str | None]]]:
    """One row with a mark inside a number: the text to append, the code the file must be refused with ("" when it
    must be read), and each value a correct reading lists with the spelling it is written in, if one."""
    alike, shape, value = rng.choice(LOOK_ALIKES), rng.random(), Decimal(f"{whole}.{fraction}")
    other = "," if mark == "." else "."
    breaks = ("\n", "\t") if delimiter is not None else ()

    def quoted(cell: str) -> str:  # quoted, so a line break or tab is inside the field
        cell = '"' + cell + '"'
        return cell + eol if delimiter is None else f"Memo{delimiter}{cell}{eol}"

    def grouped(group: str) -> str:
        head = len(whole) % 3 or 3
        return whole[:head] + "".join(group + whole[at:at + 3] for at in range(head, len(whole), 3))

    if shape < 0.1:  # two marks of one class
        cell = f"EUR {grouped(chr(0x066C) if mark == '.' else chr(0x066B))}{mark}{fraction}"
    elif shape < 0.2:  # beside a no-break or hidden space, or a quoted line break or tab; an ASCII space parts numbers
        gap = rng.choice(("\u00a0", "\u202f", "\u2008", "\u3000") + breaks)
        cell = rng.choice((f"Total {whole[:-3]}{alike}{gap}{whole[-3:]}{mark}{fraction}",  # or both sides
                           f"Total {whole[:-3]}{gap}{alike}{gap}{whole[-3:]}{mark}{fraction}",
                           f"Total {whole[:-3]}{gap}\u20ac{whole[-3:]}{mark}{fraction}"))
        if gap in breaks:
            return quoted(cell), "hidden_mark", [(value, None)]
    elif shape < 0.27 and mark == ".":  # beside an exponent mark or its sign
        cell, value = f"EUR {whole[0]}.{whole[1:]}{alike}e{len(whole) - 1}", Decimal(whole)
    elif shape < 0.3:  # right before the digits and beside a hidden mark or a space: refused, its fraction can't be read
        cell = f"USD{alike}{rng.choice(BEFORE_DIGITS)}{whole}"
    elif shape < 0.33 and mark == "." and rng.random() < 0.5:  # before digits with an exponent: the fraction's value
        return row(f"Total {alike}{whole}e3"), "", [(Decimal("0." + whole) * 1000, None)]
    elif shape < 0.33:  # right before the digits, as a decimal point would be: both readings are listed
        cell = f"{rng.choice(('USD', 'Total '))}{alike}{whole}"  # never after a comma, a decimal one read every way
        return row(cell), "", [(Decimal(whole), cell), (Decimal("0." + whole), None)]
    elif shape < 0.5:  # a sign beside a decimal or grouping mark, an exponent mark or its sign, or the grave accent
        sign, separator = rng.choice(SIGNS), rng.choice(("'", "`", other))
        cells = [f"EUR {whole}{sign}{mark}{fraction}", f"EUR {whole}{mark}{sign}{fraction}",
                 f"EUR {whole[:-3]}{separator}{sign}{whole[-3:]}{mark}{fraction}",
                 f"EUR {whole[:-3]}{sign}{separator}{whole[-3:]}{mark}{fraction}",
                 f"EUR {whole[:-3]}{rng.choice(FILLED)},{sign}{whole[-3:]}{mark}{fraction}"]
        if mark == ".":
            head, tail = f"EUR {whole[0]}.{whole[1:]}", len(whole) - 1
            cells += [f"{head}{sign}e{tail}", f"{head}e{sign}{tail}", f"{head}e+{sign}{tail}", f"{head}E{sign}-{tail}",
                      f"{head}{sign},e{tail}"]
        cell = rng.choice(cells)
    elif shape < 0.65:  # beside an ASCII space and a hidden mark, a quoted break or a sign: not parted by the space
        hidden, sign = rng.choice(HIDING + breaks), rng.choice(SIGNS)
        cell = rng.choice((f"Total {alike}{hidden}{whole}",
                           f"Total {whole[:-3]} {alike}{hidden}{whole[-3:]}{mark}{fraction}",
                           f"Total {whole[:-3]}{hidden}{alike} {whole[-3:]}{mark}{fraction}",
                           f"Total {alike}{sign}{whole}", f"Total{alike}{sign}{whole}"))
        if hidden in breaks and hidden in cell:
            return quoted(cell), "hidden_mark", [(value, None)]
    elif shape < 0.75 and mark == ".":  # a dash or minus as an exponent's sign, or beside a hidden mark
        dash, hidden, head = rng.choice(DASHES), rng.choice(HIDING), f"EUR {whole[0]}.{whole[1:]}"
        tail = len(whole) - 1
        cell = rng.choice((f"{head}e{dash}{tail}", f"{head}E{dash}{tail}", f"{head}e{hidden}{dash}{tail}",
                           f"{head}e{rng.choice(SIGNS)}{dash}{tail}", f"Fund {whole[:4]}{dash}{hidden}{whole[4:]}"))
    else:
        cell = rng.choice((f"EUR {grouped(alike)}{mark}{fraction}", f"{grouped(alike)}{mark}{fraction}",
                           f"Total {grouped(alike)}{mark}{fraction} net", f"GBP {whole}{alike}{fraction}"))
    return row(cell), "hidden_mark", [(value, None)]
