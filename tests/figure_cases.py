"""Generated cases for the confidential-figure screen. Every figure here is made up.

One figure is written in every notation the screen reads, given signs and units, and placed in
many surroundings: the screen must refuse each case. A second set holds near misses, which
it must pass. The same cases are wrapped as Python, JSON and HTML text.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
import html
from itertools import product
import json
import unicodedata

FIGURES = ("48213.57", "1234567.89", "905.125", "73026", "6729102.5", "0.004821", "250000", "19.99")


@dataclass(frozen=True)
class Case:
    figure: str
    notation: str
    decoration: str
    surrounding: str
    text: str

    @property
    def label(self) -> str:
        return f"{self.figure} | {self.notation} | {self.decoration} | {self.surrounding}"


def _grouped(whole: str, separator: str) -> str:
    head = len(whole) % 3 or 3
    return separator.join([whole[:head]] + [whole[i:i + 3] for i in range(head, len(whole), 3)])


def _digits(text: str, zero: str) -> str:
    return "".join(chr(ord(zero) + int(c)) if c.isdigit() else c for c in text)


def _value(text: str, decimal_mark: str) -> Decimal:
    """The value of one notation, read by its own rules, to check the generator itself."""
    plain = "".join(str(unicodedata.decimal(c)) if c.isdecimal() else c for c in text)
    for mark, role in (("\uff0e", "."), ("\u066c", "."), ("\uff0c", ","), ("\u066b", ",")):
        plain = plain.replace(mark, role)
    if decimal_mark == ",":
        plain = plain.replace(".", " ").replace(",", ".")
    return Decimal("".join(c for c in plain if c.isdigit() or c in ".eE+-"))


def notations(figure: str) -> dict[str, str]:
    """The figure in every notation the screen reads as the same value."""
    whole, _, fraction = figure.partition(".")
    tail = "." + fraction if fraction else ""
    forms = {"plain": figure, "trailing zeros": whole + "." + fraction + "000", "zero padded": "000" + figure,
             "underscores in odd places": "_".join(whole) + ("." + "_".join(fraction) if fraction else "")}
    comma = {"decimal comma": whole + "," + fraction} if fraction else {}
    if len(whole) > 3:
        for name, separator in (("comma groups", ","), ("underscore groups", "_"), ("space groups", " "),
                                ("no-break space groups", "\u00a0"), ("narrow no-break space groups", "\u202f"),
                                ("thin space groups", "\u2009"), ("figure space groups", "\u2007"),
                                ("apostrophe groups", "'"), ("typographic apostrophe groups", "\u2019")):
            forms[name] = _grouped(whole, separator) + tail
        forms["comma groups, trailing zeros"] = _grouped(whole, ",") + "." + fraction + "00"
        forms["comma groups, zero padded"] = "0," + _grouped(whole.rjust(len(whole) + -len(whole) % 3, "0"), ",") + tail
        forms["fullwidth digits and marks"] = _digits(_grouped(whole, "\uff0c") + tail.replace(".", "\uff0e"), "\uff10")
        comma["point groups"] = _grouped(whole, ".") + ("," + fraction if fraction else "")
        if fraction:
            comma["space groups, decimal comma"] = _grouped(whole, " ") + "," + fraction
            comma["Arabic digits and marks"] = _digits(_grouped(whole, "\u066c") + "\u066b" + fraction, "\u0660")
    if not whole.strip("0"):
        forms["leading point"] = "." + fraction
    digits = (whole + fraction).lstrip("0") or "0"
    exponent = len(whole.lstrip("0")) - 1 if whole.strip("0") else -(len(fraction) - len(fraction.lstrip("0")) + 1)
    mantissa = digits[0] + ("." + digits[1:] if len(digits) > 1 else "")
    forms["exponent"] = f"{mantissa}e{exponent}"
    forms["exponent, capital and signed"] = f"{mantissa}E{exponent:+d}"
    forms["whole mantissa, negative exponent"] = f"{digits}e-{len(fraction)}" if fraction else f"{digits}0e-1"
    forms["Arabic-Indic digits"] = _digits(figure, "\u0660")
    forms["fullwidth digits"] = _digits(figure, "\uff10")
    assert all(_value(text, ".") == Decimal(figure) for text in forms.values()), figure
    assert all(_value(text, ",") == Decimal(figure) for text in comma.values()), figure
    return {**forms, **comma}


DECORATIONS = {
    "bare": "{}", "dollar": "${}", "euro": "\u20ac{}", "pound": "\u00a3{}", "yen": "\u00a5{}",
    "minus": "-{}", "plus": "+{}", "minus dollar": "-${}", "dollar minus": "$-{}",
    "accounting": "({})", "accounting dollar": "(${})", "dollar accounting": "$({})", "minus accounting": "-({})",
    "currency code before": "USD {}", "currency code after": "{} USD", "currency code glued": "USD{}",
    "percent": "{}%", "trailing minus": "{}-", "credit suffix": "{} CR", "approximately": "~{}",
    "plus-minus": "\u00b1{}", "less than": "<{}", "at least": ">={}", "hash": "#{}", "at": "@{}",
    "bold": "**{}**", "code span": "`{}`", "italic": "_{}_", "unit glued": "{}M", "letter glued before": "A{}",
    "identifier glued before": "id_{}", "multiplier": "{}x", "unicode minus": "\u2212{}",
}

SURROUNDINGS = {
    "alone": "{}", "assignment": "x = {}", "in a sentence": "the total was {} that day", "sentence end": "It was {}.",
    "comma after": "was {}, then fell", "semicolon after": "total: {};", "colon after": "{}: the total",
    "question": "was it {}?", "exclamation": "{}!",
    "open parenthesis only": "netted figure ({} before)", "close parenthesis only": "cash after, before {}).",
    "parentheses": "({})", "double parentheses": "(({}))", "call first argument": "f({}, 2)",
    "call last argument": "f(1, {})", "call only argument": "round({})", "nested call": "g(f({}))",
    "square brackets": "[{}]", "list first": "[{}, 7]", "list last": "[7, {}]", "list compact": "[7,{},9]",
    "braces": "{{{}}}", "angle brackets": "<{}>", "double quotes": '"{}"', "single quotes": "'{}'",
    "backticks": "`{}`", "table cell": "| {} |", "tab separated": "a\t{}\tb", "text cells": "a,{},b",
    "quoted cells": '"a","{}","b"', "number cells with spaces": "7, {}, 9", "number columns": "7 {} 9",
    "wide number columns": "7  {}  9", "after a three-digit column": "112 {}", "before a three-digit column": "{} 112",
    "key equals": "amount={}", "json member": '"amount": {},', "key colon": "amount:{}",
    "sum": "1+{}", "product": "{}*2", "difference": "{}-1", "subtracted": "1-{}", "quotient": "{}/3",
    "path segment": "/a/{}/b", "hyphenated": "a-{}-b", "after a dot": "x.{}", "after a version": "v1.{}",
    "line of its own": "before\n{}\nafter", "indented": "    {}", "html cell": "<td>{}</td>",
    "trailing period and quote": 'said "{}."', "ellipsis": "{}...", "range": "{}\u2013{}",
    "arrow": "0 -> {}", "equals glued": "={}", "comparison": "x>={}", "slash date like": "on 3/4: {}",
    "no-break space around": "x\u00a0{}\u00a0y", "crlf": "a\r\n{}\r\nb",
}
_OWN_MARKS = ".,' \u00a0\u2007\u2009\u202f\u2019\uff0c\uff0e\u066b\u066c"


def _framed(frame: str, decorated: str) -> str:
    return frame.replace("{}", "\0").replace("{{", "{").replace("}}", "}").replace("\0", decorated)


def must_refuse() -> list[Case]:
    """Every figure in every notation, decoration and surrounding."""
    cases = []
    for figure in FIGURES:
        for (notation, written), (decoration, around), (surrounding, frame) in product(
                notations(figure).items(), DECORATIONS.items(), SURROUNDINGS.items()):
            # Digits after a point are a fraction first. They are a number of their own only
            # when they carry their own fraction or groups, so `v1.73026` is not the figure 73026.
            if surrounding == "after a version" and (not any(c in written for c in _OWN_MARKS) or "e-" in written):
                continue
            cases.append(Case(figure, notation, decoration, surrounding, _framed(frame, around.format(written))))
    return cases


def must_pass() -> list[Case]:
    """Near misses: another value in the same surroundings. Refusing one is a false alarm."""
    cases = []
    plain = {name: DECORATIONS[name] for name in ("bare", "dollar", "accounting", "minus")}
    for figure in FIGURES:
        fraction = figure.partition(".")[2]
        near = {"last digit changed": figure[:-1] + ("7" if figure[-1] != "7" else "3"),
                "one more leading digit": "9" + figure.lstrip("0"),
                "first digit changed": ("7" if figure[0] != "7" else "3") + figure[1:]}
        if fraction:  # A listed whole number has no fraction to extend.
            near["one more fraction digit"] = figure + "4"
        for (name, value), (decoration, around), (surrounding, frame) in product(
                near.items(), plain.items(), SURROUNDINGS.items()):
            cases.append(Case(figure, name, decoration, surrounding, _framed(frame, around.format(value))))
    return cases


def as_python(text: str) -> dict[str, str]:
    """The text inside Python source, as comment and string text and as string values."""
    middle = len(text) // 2
    wrapped = {"string": f"note = {text!r}\n", "docstring": f"def f():\n    {text!r}\n    return 1\n",
               "ascii escapes": f"note = {ascii(text)}\n",
               "joined literals": f"note = ({text[:middle]!r}\n        {text[middle:]!r})\n",
               "bytes": f"note = {text.encode('utf-8')!r}\n"}
    if "\n" not in text and "\r" not in text:
        wrapped["comment"] = f"x = 1  # {text}\n"
    return wrapped


def as_json(text: str) -> str:
    """As json.dumps writes it by default: every non-ASCII character is an escape."""
    return json.dumps({"note": text})


def as_html(text: str) -> str:
    return "<p>" + html.escape(text).replace("\u00a0", "&nbsp;").replace("\u2009", "&thinsp;") + "</p>"
