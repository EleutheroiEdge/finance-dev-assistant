"""The source languages `init --detect` recognises, and which of them the credential screen reads as code.

A repository's own source decides what is reviewable, not a fixed list: when its source files use suffixes outside
the default `text_suffixes`, detection proposes the default list plus those suffixes, for the configuration and the
gate policy alike, and says so. A person still reads and writes the draft.

The credential screen reads the languages in CODE_SUFFIXES as code: an expression in a credential-named field is
told apart from a literal. Every other suffix gets the stricter text rules, where a credential-named value is refused
whatever it is. Data and binary formats stay refused whatever a list says.
"""

from __future__ import annotations

from .code_text import LANGUAGES

# Suffix -> language. Lower case, as text_suffixes requires. Only programming languages: a configuration or data
# format is not proposed as source.
SOURCE_LANGUAGES = {
    ".py": "Python", ".pyi": "Python",
    ".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript", ".jsx": "JavaScript",
    ".ts": "TypeScript", ".mts": "TypeScript", ".cts": "TypeScript", ".tsx": "TypeScript",
    ".go": "Go", ".java": "Java", ".kt": "Kotlin", ".kts": "Kotlin", ".sql": "SQL",
    ".rs": "Rust", ".sh": "Shell", ".bash": "Shell", ".zsh": "Shell",
    ".c": "C", ".h": "C", ".cc": "C++", ".cpp": "C++", ".cxx": "C++", ".hpp": "C++", ".hh": "C++", ".hxx": "C++",
    ".cs": "C#", ".fs": "F#", ".vb": "Visual Basic",
    ".rb": "Ruby", ".php": "PHP", ".swift": "Swift", ".m": "Objective-C", ".mm": "Objective-C",
    ".scala": "Scala", ".groovy": "Groovy", ".clj": "Clojure", ".dart": "Dart",
    ".ex": "Elixir", ".exs": "Elixir", ".erl": "Erlang", ".hs": "Haskell", ".ml": "OCaml", ".fsx": "F#",
    ".lua": "Lua", ".r": "R", ".jl": "Julia", ".pl": "Perl", ".pm": "Perl", ".ps1": "PowerShell",
    ".vue": "Vue", ".svelte": "Svelte", ".zig": "Zig", ".nim": "Nim",
}
# Read as code by the credential screen: Python by its own parser, the rest by code_text's language table.
CODE_SUFFIXES = frozenset({".py", ".pyi", *LANGUAGES})


def proposed_suffixes(found: set[str], defaults) -> tuple[frozenset[str], list[str], list[str]]:
    """The reviewable suffixes to propose for a repository whose source uses `found`: the defaults plus every
    recognised source suffix outside them. Also returns the added suffixes and those of them read by the text
    rules only."""
    added = sorted(suffix for suffix in found if suffix in SOURCE_LANGUAGES and suffix not in defaults)
    return frozenset(defaults) | set(added), added, [suffix for suffix in added if suffix not in CODE_SUFFIXES]
