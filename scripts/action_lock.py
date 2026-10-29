"""Derive the action's runtime/build subset from the reviewed development lock."""

import argparse
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = {
    "anyio", "attrs", "certifi", "h11", "httpcore", "httpx", "idna", "jsonschema",
    "jsonschema-specifications", "referencing", "rpds-py", "typing-extensions",
    "packaging", "setuptools", "wheel",
}


def action_lock(source: str) -> str:
    blocks = re.split(r"(?m)(?=^[a-z][a-z0-9-]*==)", source)
    selected = {}
    for block in blocks:
        match = re.match(r"([a-z][a-z0-9-]*)==", block)
        if match and match[1] in PACKAGES:
            if match[1] in selected or "--hash=sha256:" not in block:
                raise ValueError("duplicate or unhashed action dependency")
            selected[match[1]] = block.rstrip()
    if set(selected) != PACKAGES:
        raise ValueError("action dependencies missing from reviewed lock")
    return "# Derived by scripts/action_lock.py from requirements-dev.lock; no new dependency versions.\n" + "\n".join(
        selected[name] for name in sorted(selected)
    ) + "\n"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = action_lock((ROOT / "requirements-dev.lock").read_text(encoding="utf-8"))
    path = ROOT / "requirements-action.lock"
    if args.check:
        if path.read_text(encoding="utf-8") != expected:
            raise SystemExit("Action dependency subset drifted from the reviewed development lock")
    else:
        path.write_text(expected, encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
