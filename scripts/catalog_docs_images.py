"""Bind visually reviewed, metadata-free documentation media to their bytes.

Run only after inspecting the images; a hash cannot establish pixel confidentiality.
"""
import json
from pathlib import Path

from finassist.publication import verify_public_image
from finassist.security import digest

root = Path(__file__).resolve().parent.parent
images = {}
for path in sorted([*(root / "docs/images").glob("*.png"), *(root / "docs/images").glob("hero.gif")]):
    expected = digest(path.read_bytes())
    verify_public_image(path, expected)
    images[path.relative_to(root).as_posix()] = expected
(root / "docs/images/manifest.json").write_text(json.dumps({"schema_version": 1, "images": images}, indent=2) + "\n", encoding="utf-8", newline="\n")
