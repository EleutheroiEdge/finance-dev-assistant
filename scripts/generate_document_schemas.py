"""Generate public and packaged document schemas from runtime contracts, offline."""
from pathlib import Path

from finassist.document_schemas import SCHEMA_FILES, document_schema_text

root = Path(__file__).resolve().parent.parent
for kind, name in SCHEMA_FILES.items():
    for directory in (root / "schemas", root / "src/finassist/resources"):
        directory.mkdir(parents=True, exist_ok=True)
        (directory / name).write_text(document_schema_text(kind), encoding="utf-8", newline="\n")
