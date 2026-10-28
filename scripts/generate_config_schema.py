"""Regenerate both public and packaged configuration schemas without network IO."""
from pathlib import Path
from finassist.config_schema import schema_text

root = Path(__file__).resolve().parent.parent
for path in [root / "schemas/finassist.schema.json", root / "src/finassist/resources/finassist.schema.json"]:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(schema_text(), encoding="utf-8", newline="\n")
