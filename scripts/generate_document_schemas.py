"""Generate or check public and packaged schemas against the runtime contracts."""
import argparse
from pathlib import Path

from finassist.document_schemas import SCHEMA_FILES, document_schema_text


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Refuse drift without writing files")
    parser.add_argument("--kind", choices=tuple(SCHEMA_FILES), help="Limit generation to one contract")
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parent.parent
    mismatches = []
    for kind in ([args.kind] if args.kind else SCHEMA_FILES):
        text = document_schema_text(kind)
        for directory in (root / "schemas", root / "src/finassist/resources"):
            path = directory / SCHEMA_FILES[kind]
            if args.check:
                if not path.is_file() or path.read_text(encoding="utf-8") != text:
                    mismatches.append(str(path.relative_to(root)))
            else:
                directory.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8", newline="\n")
    if mismatches:
        raise SystemExit("Schema drift: " + ", ".join(mismatches))


if __name__ == "__main__":
    main()
