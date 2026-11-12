"""Compatibility entry point for the configuration schema generator."""
import sys

from generate_document_schemas import main


if __name__ == "__main__":
    main(["--kind", "config", *sys.argv[1:]])
