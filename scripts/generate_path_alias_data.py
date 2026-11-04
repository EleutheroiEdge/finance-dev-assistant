"""Generate pinned ASCII-relevant Unicode aliases from inspected local inputs.

No network access: obtain the three public files named below separately, then run
python scripts/generate_path_alias_data.py INPUT_DIRECTORY OUTPUT_PYTHON_FILE.
"""
import argparse
import hashlib
from pathlib import Path

SOURCES = {
    "confusables.txt": ("https://www.unicode.org/Public/18.0.0/security/confusables.txt",
                        "6ed3ee967c9dfdf6677d563c9985182fbc50a2efb7d6059cd57b2e2ce18f5b92"),
    "DerivedCoreProperties.txt": ("https://www.unicode.org/Public/18.0.0/ucd/DerivedCoreProperties.txt",
                                  "09c928886a178fcafd93c29e4bd59073a058e5a100b716d425cb563ab50f68c9"),
    "UNICODE-LICENSE.txt": ("https://www.unicode.org/license.txt",
                           "e7a93b009565cfce55919a381437ac4db883e9da2126fa28b91d12732bc53d96"),
}


def generate(directory: Path) -> str:
    inputs = {}
    for name, (_, expected) in SOURCES.items():
        raw = (directory / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError("Unicode input digest mismatch: " + name)
        inputs[name] = raw.decode("utf-8")
    aliases = {}
    for line in inputs["confusables.txt"].splitlines():
        fields = line.split("#", 1)[0].strip().split(";")
        if len(fields) < 2:
            continue
        source = [int(value, 16) for value in fields[0].split()]
        target = "".join(chr(int(value, 16)) for value in fields[1].split())
        if len(source) == 1 and target.isascii():
            aliases[source[0]] = target
    ranges = []
    for line in inputs["DerivedCoreProperties.txt"].splitlines():
        fields = line.split("#", 1)[0].strip().split(";")
        if len(fields) < 2 or fields[1].strip() != "Default_Ignorable_Code_Point":
            continue
        ends = [int(value, 16) for value in fields[0].strip().split("..")]
        start, end = ends[0], ends[-1]
        if ranges and start == ranges[-1][1] + 1:
            ranges[-1] = (ranges[-1][0], end)
        else:
            ranges.append((start, end))
    header = ('"""Generated Unicode18 ASCII-target confusables and default-ignorable ranges.\n'
              'Regenerate with scripts/generate_path_alias_data.py; do not hand edit.\n'
              'This is a bounded reserved-name comparison table, not full UTS39.\n\n')
    for name, (url, sha) in SOURCES.items():
        header += f"{name}: {url}\nSHA256: {sha}\n"
    header += "\n" + inputs["UNICODE-LICENSE.txt"].strip() + '\n"""\n\n'
    rows = [f"    {key}: {value!r}," for key, value in sorted(aliases.items())]
    # Small rows keep the generated file below the normal source screening limit.
    return (header + "ASCII_CONFUSABLES = {\n" + "\n".join(rows) + "\n}\n\n"
            + "DEFAULT_IGNORABLE_RANGES = (\n"
            + "".join(f"    ({start}, {end}),\n" for start, end in ranges) + ")\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input_directory", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.write_text(generate(args.input_directory), encoding="utf-8", newline="\n")
