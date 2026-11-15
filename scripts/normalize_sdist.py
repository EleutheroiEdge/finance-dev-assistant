"""Re-pack a built sdist so that two builds of one tree give the same bytes: its directories and files, sorted, each
dated SOURCE_DATE_EPOCH, owned by no one, with a plain mode, in a gzip stream that records no time. A link or a
special file refuses. The release builds sdists this way in two jobs and publishes only when the bytes agree.

usage: normalize_sdist.py DIST (rewrites DIST's one .tar.gz in place)"""

import gzip
import io
import os
from pathlib import Path
import re
import sys
import tarfile

# A zip file cannot date anything before 1980, so neither can a wheel; the sdist is held to the same range.
EARLIEST = 315532800


def release_epoch(value):
    """SOURCE_DATE_EPOCH as a release sets it: a whole number of seconds, from 1980 on."""
    if not re.fullmatch(r"[0-9]+", value or "") or int(value) < EARLIEST:
        raise ValueError("SOURCE_DATE_EPOCH must be a whole number of seconds, from 1980 on")
    return int(value)


def normalized(raw, epoch):
    """The canonical bytes of one sdist."""
    release_epoch(str(epoch))
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as source:
        members = []
        for member in source.getmembers():
            if not (member.isfile() or member.isdir()):
                raise ValueError("an sdist holds a link or a special file")
            members.append((member.name, member, source.extractfile(member).read() if member.isfile() else None))
    if len({name for name, _member, _data in members}) != len(members):
        raise ValueError("an sdist repeats a member")
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, member, data in sorted(members, key=lambda item: item[0]):
            entry = tarfile.TarInfo(name)
            entry.mtime, entry.uid, entry.gid, entry.uname, entry.gname = epoch, 0, 0, "", ""
            if data is None:
                entry.type, entry.mode = tarfile.DIRTYPE, 0o755
                archive.addfile(entry)
            else:
                entry.mode, entry.size = (0o755 if member.mode & 0o111 else 0o644), len(data)
                archive.addfile(entry, io.BytesIO(data))
    output = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=output, compresslevel=9, mtime=0) as compressed:
        compressed.write(stream.getvalue())
    return output.getvalue()


def main():
    sdists = sorted(Path(sys.argv[1]).glob("*.tar.gz"))
    if len(sdists) != 1:
        raise SystemExit("expected exactly one sdist")
    epoch = release_epoch(os.environ.get("SOURCE_DATE_EPOCH"))
    sdists[0].write_bytes(normalized(sdists[0].read_bytes(), epoch))
    print(sdists[0].name, "normalized")


if __name__ == "__main__":
    main()
