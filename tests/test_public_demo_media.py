"""Public media stays synthetic, integrity-bound and outside private image input."""
import json
from pathlib import Path
import struct
import zlib

import pytest

from conftest import command
from finassist.cli import main
from finassist.errors import AssistantError
from finassist.demo import run_demo
from finassist.publication import public_images, verify_public_png
from finassist.security import digest

ROOT = Path(__file__).resolve().parent.parent


def chunk(kind, body):
    return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))


def png(metadata=False):
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
            + (chunk(b"tEXt", b"Comment\0synthetic metadata") if metadata else b"")
            + chunk(b"IDAT", zlib.compress(b"\0\0\0\0")) + chunk(b"IEND", b""))


def test_shipped_screenshots_match_manifest_and_have_no_metadata():
    names = {path.relative_to(ROOT).as_posix() for path in (ROOT / "docs/images").glob("*")}
    images = public_images(ROOT, names)
    assert set(images) == {f"docs/images/dashboard-{name}.png" for name in ["configuration", "statistics", "health"]}
    for name, expected in images.items():
        verify_public_png(ROOT / name, expected)


@pytest.mark.parametrize("variant", ["changed", "unregistered", "metadata", "crc", "private"])
def test_publication_scan_rejects_unreviewed_or_invalid_images(repository, capsys, variant):
    root = repository[0]
    path = root / "docs/images/demo.png"
    path.parent.mkdir(parents=True)
    data = png(metadata=variant == "metadata")
    if variant == "crc":
        data = data[:-1] + b"x"
    path.write_bytes(data)
    entries = {"docs/images/demo.png": digest(data)}
    if variant == "changed":
        entries["docs/images/demo.png"] = "0" * 64
    if variant == "unregistered":
        entries = {}
    if variant == "private":
        entries = {"docs/images/../private.png": digest(data)}
    (path.parent / "manifest.json").write_text(json.dumps({"schema_version": 1, "images": entries}), encoding="utf-8", newline="\n")
    command(root, "add", "docs")
    status = main(["scan", "--repo", str(root)])
    output = capsys.readouterr()
    assert status in {1, 2}
    if status == 1:
        assert json.loads(output.out)["findings"]
    else:
        assert json.loads(output.err)["code"] == "public_image_manifest_invalid"


def test_publication_scan_accepts_only_explicitly_catalogued_png(repository, capsys):
    root = repository[0]
    path = root / "docs/images/demo.png"
    path.parent.mkdir(parents=True)
    data = png()
    path.write_bytes(data)
    (path.parent / "manifest.json").write_text(json.dumps({"schema_version": 1, "images": {"docs/images/demo.png": digest(data)}}), encoding="utf-8", newline="\n")
    command(root, "add", "docs")
    assert main(["scan", "--repo", str(root)]) == 0
    assert json.loads(capsys.readouterr().out)["passed"]
    with pytest.raises(AssistantError):
        verify_public_png(path, "0" * 64)


def test_recording_contains_real_synthetic_demo_json_without_host_identity():
    rows = [json.loads(line) for line in (ROOT / "docs/images/demo.cast.txt").read_text(encoding="utf-8").splitlines()]
    assert rows[0]["version"] == 2
    assert set(rows[0]) == {"version", "width", "height", "title", "env"}
    assert rows[0]["env"] == {"TERM": "xterm-256color"}
    text = "".join(row[2] for row in rows[2:])
    data = json.loads(text)
    assert data["status"] == "PASS" and data["data_class"] == "synthetic"
    assert data["model_called"] is False and data["trade_execution"] is False
    assert data == run_demo()
    assert all(row[1] == "o" for row in rows[1:])


def test_readme_keeps_release_and_media_claims_honest():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "Local-first, no telemetry" in readme and "pipx install finassist" in readme
    assert "After the first PyPI" in readme and "PyPI badge will be added after" in readme
    assert readme.count("](docs/images/dashboard-") == 3
    assert "All displayed spend" in readme and "fictional" in readme
