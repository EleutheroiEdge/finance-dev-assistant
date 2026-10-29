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
from finassist.publication import public_images, verify_public_image, verify_public_png
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
    assert set(images) == {f"docs/images/dashboard-{name}.png" for name in ["configuration", "statistics", "health"]} | {"docs/images/hero.gif", "docs/images/how-it-works.png", "docs/images/social-preview.png"}
    for name, expected in images.items():
        verify_public_image(ROOT / name, expected)


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
    assert "Local-first, no telemetry" in readme and "pipx install finledgerpoli" in readme
    assert "pip install finledgerpoli" in readme
    assert "After the first PyPI" not in readme and "PyPI badge will be added after" not in readme
    assert "https://img.shields.io/pypi/v/finledgerpoli" in readme
    assert "<h3>From source</h3>" in readme and "from a source checkout with `asciinema play" in readme
    assert "All displayed spend" in readme and "fictional" in readme


def gif(delay=20):
    header = b"GIF89a" + struct.pack("<HHBBB", 1, 1, 128, 0, 0) + b"\0\0\0\xff\xff\xff"
    frame = (b"!\xf9\x04" + struct.pack("<BHB", 0, delay, 0) + b"\0,"
             + struct.pack("<HHHHB", 0, 0, 1, 1, 0) + b"\x02\x02D\x01\0")
    return header + frame * 2 + b";"


@pytest.mark.parametrize("variant", ["comment", "application", "text", "truncated", "trailing", "duration", "dimensions", "hash"])
def test_public_gif_rejects_metadata_corruption_and_unbounded_media(tmp_path, variant):
    data = gif(delay=750 if variant == "duration" else 20)
    if variant in {"comment", "application", "text"}:
        extension = {"comment": b"!\xfe\x03bad\0", "application": b"!\xff\x0bPRIVATEINFO\0", "text": b"!\x01\0"}[variant]
        data = data[:-1] + extension + data[-1:]
    if variant == "truncated":
        data = data[:-2]
    if variant == "trailing":
        data += b"private"
    if variant == "dimensions":
        data = data[:6] + struct.pack("<H", 5000) + data[8:]
    path = tmp_path / "hero.gif"
    path.write_bytes(data)
    with pytest.raises(AssistantError):
        verify_public_image(path, "0" * 64 if variant == "hash" else digest(data))


def test_publication_scan_accepts_only_catalogued_bounded_gif(repository, capsys):
    root = repository[0]
    path = root / "docs/images/hero.gif"
    path.parent.mkdir(parents=True)
    path.write_bytes(gif())
    manifest = path.parent / "manifest.json"
    manifest.write_text(json.dumps({"schema_version": 1, "images": {"docs/images/hero.gif": digest(gif())}}), encoding="utf-8")
    command(root, "add", "docs")
    assert main(["scan", "--repo", str(root)]) == 0
    assert json.loads(capsys.readouterr().out)["passed"]
    path.write_bytes(gif() + b"private")
    assert main(["scan", "--repo", str(root)]) == 1
    assert json.loads(capsys.readouterr().out)["findings"][0]["code"] == "public_image_hash_mismatch"


def test_marketing_media_dimensions_and_size():
    social = (ROOT / "docs/images/social-preview.png").read_bytes()
    assert struct.unpack(">II", social[16:24]) == (1280, 640)
    assert len(social) < 1_000_000
    hero = (ROOT / "docs/images/hero.gif").read_bytes()
    assert len(hero) < 3_000_000
    verify_public_image(ROOT / "docs/images/hero.gif", digest(hero))
