"""Verify explicitly catalogued public documentation images, never private inputs.

Hashes bind reviewed images to the manifest. They do not classify pixel content;
maintainers must inspect images for private information before committing them.
"""

import json
from pathlib import Path
import re
import struct
import zlib

from .errors import AssistantError
from .security import digest, regular_path


def public_images(repo: Path, tracked: set[str]) -> dict:
    name = "docs/images/manifest.json"
    if name not in tracked:
        return {}
    path = regular_path(repo / name)
    if not path.is_file() or path.stat().st_size > 64_000:
        raise AssistantError("public_image_manifest_invalid")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or set(data) != {"schema_version", "images"} or type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise AssistantError("public_image_manifest_invalid")
    images = data["images"]
    if not isinstance(images, dict) or len(images) > 32:
        raise AssistantError("public_image_manifest_invalid")
    for name, expected in images.items():
        if (not re.fullmatch(r"docs/images/(?:[a-z0-9-]+\.png|hero\.gif)", name) or name not in tracked
                or not isinstance(expected, str) or not re.fullmatch(r"[a-f0-9]{64}", expected)):
            raise AssistantError("public_image_manifest_invalid")
    return images


def verify_public_png(path: Path, expected: str) -> None:
    path = regular_path(path)
    if not path.is_file() or path.stat().st_size > 2_000_000:
        raise AssistantError("public_image_too_large")
    data = path.read_bytes()
    if digest(data) != expected:
        raise AssistantError("public_image_hash_mismatch")
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise AssistantError("public_image_invalid")
    offset, kinds = 8, []
    while offset < len(data):
        if offset + 12 > len(data):
            raise AssistantError("public_image_invalid")
        length = struct.unpack(">I", data[offset:offset + 4])[0]
        kind = data[offset + 4:offset + 8]
        body = data[offset + 8:offset + 8 + length]
        end = offset + 12 + length
        if (end > len(data) or kind not in {b"IHDR", b"IDAT", b"IEND"}
                or zlib.crc32(kind + body) != struct.unpack(">I", data[end - 4:end])[0]):
            raise AssistantError("public_image_metadata_or_format_invalid")
        if kind == b"IHDR":
            if kinds or length != 13:
                raise AssistantError("public_image_invalid")
            width, height = struct.unpack(">II", body[:8])
            if not 1 <= width <= 4096 or not 1 <= height <= 4096:
                raise AssistantError("public_image_invalid")
        if kind == b"IEND" and (length or end != len(data)):
            raise AssistantError("public_image_invalid")
        kinds.append(kind)
        offset = end
    if not kinds or kinds[0] != b"IHDR" or kinds[-1] != b"IEND" or b"IDAT" not in kinds:
        raise AssistantError("public_image_invalid")


def verify_public_image(path: Path, expected: str) -> None:
    """Verify catalogued PNGs or the single bounded, metadata-free demo GIF."""
    if path.name != "hero.gif":
        verify_public_png(path, expected)
        return
    path = regular_path(path)
    if not path.is_file() or path.stat().st_size >= 3_000_000:
        raise AssistantError("public_image_too_large")
    data = path.read_bytes()
    if digest(data) != expected:
        raise AssistantError("public_image_hash_mismatch")
    verify_public_gif(data)


def verify_public_gif(data: bytes) -> None:
    """Check GIF framing, dimensions, duration and a narrow extension allowlist.

    As with PNG checks, framing is not a pixel-content privacy classifier.
    Comment, plain-text and arbitrary application extensions are refused.
    """
    def invalid():
        raise AssistantError("public_image_metadata_or_format_invalid")

    offset = 0

    def take(length):
        nonlocal offset
        if offset + length > len(data):
            invalid()
        block = data[offset:offset + length]
        offset += length
        return block

    def blocks():
        result = bytearray()
        while True:
            size = take(1)[0]
            if not size:
                return bytes(result)
            result.extend(take(size))

    if take(6) not in {b"GIF87a", b"GIF89a"}:
        invalid()
    width, height, packed, _background, _aspect = struct.unpack("<HHBBB", take(7))
    if not 1 <= width <= 4096 or not 1 <= height <= 4096:
        invalid()
    if packed & 128:
        take(3 * 2 ** ((packed & 7) + 1))
    frames, duration, delay = 0, 0, None
    loop_seen = False
    while True:
        kind = take(1)
        if kind == b";":
            if offset != len(data) or frames < 2 or not 0 < duration < 1500 or delay is not None:
                invalid()
            return
        if kind == b"!":
            extension = take(1)
            if extension == b"\xf9":
                if delay is not None or take(1) != b"\x04":
                    invalid()
                flags, delay, _transparent = struct.unpack("<BHB", take(4))
                if flags & 0b11100010 or not delay or take(1) != b"\0":
                    invalid()
            elif extension == b"\xff":
                if loop_seen or frames or take(1) != b"\x0b" or take(11) != b"NETSCAPE2.0":
                    invalid()
                if blocks() != b"\x01\0\0":
                    invalid()
                loop_seen = True
            else:
                invalid()
        elif kind == b",":
            left, top, frame_width, frame_height, packed = struct.unpack("<HHHHB", take(9))
            if (not frame_width or not frame_height or left + frame_width > width
                    or top + frame_height > height or packed & 0b00011000 or delay is None):
                invalid()
            if packed & 128:
                take(3 * 2 ** ((packed & 7) + 1))
            if not 2 <= take(1)[0] <= 8 or not blocks():
                invalid()
            frames += 1
            duration += delay
            delay = None
            if frames > 300 or duration >= 1500:
                invalid()
        else:
            invalid()
