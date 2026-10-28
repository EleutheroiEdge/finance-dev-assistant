"""Verify explicitly catalogued public documentation PNGs, never private inputs.

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
        if (not re.fullmatch(r"docs/images/[a-z0-9-]+\.png", name) or name not in tracked
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
