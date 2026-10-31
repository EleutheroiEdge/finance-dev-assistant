"""Base-pinned synthetic fixture exceptions; never an ordinary config capability."""
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from .config import Config, load_config
from .errors import AssistantError
from .scope import git, read_entry
from .security import (canonical, check_fixture_private, check_model_path, check_path,
                       check_text, digest, is_text_fixture)

FIXTURE_PROPERTIES = {
    "fixture_roots": {"type": "array", "maxItems": 128, "uniqueItems": True,
                      "items": {"type": "string", "minLength": 1, "maxLength": 512}},
    "fixture_max_file_bytes": {"type": "integer", "minimum": 1, "maximum": 2_000_000},
}
MARKER = ".finledgerpoli-synthetic"


class _MarkerReadConfig(Config):
    def check_path(self, path: str, **kwargs) -> str:
        # The single marker has no extension; all ordinary privacy rules remain.
        if PurePosixPath(path).name != MARKER:
            raise AssistantError("fixture_marker_path_invalid")
        return check_model_path(path, source_only=False)


@dataclass(frozen=True)
class PolicyFixtureConfig(Config):
    fixture_roots: tuple[str, ...] = ()
    fixture_max_file_bytes: int = 48_000
    fixture_markers: dict = field(default_factory=dict)

    def validate(self) -> Config:
        if type(self.fixture_max_file_bytes) is not int or not 1 <= self.fixture_max_file_bytes <= 2_000_000:
            raise AssistantError("invalid_fixture_limit")
        return super().validate()

    def check_path(self, path: str, **kwargs) -> str:
        # check_path applies the extra private checks only to fixture candidates.
        return check_path(path, denied_parts=self.denied_parts, text_suffixes=self.text_suffixes,
                          fixture_roots=self.fixture_roots, **kwargs)

    def file_byte_limit(self, path: str) -> int:
        return self.fixture_max_file_bytes if is_text_fixture(path, self.fixture_roots) else self.max_file_bytes

    def allows(self, path: str) -> bool:
        # Marker bytes qualify policy; they are never review context or recipe input.
        return path not in self.fixture_markers and super().allows(path)


def fixture_settings(repo: Path, base: str, options: dict) -> dict | None:
    roots = tuple(options.get("fixture_roots", ()))
    limit = options.get("fixture_max_file_bytes", 48_000)
    if type(limit) is not int or not 1 <= limit <= 2_000_000:
        raise AssistantError("invalid_fixture_limit")
    if not roots:
        return None
    markers = {}
    for root in roots:
        if any(char in root for char in "*?[]"):
            raise AssistantError("fixture_root_invalid")
        path = root.removesuffix("/")
        check_fixture_private(path)
        check_model_path(path, fixture_roots=(root,), source_only=False)
        entry = git(repo, "--literal-pathspecs", "ls-tree", "-z", base, "--", path, binary=True)
        if entry:
            mode, kind, _ = entry.split(b"\t", 1)[0].decode().split()
            if (root.endswith("/") and kind != "tree") or mode not in {"040000", "100644", "100755"}:
                raise AssistantError("linked_or_special_git_object")
        parts = PurePosixPath(path).parts
        if any(part in {"tests", "fixtures"} for part in parts):
            continue
        directory = PurePosixPath(path) if root.endswith("/") else PurePosixPath(path).parent
        marker = str(directory / MARKER)
        raw, _ = read_entry(repo, base, marker, 4096, _MarkerReadConfig())
        if raw is None:
            raise AssistantError("fixture_root_unqualified")
        try:
            text = raw.decode("utf-8")
        except UnicodeError as exc:
            raise AssistantError("fixture_root_unqualified") from exc
        check_text(text)
        if text.split("\n", 1)[0] != "synthetic: true":
            raise AssistantError("fixture_root_unqualified")
        markers[marker] = digest(raw)
    return {"fixture_roots": roots, "fixture_max_file_bytes": limit, "fixture_markers": markers}


def load_policy_config(document: dict, settings: dict | None) -> Config:
    return load_config(content=canonical(document), _policy_fixture_settings=settings)
