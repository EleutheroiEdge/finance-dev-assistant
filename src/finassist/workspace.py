"""Export screened committed source for test execution; never mount a developer's home."""

from pathlib import Path

from .config import Config
from .errors import AssistantError
from .scope import git, read_entry, resolve
from .security import PUBLIC_ASSETS, check_text, digest


def export_snapshot(repo: Path, ref: str, destination: Path, config: Config) -> dict:
    sha = resolve(repo, ref)
    if destination.exists():
        raise AssistantError("snapshot_destination_exists")
    destination.mkdir(mode=0o755)
    paths = git(repo, "ls-tree", "-r", "-z", "--name-only", sha, binary=True).decode().split("\0")
    manifest = []
    for path in paths:
        if not path or not config.allows(path):
            continue
        config.check_path(path, source_only=False, metadata_only=True)
        check_text(path, extra_patterns=config.extra_sensitive_patterns)
        if Path(path).suffix.lower() in PUBLIC_ASSETS:
            continue
        config.check_path(path)
        data, mode = read_entry(repo, sha, path, config.max_file_bytes, config)
        if data is None:
            raise AssistantError("snapshot_blob_missing")
        try:
            check_text(data.decode(), extra_patterns=config.extra_sensitive_patterns)
        except UnicodeError as exc:
            raise AssistantError("snapshot_non_text_blob") from exc
        target = destination / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        target.chmod(0o555 if mode == "100755" else 0o444)
        manifest.append({"path": path, "sha256": digest(data), "mode": mode})
    if not manifest:
        raise AssistantError("empty_snapshot")
    for directory in sorted((p for p in destination.rglob("*") if p.is_dir()), reverse=True):
        directory.chmod(0o555)
    destination.chmod(0o555)
    return {"head": sha, "files": manifest}
