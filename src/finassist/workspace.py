"""Export screened committed source for test execution; never mount a developer's home."""

from collections import Counter
from pathlib import Path

from .config import Config
from .errors import AssistantError
from .hidden_text import Waiting
from .scope import WITHHELD_CODES, git, left_out, read_entry, require_regular, resolve
from .security import PUBLIC_ASSETS, check_credentials, check_name, digest


def export_snapshot(repo: Path, ref: str, destination: Path, config: Config) -> dict:
    """Write the screened files of a commit for a recipe to run on.

    With private_paths: skip-and-report, a private name is never read or copied, only counted; with
    unreviewable_paths: skip-and-report, a file that cannot be reviewed is left out and counted by reason. Under
    the defaults either refuses the export, as before. The counts are in the manifest only when nonzero.
    As on the review routes, a name that matches a configured sensitive pattern refuses rather than being
    withheld, and only an ordinary file is left out: a link, a submodule or another special entry still refuses.
    """
    sha = resolve(repo, ref)
    if destination.exists():
        raise AssistantError("snapshot_destination_exists")
    destination.mkdir(mode=0o755)
    paths = git(repo, "ls-tree", "-r", "-z", "--name-only", sha, binary=True).decode().split("\0")
    manifest = []
    withheld, omitted = 0, Counter()
    unseen = Waiting()  # A hidden character in one file waits for the credential screen of every file.
    for path in paths:
        if not path or not config.allows(path):
            continue
        try:
            config.check_path(path, source_only=False, metadata_only=True)
        except AssistantError as exc:
            if config.private_paths == "skip-and-report" and exc.code in WITHHELD_CODES:
                check_name(path, extra_patterns=config.extra_sensitive_patterns)  # the name only; nothing is read
                withheld += 1  # never read or copied
                continue
            raise
        check_name(path, extra_patterns=config.extra_sensitive_patterns)
        if config.generated(path) or Path(path).suffix.lower() in PUBLIC_ASSETS:
            continue
        try:
            config.check_path(path)
            data, mode = read_entry(repo, sha, path, config.file_byte_limit(path), config)
        except AssistantError as exc:
            reason = left_out(config, exc.code)
            if reason is None:
                raise
            require_regular(repo, (sha,), path)  # the tree entry's mode only; no blob is read
            omitted[reason] += 1  # left out unread, as the review routes leave it out
            continue
        if data is None:
            raise AssistantError("snapshot_blob_missing")
        try:
            text = data.decode()
        except UnicodeError as exc:
            if left_out(config, "non_text_blob") is None:
                raise AssistantError("snapshot_non_text_blob") from exc
            omitted["non_text_blob"] += 1
            continue
        check_credentials(text, extra_patterns=config.extra_sensitive_patterns, source_path=path,
                          placeholders=config.placeholder_credential_paths)
        unseen.check(text, file=True)
        if unseen.first is not None:
            continue  # The export will be refused. No file is written from here on; the rest are still screened.
        target = destination / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        target.chmod(0o555 if mode == "100755" else 0o444)
        manifest.append({"path": path, "sha256": digest(data), "mode": mode})
    unseen.release()
    if not manifest:
        raise AssistantError("empty_snapshot")
    for directory in sorted((p for p in destination.rglob("*") if p.is_dir()), reverse=True):
        directory.chmod(0o555)
    destination.chmod(0o555)
    result = {"head": sha, "files": manifest}
    if withheld:
        result["withheld"] = withheld
    if omitted:
        result["omitted"] = dict(sorted(omitted.items()))
    return result
