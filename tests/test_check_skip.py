"""check's snapshot honours the two skip settings the review routes have. Synthetic repositories only."""

from dataclasses import replace

import pytest

from conftest import command, synthetic_symlink
from finassist import workspace
from finassist.config import Config
from finassist.errors import AssistantError
from finassist.scope import omission_for
from finassist.workspace import export_snapshot

LEDGER = "def total(values):\n    return sum(values)\n"
FILES = {"src/ledger.py": LEDGER, "tests/data/prices.csv": "date,close\n2026-01-02,1\n",
         "src/notes.xyz": "synthetic notes\n"}
SKIP = {"private_paths": "skip-and-report", "unreviewable_paths": "skip-and-report"}


def _repo(tmp_path, files: dict, name: str = "repo"):
    repo = tmp_path / name
    repo.mkdir()
    command(repo, "init", "-q", "-b", "main")
    for path, text in files.items():
        (repo / path).parent.mkdir(parents=True, exist_ok=True)
        (repo / path).write_text(text, encoding="utf-8")
    command(repo, "add", "--force", "--", *files)
    command(repo, "-c", "user.name=Synthetic", "-c", "user.email=synthetic@example.invalid",
            "commit", "-q", "-m", "Synthetic snapshot source")
    return repo


def _config(**settings):
    return replace(Config(), allow_paths=("src/", "tests/"), **settings)


def test_by_default_each_kind_still_refuses_the_export(tmp_path):
    repo = _repo(tmp_path, FILES)
    with pytest.raises(AssistantError, match="^unsupported_file_type$"):  # the first in tree order
        export_snapshot(repo, "HEAD", tmp_path / "a", _config())
    with pytest.raises(AssistantError, match="^private_or_binary_path$"):
        export_snapshot(repo, "HEAD", tmp_path / "b", replace(Config(), allow_paths=("tests/",)))


def test_skip_and_report_leaves_both_kinds_out_and_counts_them(tmp_path, monkeypatch):
    repo = _repo(tmp_path, FILES)
    reads, real = [], workspace.read_entry

    def spy(repo_path, sha, path, *args, **kwargs):
        reads.append(path)
        return real(repo_path, sha, path, *args, **kwargs)
    monkeypatch.setattr(workspace, "read_entry", spy)
    manifest = export_snapshot(repo, "HEAD", tmp_path / "out", _config(**SKIP))
    assert [item["path"] for item in manifest["files"]] == ["src/ledger.py"]
    assert manifest["withheld"] == 1 and manifest["omitted"] == {"unsupported_file_type": 1}
    assert "tests/data/prices.csv" not in reads  # a private name is never read
    assert not (tmp_path / "out" / "tests").exists() and not (tmp_path / "out" / "src" / "notes.xyz").exists()


def test_one_setting_without_the_other_still_refuses_the_other_kind(tmp_path):
    repo = _repo(tmp_path, FILES)
    with pytest.raises(AssistantError, match="^unsupported_file_type$"):
        export_snapshot(repo, "HEAD", tmp_path / "a", _config(private_paths="skip-and-report"))
    with pytest.raises(AssistantError, match="^private_or_binary_path$"):
        export_snapshot(repo, "HEAD", tmp_path / "b", _config(unreviewable_paths="skip-and-report"))


def test_an_oversized_file_is_left_out_by_reason(tmp_path):
    repo = _repo(tmp_path, {"src/ledger.py": LEDGER, "src/big.py": "# " + "x" * 300 + "\n"})
    manifest = export_snapshot(repo, "HEAD", tmp_path / "out", _config(max_file_bytes=100, **SKIP))
    assert [item["path"] for item in manifest["files"]] == ["src/ledger.py"]
    assert manifest["omitted"] == {"file_limit_exceeded": 1} and "withheld" not in manifest


def test_leaving_everything_out_is_still_an_empty_snapshot(tmp_path):
    repo = _repo(tmp_path, {"tests/data/prices.csv": FILES["tests/data/prices.csv"]})
    with pytest.raises(AssistantError, match="^empty_snapshot$"):
        export_snapshot(repo, "HEAD", tmp_path / "out", _config(**SKIP))


@pytest.mark.parametrize("kind", ["symlink", "submodule"])
@pytest.mark.parametrize("suffix", [".xyz", ".py"])
def test_a_link_or_submodule_is_never_left_out(tmp_path, kind, suffix):
    # Whatever reason the file would be left out for, a special entry refuses, as omission_for refuses it.
    repo = _repo(tmp_path, {"src/ledger.py": LEDGER})
    name = "src/dependency" + suffix
    if kind == "symlink":
        synthetic_symlink(repo / name, "ledger.py")
        command(repo, "add", "--", name)
    else:
        command(repo, "update-index", "--add", "--cacheinfo", "160000," + command(repo, "rev-parse", "HEAD") + "," + name)
    command(repo, "-c", "user.name=Synthetic", "-c", "user.email=synthetic@example.invalid",
            "commit", "-q", "-m", "Synthetic special entry")
    with pytest.raises(AssistantError, match="^linked_or_special_git_object$"):
        omission_for(repo, ("HEAD", "HEAD"), name, _config(**SKIP), "unsupported_file_type")
    with pytest.raises(AssistantError, match="^linked_or_special_git_object$"):
        export_snapshot(repo, "HEAD", tmp_path / "out", _config(**SKIP))


@pytest.mark.parametrize("suffix", [".csv", ".py"], ids=["private-name", "source-name"])
@pytest.mark.parametrize("stem,code", [("REVIEW_SENTINEL", "project_content_blocked"),
                                       ("hidden" + chr(0x200B) + "name", "unsafe_path")], ids=["pattern", "hidden"])
def test_a_name_the_screen_refuses_is_never_withheld(tmp_path, suffix, stem, code):
    # A private name is withheld only after the configured patterns pass it, as on the review routes.
    name = "src/" + stem + suffix
    repo = _repo(tmp_path, {"src/ledger.py": LEDGER, name: "# synthetic\n"})
    config = _config(**SKIP, extra_sensitive_patterns=("REVIEW_SENTINEL",))
    with pytest.raises(AssistantError, match="^" + code + "$"):
        export_snapshot(repo, "HEAD", tmp_path / "out", config)


def test_a_clean_tree_keeps_the_manifest_it_had(tmp_path):
    repo = _repo(tmp_path, {"src/ledger.py": LEDGER})
    manifest = export_snapshot(repo, "HEAD", tmp_path / "out", _config(**SKIP))
    assert set(manifest) == {"head", "files"}  # no counts when nothing was left out
