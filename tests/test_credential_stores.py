"""A hidden spelling of a private name, and a credential store, are private on every route.

Every path here is synthetic; no file is read.
"""

from dataclasses import replace
from pathlib import Path

import pytest

from finassist.config import Config
from finassist.errors import AssistantError
from finassist.security import CREDENTIAL_STORES, check_model_path, check_path

FULLWIDTH_STOP = chr(0xFF0E)  # Reads as a dot, and normalizes to one.

HIDDEN = [
    (".secrets/notes.py", "private_path"),
    ("src/.secrets/notes.py", "private_path"),
    (".github/.secrets/config.py", "private_path"),
    (".github/.credentials/login.py", "private_path"),
    ("docs/.holdings/notes.md", "private_path"),
    ("..secrets/notes.py", "private_path"),
    (".Secrets./notes.py", "private_path"),
    (FULLWIDTH_STOP + "secrets/notes.py", "private_path"),
    (".node_modules/pkg/index.js", "private_path"),
    ("..git/hooks.py", "private_path"),
    (".github/.data/rows.py", "gate_private_path"),
    (".private/notes.md", "gate_private_path"),
    ("src/.client/notes.py", "gate_private_path"),
    (".claude/.credentials.json", "gate_private_path"),
    ("src/.client.json", "gate_private_path"),
    ("src/.auth.json", "private_profile_path"),
]
# Names that only resemble a private one, or sit beside a credential store. Each stays reviewable.
UNCHANGED = [
    "src/aws/s3.py", "env/settings.py", "git/hooks.py", "ssh/keys.py", "azure/pipelines.yml", "venv/tool.py",
    "docker/config.json", ".docker/compose.yml", ".docker/daemon.json", "config/gh/hosts.yml",
    ".config/nextest.toml", ".config/dotnet-tools.json", ".config/git/ignore.txt", ".cargo/config.toml",
    "src/netrc.py", "src/kube/config.py", ".github/workflows/ci.yml", ".secrets.baseline.json",
    "docs/.vitepress/config.ts", "src/id_rsa.py", "keys/id_rsa.pub.txt", "gradle.properties.md",
    ".gradle/notes.md", ".m2/extensions.json", ".fly/notes.yml", ".expo/settings.json", "src/.hidden/module.py",
]


@pytest.mark.parametrize("path, code", HIDDEN)
def test_a_hidden_spelling_of_a_private_name_is_private(path, code):
    with pytest.raises(AssistantError, match="^" + code + "$"):
        check_model_path(path, source_only=False)
    if code != "gate_private_path":  # The configuration route applies the shared rules; the gate adds its own names.
        for check in (check_path, Config().check_path):
            with pytest.raises(AssistantError, match="^" + code + "$"):
                check(path, source_only=False)


@pytest.mark.parametrize("path", UNCHANGED)
def test_a_name_that_only_resembles_one_stays_reviewable(path):
    assert check_model_path(path) == path
    assert Config().check_path(path) == path


@pytest.mark.parametrize("store", CREDENTIAL_STORES, ids="/".join)
def test_every_credential_store_is_private_wherever_it_sits(store):
    name = "/".join(store)
    for path in (name, name + "/settings.json", "tools/" + name, "tools/" + name + "/nested/session.yaml",
                 name.upper(), name + "."):
        for check in (check_path, check_model_path, Config().check_path):
            with pytest.raises(AssistantError, match="^private_path$"):
                check(path, source_only=False)


def test_a_store_needs_its_whole_run_of_components():
    for store in CREDENTIAL_STORES:
        if len(store) > 1:  # The directory alone, and the file elsewhere, are ordinary names.
            assert check_path("/".join(store[:-1]) + "/notes.md") == "/".join(store[:-1]) + "/notes.md"


def test_no_setting_admits_a_credential_store_and_denied_parts_still_governs_hidden_spellings():
    open_policy = replace(Config(), denied_parts=(".finassist", ".git"))
    for path in ("secrets/notes.py", ".secrets/notes.py", "src/.holdings/notes.py"):
        assert open_policy.check_path(path) == path  # Approved source, by removing the component.
    for path in (".docker/config.json", ".config/gh/hosts.yml", "tools/.netrc", ".kube/config.yaml"):
        with pytest.raises(AssistantError, match="^private_path$"):
            open_policy.check_path(path, source_only=False)
    with pytest.raises(AssistantError, match="^private_path$"):
        check_path("..custom/notes.py", denied_parts={"custom"})


def test_the_configuration_guide_lists_every_credential_store():
    guide = (Path(__file__).parents[1] / "docs" / "configuration.md").read_text(encoding="utf-8")
    missing = [name for name in ("/".join(store) for store in CREDENTIAL_STORES)
               if "`" + name + "`" not in guide and "`" + name + "/`" not in guide]
    assert not missing, missing
