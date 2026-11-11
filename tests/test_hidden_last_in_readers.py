"""A credential in any text of an operation is reported before a hidden character in another (#110).

Five readers screened each of several texts in turn, hidden characters included. A hidden
character in an early text then came before a credential in a later one, and the refusal a user
was given depended on the order of the texts. Nothing got through either way. Synthetic values
only: the credential is spelled at run time and the hidden character is built here.
"""
from copy import deepcopy
from dataclasses import replace
import itertools

import pytest

from conftest import command
from credential_cases import spell
from finassist.config import Config
from finassist.errors import AssistantError
from finassist.evaluation import validate_suite
from finassist.scope import build_packet
from finassist.security import check_texts
from finassist.triage_contract import validate_request
from finassist.workflow import build_workflow_plan
from finassist.workspace import export_snapshot
from test_evaluation import suite
from test_triage_contract import sample_case

HIDDEN = "total" + chr(0x200B) + " = 1\n"  # a zero-width space, built here so that this file holds none
LABELLED = spell('@pw@ = "@V@"\n')
PLAIN = "total = 1\n"


def code_of(call) -> str | None:
    try:
        call()
    except AssistantError as refusal:
        return refusal.code
    return None


def orders(first, second):
    """Both orders of two texts, and each alone beside a plain one."""
    return [((first, second), "sensitive_content"), ((second, first), "sensitive_content"),
            ((first, PLAIN), "hidden_characters"), ((PLAIN, first), "hidden_characters"),
            ((PLAIN, second), "sensitive_content"), ((PLAIN, PLAIN), None)]


CASES = orders(HIDDEN, LABELLED)
each_order = pytest.mark.parametrize("texts,expected", CASES, ids=[
    "hidden then credential", "credential then hidden", "hidden then plain", "plain then hidden",
    "plain then credential", "plain"])


@each_order
def test_several_texts_that_stand_together(texts, expected):
    assert code_of(lambda: check_texts(texts)) == expected
    assert code_of(lambda: check_texts(iter(texts))) == expected


@each_order
def test_the_cases_of_an_evaluation_suite(texts, expected):
    data = suite()
    for case, text in zip(data["cases"], texts, strict=False):
        case["after"] = text
    assert code_of(lambda: validate_suite(data)) == expected


def test_a_credential_in_one_version_of_a_case_comes_before_a_hidden_character_in_the_other():
    for before, after in itertools.permutations((HIDDEN, LABELLED)):
        data = suite()
        data["cases"][0].update(before=before, after=after)
        assert code_of(lambda data=data: validate_suite(data)) == "sensitive_content"


@each_order
def test_the_checklists_of_a_configuration(texts, expected):
    items = [text.strip() for text in texts]
    shipped = Config().profiles  # The other profiles stay, so that the configuration is valid apart from the texts.
    together = replace(Config(), profiles={**shipped, "general": items})
    apart = replace(Config(), profiles={**shipped, "general": [items[0]], "second": [items[1]]})
    assert code_of(together.validate) == expected
    assert code_of(apart.validate) == expected


@each_order
def test_the_context_and_the_candidates_of_a_triage_request(texts, expected):
    request = deepcopy(sample_case()[0])
    request["context"] = texts[0].strip()
    request["candidates"]["checks"][-1]["description"] = texts[1].strip()
    assert code_of(lambda: validate_request(request)) == expected


def _commit(repo, files, message):
    for name, text in files.items():
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_text(text, encoding="utf-8", newline="\n")
        command(repo, "add", "-f", name)
    command(repo, "commit", "-q", "-m", message)
    return command(repo, "rev-parse", "HEAD")


@each_order
def test_the_files_of_an_export(repository, tmp_path, texts, expected):
    repo, _base, _head = repository
    head = _commit(repo, {"src/aaa.py": texts[0], "src/bbb.py": texts[1]}, "Synthetic files for an export")
    destination = tmp_path / "snapshot"
    assert code_of(lambda: export_snapshot(repo, head, destination, Config())) == expected
    if expected == "hidden_characters":
        # The file that holds it is never written, and nothing after it is.
        hidden, other = ("src/aaa.py", "src/bbb.py") if texts[0] == HIDDEN else ("src/bbb.py", "src/aaa.py")
        assert not (destination / hidden).exists()
        assert (destination / other).exists() is (other < hidden)


@each_order
def test_the_methodology_documents_of_a_workflow(repository, texts, expected):
    repo, _base, _head = repository
    documents = {"docs/a-first.md": "# Synthetic rule\n" + texts[0], "docs/b-second.md": "# Synthetic rule\n" + texts[1]}
    base = _commit(repo, documents, "Synthetic governing rules")
    head = _commit(repo, {"src/fees.py": "def fee(amount):\n    return amount // 100\n"}, "Synthetic change")
    config = replace(Config(), recipes={"unit": ["python", "-m", "pytest"]}, required_recipes=("unit",))
    template = {
        "schema_version": 1, "name": "cash-validation", "goal": "Validate the synthetic cash rule",
        "methodology": sorted(documents),
        "requirements": [{"id": "unit-tests", "recipe": "unit", "methodology": sorted(documents)}],
        "steps": [{"id": "unit", "requirement": "unit-tests", "depends_on": []}],
    }
    packet = build_packet(repo, base, head, config)  # The documents are not in the range: the workflow reads them.
    assert code_of(lambda: build_workflow_plan(template, packet, repo, config)) == expected
