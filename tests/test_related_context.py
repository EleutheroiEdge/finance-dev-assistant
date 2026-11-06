"""Related-code context in review packets (#64 phase 3a).

Every repository, name and value here is synthetic.
"""

from dataclasses import replace

import pytest

from conftest import command
from finassist import scope
from finassist.config import Config
from finassist.errors import AssistantError
from finassist.related import MAX_SNIPPET_BYTES, source_lines
from finassist.security import canonical, digest
from finassist.scope import build_packet, verify_packet

RATES = (
    '"""Synthetic rates."""\n'
    "\x0c\n"  # A form feed: str.splitlines() would shift every later line number.
    "LABEL = 'a\u2028b'\n"
    "\n"
    "\n"
    "def discount(rate, years):\n"
    '    """Discount factor for a synthetic rate."""\n'
    "    factor = (1 + rate) ** -years\n"
    "    return factor\n"
    "\n"
    "\n"
    "class Instrument:\n"
    '    """A synthetic instrument."""\n'
    "\n"
    "    def __init__(self, face):\n"
    "        self.face = face\n"
    "\n"
    "    @property\n"
    "    def scale(self):\n"
    "        return 1\n"
)
BOND_BASE = (
    "from .rates import Instrument, discount\n"
    "\n"
    "\n"
    "def price(face, rate, years):\n"
    "    return face\n"
    "\n"
    "\n"
    "class Bond:\n"
    "    pass\n"
)
BOND_HEAD = (
    "from .rates import Instrument, discount\n"
    "\n"
    "\n"
    "def price(face, rate, years):\n"
    "    return face * discount(rate, years)\n"
    "\n"
    "\n"
    "class Bond(Instrument):\n"
    "    pass\n"
)
CALLER = (
    "from pricing import bond\n"
    "\n"
    "\n"
    "def value(holdings):\n"
    '    """Synthetic portfolio value."""\n'
    "    total = 0\n"
    "    for face in holdings:\n"
    "        total += bond.price(face, 0.01, 2)\n"
    "    return total\n"
)
TEST = (
    "from pricing.bond import price\n"
    "\n"
    "\n"
    "def test_price():\n"
    "    assert price(100, 0.0, 1) == 100\n"
)
PRIVATE = "from pricing.bond import price\n\n\ndef holdings():\n    return price(1, 0.0, 1)\n"
SCREENED = "from pricing.bond import price\n\nTAG = 'SYNTHETIC_PROJECT_TAG'\nX = price(1, 0.0, 1)\n"
BROKEN = "from pricing.bond import price\n\ndef broken(:\n    price(1, 0.0, 1)\n"
CONFIG = Config(allow_paths=("src/", "tests/"), related_context="related",
                extra_sensitive_patterns=("SYNTHETIC_PROJECT_TAG",))


@pytest.fixture
def pricing(tmp_path):
    repo = tmp_path / "pricing-repo"
    repo.mkdir()
    command(repo, "init", "-b", "main")
    command(repo, "config", "user.name", "Synthetic Tester")
    command(repo, "config", "user.email", "tester@example.invalid")
    command(repo, "config", "core.autocrlf", "false")
    files = {"src/pricing/__init__.py": "", "src/pricing/rates.py": RATES, "src/pricing/bond.py": BOND_BASE,
             "src/pricing/portfolio.py": CALLER, "tests/test_bond.py": TEST,
             "src/pricing/data/positions.py": PRIVATE, "src/pricing/audit.py": SCREENED,
             "src/pricing/broken.py": BROKEN}
    for name, text in files.items():
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_bytes(text.encode("utf-8"))
    command(repo, "add", "-A")
    command(repo, "commit", "-q", "-m", "Synthetic base")
    base = command(repo, "rev-parse", "HEAD")
    (repo / "src/pricing/bond.py").write_bytes(BOND_HEAD.encode("utf-8"))
    command(repo, "commit", "-q", "-am", "Synthetic change")
    return repo, base, command(repo, "rev-parse", "HEAD")


def _rehash(packet):
    body = {key: value for key, value in packet.items() if key != "packet_hash"}
    return {**body, "packet_hash": digest(canonical(body))}


def test_the_block_holds_callee_caller_test_and_base_skeletons_in_tier_order(pricing):
    repo, base, head = pricing
    block = build_packet(repo, base, head, CONFIG)["related"]
    shown = [(item["relation"], item["path"], item["symbol"]) for item in block["snippets"]]
    assert shown == [("callee", "src/pricing/rates.py", "discount"),
                     ("caller", "src/pricing/portfolio.py", "value"),
                     ("test", "tests/test_bond.py", "test_price"),
                     ("base", "src/pricing/rates.py", "Instrument")]
    callee, caller, test, parent = block["snippets"]
    # Signature and the docstring's first line only; the body is never sent.
    assert [line for _number, line in callee["lines"]] == [
        "def discount(rate, years):", '    """Discount factor for a synthetic rate."""']
    assert callee["reference"] == {"path": "src/pricing/bond.py", "line": 5}
    assert caller["reference"] == {"path": "src/pricing/bond.py", "symbol": "price"}
    assert [line for _number, line in caller["lines"]][-1] == "        total += bond.price(face, 0.01, 2)"
    assert "    @property" in [line for _number, line in parent["lines"]]
    assert "        return 1" not in [line for _number, line in parent["lines"]]
    assert test["lines"][-1] == [5, "    assert price(100, 0.0, 1) == 100"]
    assert callee["sha256"] == digest(RATES.encode())


def test_line_numbers_follow_python_not_str_splitlines(pricing):
    repo, base, head = pricing
    callee = build_packet(repo, base, head, CONFIG)["related"]["snippets"][0]
    lines = source_lines(RATES)
    assert len(RATES.splitlines()) != len(lines)  # The form feed and U+2028 split differently.
    assert all(lines[number - 1] == text for number, text in callee["lines"])
    assert callee["lines"][0][0] == 6


def test_a_private_name_is_never_read_searched_or_listed(pricing, monkeypatch):
    repo, base, head = pricing
    reads, searched = [], []
    real_read, real_grep = scope.read_entry, scope._grep_names

    def read_spy(repository, revision, path, *args, **kwargs):
        reads.append(path)
        return real_read(repository, revision, path, *args, **kwargs)

    def grep_spy(repository, revision, names, paths):
        searched.extend(paths)
        return real_grep(repository, revision, names, paths)

    monkeypatch.setattr(scope, "read_entry", read_spy)
    monkeypatch.setattr(scope, "_grep_names", grep_spy)
    packet = build_packet(repo, base, head, CONFIG)
    private = "src/pricing/data/positions.py"
    assert private not in reads and private not in searched and searched
    assert "positions" not in canonical(packet).decode()


def test_screening_and_parse_failures_are_listed_by_name_and_code_only(pricing):
    repo, base, head = pricing
    block = build_packet(repo, base, head, CONFIG)["related"]
    skipped = {item["path"]: item["reason"] for item in block["skipped"]}
    assert skipped["src/pricing/broken.py"] == "python_source_unparseable"
    assert skipped["src/pricing/audit.py"] not in {"python_source_unparseable", "related_budget"}
    assert skipped["src/pricing/audit.py"] == "project_content_blocked"
    assert "SYNTHETIC_PROJECT_TAG" not in canonical(block).decode()


def test_the_packet_is_deterministic_and_verifies(pricing):
    repo, base, head = pricing
    first, second = build_packet(repo, base, head, CONFIG), build_packet(repo, base, head, CONFIG)
    assert first == second
    verify_packet(first, CONFIG)


def test_the_budget_lists_what_did_not_fit(pricing):
    repo, base, head = pricing
    small = replace(CONFIG, related_max_bytes=700)
    packet = build_packet(repo, base, head, small)
    block = packet["related"]
    assert block["budget_bytes"] == 700
    assert sum(len(canonical(item)) for item in block["snippets"]) <= 700
    assert any(item["reason"] == "related_budget" for item in block["skipped"])
    assert block["skipped_count"] >= len(block["skipped"])
    verify_packet(packet, small)


def test_the_budget_follows_the_change_size_with_a_floor(pricing):
    repo, base, head = pricing
    packet = build_packet(repo, base, head, replace(CONFIG, related_max_bytes=400_000))
    assert packet["related"]["budget_bytes"] == 16_000 > len(BOND_HEAD.encode())


def test_the_default_packet_is_unchanged(pricing):
    repo, base, head = pricing
    plain = build_packet(repo, base, head, Config(allow_paths=("src/", "tests/")))
    assert "related" not in plain
    with pytest.raises(AssistantError, match="packet_related_missing"):
        verify_packet(plain, CONFIG)
    related = build_packet(repo, base, head, CONFIG)
    with pytest.raises(AssistantError, match="packet_related_not_allowed"):
        verify_packet(related, Config(allow_paths=("src/", "tests/")))


@pytest.mark.parametrize("tamper", [
    lambda item: item.update(path="src/pricing/data/positions.py"),
    lambda item: item.update(path="src/pricing/bond.py"),
    lambda item: item.update(relation="neighbour"),
    lambda item: item.update(lines=[[2, "a"], [1, "b"]]),
    lambda item: item.update(lines=[[1, "a\rb"]]),
    lambda item: item.update(lines=[[1, "x" * MAX_SNIPPET_BYTES]]),
    lambda item: item.update(reference={"path": "src/pricing/rates.py", "line": 1}),
    lambda item: item.update(sha256="0" * 63),
])
def test_an_edited_block_is_refused(pricing, tamper):
    repo, base, head = pricing
    packet = build_packet(repo, base, head, CONFIG)
    tamper(packet["related"]["snippets"][0])
    with pytest.raises(AssistantError, match="packet_related_invalid"):
        verify_packet(_rehash(packet), CONFIG)


def test_a_sensitive_line_added_to_the_block_is_refused(pricing):
    repo, base, head = pricing
    packet = build_packet(repo, base, head, CONFIG)
    packet["related"]["snippets"][0]["lines"].append([99, "TAG = 'SYNTHETIC_PROJECT_TAG'"])
    with pytest.raises(AssistantError) as error:
        verify_packet(_rehash(packet), CONFIG)
    assert error.value.code == "project_content_blocked"  # The content screen refuses it.


def test_the_instructions_mention_the_block_only_when_it_is_enabled():
    assert "`related`" in CONFIG.instructions()
    assert "`related`" not in Config().instructions()


def test_a_gate_policy_can_enable_it():
    from finassist.model_policy import _SCHEMA, policy_config_fields
    from test_model_policy import model_policy

    model = {**model_policy()["model_review"], "related_context": "related", "related_max_bytes": 9000}
    fields = policy_config_fields(model, None)
    assert fields["related_context"] == "related" and fields["related_max_bytes"] == 9000
    properties = _SCHEMA["properties"]["model_review"]["properties"]
    assert properties["related_context"]["enum"] == ["none", "related"]


@pytest.mark.parametrize("changes, code", [
    ({"related_context": "everything"}, "invalid_related_context"),
    ({"related_max_bytes": 0}, "invalid_limit"),
    ({"related_max_bytes": True}, "invalid_limit"),
])
def test_invalid_settings_are_refused(changes, code):
    with pytest.raises(AssistantError, match=code):
        replace(CONFIG, **changes).validate()
