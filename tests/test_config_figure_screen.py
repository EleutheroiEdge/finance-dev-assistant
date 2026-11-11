"""The confidential-figure screen on the configuration route: plan, review, propose and doctor.

Every figure, repository and name here is synthetic.
"""

from dataclasses import asdict, replace
import hashlib
import json

import httpx
import pytest

from conftest import command
from finassist.cli import main
from finassist.config import Config, config_hash, config_identity, load_config, save_config
from finassist.config_preflight import config_preflight
from finassist.errors import AssistantError
from finassist.forbidden_tokens import normalize_numeric_token
from finassist.proposal import propose
from finassist.review import review_packet
from finassist.scope import build_packet, config_token_guard
from finassist.security import canonical
from test_providers_review import envelope, model_config, response
from test_related_context import RATES

pytest_plugins = ("test_related_context",)

FIGURE = "6729102.50"
HASH = hashlib.sha256(normalize_numeric_token(FIGURE).encode()).hexdigest()
# The default configuration's hash in 0.10.0. It changes only when a default or an always-hashed
# setting changes, which makes saved check records stale and belongs in the Upgrading notes.
DEFAULT_HASH_0_10_0 = "9354cf6ac3bf4e49201e9255169f76646236fb76fb960fc2413ab009ba49061c"


def _shows_figure(text: str) -> bool:
    # Hashes in a report are hex without commas, so these can't match one by chance.
    return "729,102" in text or "6729102" in text


@pytest.fixture
def listed(tmp_path):
    """A private list outside the repository, and both ways to configure it."""
    path = tmp_path / "private-figures.txt"
    path.write_text(FIGURE + "\n", encoding="utf-8", newline="\n")
    return {"file": {"forbidden_token_file": str(path)}, "hashes": {"forbidden_token_hashes": (HASH,)}}


@pytest.fixture
def leaking(repository):
    """A range whose head writes the figure in a comment, beside a single parenthesis."""
    repo, base, _head = repository
    (repo / "src/cash.py").write_text(
        "def balance(opening, deposits):\n    # reconciled (6,729,102.50 before fees\n    return opening - deposits\n",
        encoding="utf-8", newline="\n")
    command(repo, "add", "src/cash.py")
    command(repo, "commit", "-q", "-m", "Synthetic candidate with a listed figure")
    return repo, base, command(repo, "rev-parse", "HEAD")


def test_unset_figure_settings_leave_the_configuration_hash_as_it_was():
    config = Config()
    assert config.forbidden_token_rules == {}
    assert not {name for name in config_identity(config) if name.startswith("forbidden_token_")}
    assert config_hash(config) == DEFAULT_HASH_0_10_0
    assert config_hash(replace(config, forbidden_token_hashes=(HASH,))) != DEFAULT_HASH_0_10_0
    assert config_hash(replace(config, **{"forbidden_token_file": "/synthetic/figures.txt"})) != DEFAULT_HASH_0_10_0
    # Every other setting is hashed whether or not it has its default.
    assert set(asdict(config)) - set(config_identity(config)) == {
        "forbidden_token_file", "forbidden_token_hashes", "forbidden_token_sources", "forbidden_token_match",
        "forbidden_token_min_digits"}


@pytest.mark.parametrize("document,code", [
    ({"forbidden_token_hashes": ["not-a-hash"]}, "forbidden_token_hashes_invalid"),
    ({"forbidden_token_hashes": [HASH, HASH]}, "forbidden_token_hashes_invalid"),
    ({"forbidden_token_hashes": [hashlib.sha256(str(n).encode()).hexdigest() for n in range(1025)]},
     "forbidden_token_hashes_invalid"),
    ({"forbidden_token_hashes": [7]}, "invalid_list"),
    ({"forbidden_token_file": "x" * 4097}, "forbidden_token_file_invalid"),
    ({"forbidden_token_file": 7}, "forbidden_token_file_invalid"),
])
def test_malformed_figure_settings_are_refused_when_the_configuration_loads(document, code):
    with pytest.raises(AssistantError) as raised:
        load_config(content=json.dumps(document).encode())
    assert raised.value.code == code


@pytest.mark.parametrize("kind", ["file", "hashes"])
def test_plan_refuses_a_listed_figure_and_names_the_file_only_locally(leaking, listed, kind):
    repo, base, head = leaking
    with pytest.raises(AssistantError) as raised:
        build_packet(repo, base, head, replace(Config(), **listed[kind]))
    assert raised.value.code == "forbidden_token_present"
    assert raised.value.local_details["path"] == "src/cash.py"
    assert not _shows_figure(json.dumps(raised.value.public_details) + json.dumps(raised.value.local_details))


def test_plan_passes_a_range_without_the_figure_and_an_unlisted_range_is_unchanged(repository, leaking, listed):
    repo, base, head = leaking
    clean = command(repo, "rev-parse", "HEAD~1")
    assert build_packet(repo, base, clean, replace(Config(), **listed["file"]))["files"]
    assert build_packet(repo, base, head, Config())["files"]  # No list configured: no figure screen.


def test_the_cli_plan_reports_the_refusal_and_writes_no_packet(leaking, listed, tmp_path, capsys):
    repo, base, head = leaking
    config_path, output = tmp_path / "finassist.json", tmp_path / "packet.json"
    save_config(config_path, replace(Config(), **listed["file"]))
    assert main(["--config", str(config_path), "--audit-dir", str(tmp_path / "audit"), "plan", "--repo", str(repo),
                 "--base", base, "--head", head, "--output", str(output)]) != 0
    captured = capsys.readouterr()
    assert "forbidden_token_present" in captured.err and "src/cash.py" in captured.err
    assert not _shows_figure(captured.err + captured.out) and not output.exists()


def test_a_list_inside_the_repository_is_refused(leaking):
    repo, base, head = leaking
    (repo / "figures.txt").write_text(FIGURE + "\n", encoding="utf-8", newline="\n")
    config = replace(Config(), forbidden_token_file=str(repo / "figures.txt"))
    with pytest.raises(AssistantError, match="^forbidden_token_file_invalid$"):
        config_token_guard(config, repo)
    with pytest.raises(AssistantError, match="^forbidden_token_file_invalid$"):
        build_packet(repo, base, head, config)


def _transport(calls, reply):
    def handler(request):
        calls.append(request)
        return httpx.Response(200, json=envelope(json.dumps(reply)))
    return httpx.MockTransport(handler)


def test_review_never_sends_without_the_screen_and_screens_the_packet_again(leaking, listed, tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "fictional")
    repo, base, head = leaking
    packet = build_packet(repo, base, head, Config())  # Built somewhere no list was configured.
    config, calls = model_config(**listed["file"]), []
    arguments = dict(network_approved=True, approved_packet_hash=packet["packet_hash"],
                     transport=_transport(calls, response(packet)))
    with pytest.raises(AssistantError, match="^forbidden_token_guard_required$"):
        review_packet(packet, config, tmp_path / "audit.db", **arguments)
    other = config_token_guard(replace(Config(), forbidden_token_hashes=(hashlib.sha256(b"7").hexdigest(),)), repo)
    with pytest.raises(AssistantError, match="^forbidden_token_guard_required$"):  # Another list's screen.
        review_packet(packet, config, tmp_path / "audit.db", token_guard=other, **arguments)
    with pytest.raises(AssistantError, match="^forbidden_token_present$"):
        review_packet(packet, config, tmp_path / "audit.db", token_guard=config_token_guard(config, repo), **arguments)
    assert not calls and not (tmp_path / "audit.db").exists()


def test_review_screens_what_the_model_returns(repository, listed, tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "fictional")
    repo, base, head = repository
    config = model_config(**listed["hashes"])
    packet = build_packet(repo, base, head, config)
    reply = response(packet)
    reply["findings"][0]["impact"] = "Cash is understated by $6,729,102.50"
    calls = []
    with pytest.raises(AssistantError, match="^forbidden_token_present$"):
        review_packet(packet, config, tmp_path / "audit.db", network_approved=True,
                      approved_packet_hash=packet["packet_hash"], transport=_transport(calls, reply),
                      token_guard=config_token_guard(config, repo))
    assert len(calls) == 1
    report = review_packet(packet, config, tmp_path / "second.db", network_approved=True,
                           approved_packet_hash=packet["packet_hash"], transport=_transport(calls, response(packet)),
                           token_guard=config_token_guard(config, repo))
    assert report["status"] == "findings"


def test_propose_never_sends_without_the_screen(leaking, listed, tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "fictional")
    repo, base, head = leaking
    packet = build_packet(repo, base, head, Config())
    config, calls = model_config(**listed["hashes"]), []
    arguments = dict(network_approved=True, approved_packet_hash=packet["packet_hash"],
                     transport=_transport(calls, {"head": head, "patch": "", "summary": "None."}))
    with pytest.raises(AssistantError, match="^forbidden_token_guard_required$"):
        propose(packet, config, tmp_path / "audit.db", **arguments)
    with pytest.raises(AssistantError, match="^forbidden_token_present$"):
        propose(packet, config, tmp_path / "audit.db", token_guard=config_token_guard(config, repo), **arguments)
    assert not calls


def test_doctor_lists_the_file_and_says_whether_a_figure_screen_ran(leaking, listed):
    repo, base, head = leaking
    report = config_preflight(repo, base, head, replace(Config(), **listed["file"]))
    assert report["status"] == "blocked"
    assert report["figure_screen"] == {"configured": True, "listed": 1, "match": "value", "digit_forms": 0}
    assert [(row["path"], row["status"], row.get("code")) for row in report["paths"]] == [
        ("src/cash.py", "refused", "forbidden_token_present")]
    assert [(item["code"], item["count"]) for item in report["blockers"]] == [("forbidden_token_present", 1)]
    assert not _shows_figure(canonical(report).decode())
    unlisted = config_preflight(repo, base, head, Config())
    assert unlisted["status"] == "ready" and unlisted["figure_screen"]["configured"] is False


def test_doctor_reports_an_unusable_list_and_still_lists_the_paths(leaking):
    repo, base, head = leaking
    report = config_preflight(repo, base, head, replace(Config(), forbidden_token_file=str(repo / "missing.txt")))
    assert report["status"] == "blocked" and report["blockers"][0]["code"] == "forbidden_token_file_invalid"
    assert report["paths"] and report["figure_screen"]["configured"] is True and report["figure_screen"]["listed"] == 0


def test_related_context_drops_a_file_holding_a_listed_figure(pricing):
    repo, _base, _head = pricing
    rates, bond = repo / "src/pricing/rates.py", repo / "src/pricing/bond.py"
    rates.write_text(RATES + "\n\ndef scale():\n    return 314_159.265\n", encoding="utf-8", newline="\n")
    command(repo, "commit", "-q", "-am", "Synthetic related file with a listed figure")
    base = command(repo, "rev-parse", "HEAD")
    text = bond.read_text(encoding="utf-8")
    assert "discount(rate, years)" in text
    bond.write_text(text.replace("discount(rate, years)", "discount(rate, years) * 1", 1), encoding="utf-8", newline="\n")
    command(repo, "commit", "-q", "-am", "Synthetic change that calls into the related file")
    head = command(repo, "rev-parse", "HEAD")
    config = replace(Config(), related_context="related",
                     forbidden_token_hashes=(hashlib.sha256(b"314159.265").hexdigest(),))
    block = build_packet(repo, base, head, config)["related"]
    assert "src/pricing/rates.py" not in {item["path"] for item in block["snippets"]}
    assert {"path": "src/pricing/rates.py", "symbol": None, "reason": "forbidden_token_present"} in block["skipped"]
    shown = build_packet(repo, base, head, replace(config, forbidden_token_hashes=()))["related"]
    assert "src/pricing/rates.py" in {item["path"] for item in shown["snippets"]}  # Without a list it is shown.
