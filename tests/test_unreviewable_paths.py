"""unreviewable_paths: skip-and-report leaves out a file that cannot be reviewed, and names it. refuse is the default.

Every repository, file and value here is synthetic.
"""

from dataclasses import replace
import json

import httpx
import pytest

from conftest import command
from test_model_gate import change_policy, run
from test_providers_review import envelope, response
from finassist import scope
from finassist.config import Config, config_hash, load_config
from finassist.config_preflight import config_preflight
from finassist.errors import AssistantError
from finassist.github_actions import summary_markdown
from finassist.model_gate import prepare_model_source
from finassist.model_policy import load_model_policy
from finassist.onboarding import policy_preflight
from finassist.review import review_packet
from finassist.scope import UNREVIEWABLE_REASONS, WITHHELD_REASON, build_packet, left_out, verify_packet
from finassist.security import canonical

pytest_plugins = ("test_model_gate", "test_model_policy")

LARGE = b"X = 1\n" * 10_000  # 60,000 bytes: over the 48,000-byte file limit.
# One changed file of each kind a review cannot read, with the reason it is left out for.
UNREVIEWABLE = {
    "src/events.jsonl": ("unsupported_file_type", b'{"synthetic": 1}\n'),
    "src/large.py": ("file_limit_exceeded", LARGE),
    "src/latin1.py": ("non_text_blob", b"NAME = '" + bytes([0xE9]) + b"'\n"),
    "tools/build.py": ("outside_allowlist", b"print('synthetic')\n"),
    # Two reasons at once: the name rules give one answer, the allow list first.
    "tools/events.jsonl": ("outside_allowlist", b'{"synthetic": 3}\n'),
    "tools/diagram.svg": ("binary_asset_excluded", b"<svg/>\n"),
    "src/logo.svg": ("binary_asset_excluded", b"<svg/>\n"),
}
REASONS = {name: reason for name, (reason, _data) in UNREVIEWABLE.items()}
# Private by name. The second also has a suffix no review reads: it must stay private, never named.
PRIVATE = {"src/data/clients.csv": b"name,value\nSynthetic Client,1\n", "src/data/notes.jsonl": b'{"synthetic": 2}\n'}
LEAVE = replace(Config(), unreviewable_paths="skip-and-report")
BOTH = replace(LEAVE, private_paths="skip-and-report")
MODEL = dict(provider="openai", model="operator-selected", allow_network=True, input_usd_per_million=1,
             output_usd_per_million=2)


def _commit(repo, files, message="Synthetic change"):
    for name, data in files.items():
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_bytes(data)
    command(repo, "add", "-A", "-f")
    command(repo, "commit", "-q", "-m", message)
    return command(repo, "rev-parse", "HEAD")


def _files(private=False):
    files = {name: data for name, (_reason, data) in UNREVIEWABLE.items()}
    return {**files, **PRIVATE} if private else files


@pytest.fixture
def mixed(repository):
    repo, base, _head = repository
    return repo, base, _commit(repo, _files())


def _blob_reads(monkeypatch, repo, head, names):
    """The names among `names` whose content is asked of Git from now on."""
    blobs = {command(repo, "rev-parse", f"{head}:{name}"): name for name in names}
    read, real = [], scope.git

    def spy(repository, *args, **kwargs):
        if args[:2] == ("cat-file", "blob") and args[2] in blobs:
            read.append(blobs[args[2]])
        return real(repository, *args, **kwargs)

    monkeypatch.setattr(scope, "git", spy)
    return read


# The configuration route ---------------------------------------------------------------------


def test_refuse_is_the_default_and_adding_the_setting_keeps_the_configuration_hash(mixed):
    repo, base, head = mixed
    assert Config().unreviewable_paths == "refuse" and left_out(Config(), "unsupported_file_type") is None
    assert config_hash(load_config(content=b'{"unreviewable_paths": "refuse"}')) == config_hash(Config())
    assert config_hash(LEAVE) != config_hash(Config())
    with pytest.raises(AssistantError, match="^unsupported_file_type$"):
        build_packet(repo, base, head, Config())
    with pytest.raises(AssistantError, match="^invalid_unreviewable_paths$"):
        replace(Config(), unreviewable_paths="skip").validate()


def test_files_that_cannot_be_reviewed_are_left_out_and_named(mixed, monkeypatch):
    repo, base, head = mixed
    read = _blob_reads(monkeypatch, repo, head, UNREVIEWABLE)
    packet = build_packet(repo, base, head, LEAVE)
    assert [item["path"] for item in packet["files"]] == ["src/cash.py"]
    assert {row["path"]: row["reason"] for row in packet["omitted"]} == REASONS
    assert sorted(packet["changed_paths"]) == sorted(["src/cash.py", *UNREVIEWABLE])
    # An oversized file is decided from its object header, and a name-only reason reads nothing.
    # Only the file that had to be decoded to find out was read.
    assert read == ["src/latin1.py"]
    encoded = canonical(packet).decode()
    assert "synthetic" not in encoded and "X = 1" not in encoded and "NAME" not in encoded
    verify_packet(packet, LEAVE)
    assert scope.triage(packet, LEAVE)["coverage_complete"] is False


def test_every_reason_is_one_the_shared_table_gives():
    assert set(REASONS.values()) == {*UNREVIEWABLE_REASONS.values(), "binary_asset_excluded"}
    assert all(left_out(LEAVE, code) == reason for code, reason in UNREVIEWABLE_REASONS.items())
    for code in ("sensitive_content", "forbidden_token_present", "private_path", "gate_private_path",
                 "private_or_binary_path", "gate_denied_path", "gate_ignored_path", "linked_or_special_git_object",
                 "unsafe_path", "gate_ignore_change_requires_review"):
        assert left_out(LEAVE, code) is None, code


def test_a_private_name_is_never_listed_as_left_out(repository):
    repo, base, _head = repository
    head = _commit(repo, _files(private=True))
    with pytest.raises(AssistantError) as raised:  # Leaving out is not withholding: a private name still refuses.
        build_packet(repo, base, head, LEAVE)
    assert raised.value.code in scope.WITHHELD_CODES
    names = []
    packet = build_packet(repo, base, head, BOTH, withheld_names=names)
    assert sorted(names) == sorted(PRIVATE) and packet["withheld"] == {"count": 2, "reason": WITHHELD_REASON}
    assert {row["path"] for row in packet["omitted"]} == set(UNREVIEWABLE)
    assert "data/" not in canonical(packet).decode()


@pytest.mark.parametrize("name, text, code", [
    ("src/keys.py", "API_KEY = 'synthetic-" + "a" * 30 + "'\n", "sensitive_content"),
    ("src/big_keys.py", "X = 1\n" * 100 + "PASSWORD = 'synthetic-" + "b" * 30 + "'\n", "sensitive_content"),
])
def test_credential_content_still_refuses(repository, name, text, code):
    repo, base, _head = repository
    head = _commit(repo, {**_files(), name: text.encode()})
    with pytest.raises(AssistantError, match="^" + code + "$"):
        build_packet(repo, base, head, LEAVE)


def test_a_listed_figure_still_refuses(repository, tmp_path):
    repo, base, _head = repository
    listed = tmp_path / "figures.txt"
    listed.write_text("48213.57\n", encoding="utf-8")
    head = _commit(repo, {**_files(), "src/report.py": b"TOTAL = 48213.57\n"})
    config = replace(LEAVE, **{"forbidden_token_file": str(listed)})
    with pytest.raises(AssistantError, match="^forbidden_token_present$"):
        build_packet(repo, base, head, config)


def test_a_model_review_goes_ahead_without_them_and_is_partial(mixed, tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "fictional")
    repo, base, head = mixed
    config = replace(LEAVE, **MODEL)
    packet = build_packet(repo, base, head, config)
    sent = []

    def handler(request):
        sent.append(request.content.decode())
        return httpx.Response(200, json=envelope(json.dumps(response(packet))))

    report = review_packet(packet, config, tmp_path / "audit.db", network_approved=True,
                           approved_packet_hash=packet["packet_hash"], transport=httpx.MockTransport(handler))
    assert report["status"] == "partial-review" and len(sent) == 1
    # The reviewer is told what it does not see, by name and reason, and gets none of the text.
    assert all(name in sent[0] for name in UNREVIEWABLE) and "outside_allowlist" in sent[0]
    assert "X = 1" not in sent[0] and "print(" not in sent[0]
    # Without the setting the same range is refused before any request, as before.
    refusing = replace(Config(), **MODEL)
    with pytest.raises(AssistantError, match="^unsupported_file_type$"):
        build_packet(repo, base, head, refusing)


def test_the_configuration_preflight_lists_them_and_stays_ready(mixed, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "fictional")
    repo, base, head = mixed
    report = config_preflight(repo, base, head, replace(LEAVE, **MODEL))
    assert report["status"] == "ready", report["blockers"]
    assert report["coverage_complete"] is False
    rows = {row["path"]: row for row in report["paths"]}
    assert rows["src/cash.py"] == {"path": "src/cash.py", "status": "included"}
    assert {name: (rows[name]["status"], rows[name]["reason"]) for name in UNREVIEWABLE} == {
        name: ("omitted", reason) for name, reason in REASONS.items()}
    assert {"code": "unreviewable_paths_left_out", "count": 3} in [
        {key: warning[key] for key in ("code", "count")} for warning in report["warnings"]]
    blocked = config_preflight(repo, base, head, replace(Config(), **MODEL))
    assert blocked["status"] == "blocked"
    assert {"unsupported_file_type", "file_limit_exceeded", "non_text_blob", "scope_incomplete"} == {
        entry["code"] for entry in blocked["blockers"]}


# The gate ------------------------------------------------------------------------------------


def _gate(case, files, **policy):
    change_policy(case, **policy)
    case["head"] = _commit(case["repo"], files, "Synthetic gate candidate")


def test_the_gate_refuses_them_by_default(gate_case):
    _gate(gate_case, _files())
    report, calls = run(gate_case)
    assert report["verdict"] == "BLOCKED" and report["reasons"] == ["unsupported_file_type"] and not calls
    assert "coverage" not in report


def test_the_gate_leaves_them_out_and_counts_them(gate_case, monkeypatch):
    _gate(gate_case, _files(), unreviewable_paths="skip-and-report")
    read = _blob_reads(monkeypatch, gate_case["repo"], gate_case["head"], UNREVIEWABLE)
    report, calls = run(gate_case)
    assert report["verdict"] == "PASS", report["reasons"]
    assert report["coverage"] == {"complete": False, "withheld": len(UNREVIEWABLE)}
    assert read == ["src/latin1.py"]
    packet = json.loads(json.loads(calls[0].content)["input"])
    assert [item["path"] for item in packet["files"]] == ["src/cash.py"]
    assert {row["path"]: row["reason"] for row in packet["omitted"]} == REASONS
    assert "X = 1" not in calls[0].content.decode() and "print(" not in calls[0].content.decode()
    summary = summary_markdown(report)
    assert "Coverage: **incomplete**" in summary and "7 changed file(s) were left out" in summary
    assert not any(name in summary or name in canonical(report).decode() for name in UNREVIEWABLE)


def test_the_gate_counts_private_and_unreviewable_files_together_and_names_no_private_one(gate_case):
    _gate(gate_case, _files(private=True), unreviewable_paths="skip-and-report", private_paths="skip-and-report")
    report, calls = run(gate_case)
    assert report["verdict"] == "PASS", report["reasons"]
    assert report["coverage"] == {"complete": False, "withheld": len(UNREVIEWABLE) + len(PRIVATE)}
    request = calls[0].content.decode()
    assert "data/" not in request and "clients" not in request and "notes.jsonl" not in request
    packet = json.loads(json.loads(calls[0].content)["input"])
    assert packet["withheld"] == {"count": 2, "reason": WITHHELD_REASON}
    assert {row["path"] for row in packet["omitted"]} == set(UNREVIEWABLE)


@pytest.mark.parametrize("policy, verdict, reasons", [
    # Leaving out is on, withholding is off: the private name refuses, and is not named in a packet.
    ({"unreviewable_paths": "skip-and-report"}, "BLOCKED", ["gate_private_path"]),
    # Withholding alone withholds it, as it does any other private name, whatever the suffix.
    ({"private_paths": "skip-and-report"}, "PASS", []),
])
def test_a_private_name_with_an_unreviewable_suffix_is_private_first(gate_case, policy, verdict, reasons):
    _gate(gate_case, {"src/data/notes.jsonl": PRIVATE["src/data/notes.jsonl"]}, **policy)
    report, calls = run(gate_case)
    assert report["verdict"] == verdict and report["reasons"] == reasons
    if verdict == "PASS":
        assert report["coverage"] == {"complete": False, "withheld": 1}
        assert "notes.jsonl" not in calls[0].content.decode()
    else:
        assert not calls and "coverage" not in report


@pytest.mark.parametrize("files, policy, code", [
    ({"tools/build.py": b"print('synthetic')\n"}, {"deny_paths": ["tools/"]}, "gate_denied_path"),
    ({"src/events.jsonl": b"{}\n"}, {"deny_paths": ["src/events.jsonl"]}, "gate_denied_path"),
    ({"tools/.gitignore": b"*.log\n"}, {}, "gate_ignore_change_requires_review"),
    ({"src/keys.py": b"API_KEY = 'synthetic-" + b"a" * 30 + b"'\n"}, {}, "sensitive_content"),
])
def test_what_the_gate_still_refuses_whatever_the_setting(gate_case, files, policy, code):
    _gate(gate_case, files, unreviewable_paths="skip-and-report", **policy)
    report, calls = run(gate_case)
    assert report["verdict"] == "BLOCKED" and report["reasons"] == [code] and not calls


def test_a_range_with_nothing_left_to_review_is_refused(gate_case):
    change_policy(gate_case, unreviewable_paths="skip-and-report")
    repo = gate_case["repo"]
    command(repo, "switch", "-q", "-c", "only-unreviewable", gate_case["base"])
    gate_case["head"] = _commit(repo, {"tools/build.py": b"print('synthetic')\n", "src/events.jsonl": b"{}\n"})
    report, calls = run(gate_case)
    assert report["verdict"] == "BLOCKED" and report["reasons"] == ["empty_model_context"] and not calls


def test_a_range_of_only_private_files_says_so(gate_case):
    change_policy(gate_case, private_paths="skip-and-report")
    repo = gate_case["repo"]
    command(repo, "switch", "-q", "-c", "only-private", gate_case["base"])
    gate_case["head"] = _commit(repo, {"src/data/clients.csv": PRIVATE["src/data/clients.csv"]})
    report, calls = run(gate_case)
    assert report["verdict"] == "BLOCKED" and report["reasons"] == ["review_scope_entirely_withheld"] and not calls
    preflight = policy_preflight(repo, gate_case["base"], gate_case["head"], "gate-policy.json", gate_case["pin"])
    assert [entry["code"] for entry in preflight["blockers"]] == ["review_scope_entirely_withheld"]


def test_the_gate_preflight_lists_them_without_blocking(gate_case):
    _gate(gate_case, _files(), unreviewable_paths="skip-and-report")
    report = policy_preflight(gate_case["repo"], gate_case["base"], gate_case["head"], "gate-policy.json",
                              gate_case["pin"])
    assert report["status"] == "ready", report["blockers"]
    assert report["coverage_complete"] is False
    rows = {row["path"]: row for row in report["paths"]}
    assert {name: rows[name] for name in UNREVIEWABLE} == {
        name: {"path": name, "status": "omitted", "reason": reason} for name, reason in REASONS.items()}
    assert {"code": "unreviewable_paths_left_out", "count": len(UNREVIEWABLE)} in [
        {key: warning[key] for key in ("code", "count")} for warning in report["warnings"]]


def test_a_policy_accepts_only_the_two_modes(gate_case):
    change_policy(gate_case, unreviewable_paths="skip-everything")
    report, calls = run(gate_case)
    assert report["verdict"] == "BLOCKED" and not calls


# The proposal ----------------------------------------------------------------------------------


def test_the_proposal_counts_recent_changes_that_hold_such_a_file_and_does_not_choose(repository, capsys):
    from finassist.cli import main

    repo, _base, _head = repository
    command(repo, "switch", "-q", "main")
    command(repo, "merge", "-q", "--ff-only", "test/candidate")
    _commit(repo, {"src/cash.py": b"def balance(opening, deposits):\n    return opening\n"})
    _commit(repo, {"src/events.jsonl": b'{"synthetic": 1}\n', "src/fees.py": b"FEE = 1\n"})
    _commit(repo, {"captions.vtt": b"WEBVTT\n"})
    _commit(repo, {"src/data/clients.csv": PRIVATE["src/data/clients.csv"]})  # Private: never counted here.
    assert main(["init", "--detect", "--repo", str(repo)]) == 0
    proposal = json.loads(capsys.readouterr().out)
    warning = next(entry for entry in proposal["warnings"] if entry["code"] == "unreviewable_files_in_recent_changes")
    assert warning == {"code": "unreviewable_files_in_recent_changes", "count": 2, "changes_measured": 5}
    assert "unreviewable_paths" not in proposal["config"]
    assert "unreviewable_paths" not in proposal["gate_policy_draft"]["model_review"]


# One answer from all four callers ---------------------------------------------------------------


def _plan(repo, base, head, config):
    """{path: (status, reason)} from the packet builder, or the code that refuses the range."""
    names = []
    try:
        packet = build_packet(repo, base, head, config, withheld_names=names)
    except AssistantError as exc:
        return exc.code
    rows = {item["path"]: ("included", None) for item in packet["files"]}
    rows.update({row["path"]: ("omitted", row["reason"]) for row in packet["omitted"]})
    rows.update({name: ("withheld", None) for name in names})
    return rows


def _rows(report):
    return {row["path"]: (row["status"], row.get("reason") if row["status"] == "omitted" else None)
            for row in report["paths"] if row["status"] != "refused"}


@pytest.mark.parametrize("private", ["refuse", "skip-and-report"])
@pytest.mark.parametrize("unreviewable", ["refuse", "skip-and-report"])
def test_plan_and_the_configuration_preflight_give_each_path_the_same_outcome(repository, private, unreviewable):
    repo, base, _head = repository
    head = _commit(repo, _files(private=True))
    config = replace(Config(), private_paths=private, unreviewable_paths=unreviewable)
    planned = _plan(repo, base, head, config)
    report = config_preflight(repo, base, head, config)
    refused = {row["path"]: row["code"] for row in report["paths"] if row["status"] == "refused"}
    if isinstance(planned, str):  # plan refuses the range: the preflight names every file that refuses it.
        assert report["status"] == "blocked" and planned in refused.values()
    else:
        assert report["status"] == "ready" and not refused and _rows(report) == planned
    if private == unreviewable == "skip-and-report":
        assert planned == {"src/cash.py": ("included", None), **{name: ("withheld", None) for name in PRIVATE},
                           **{name: ("omitted", reason) for name, reason in REASONS.items()}}


@pytest.mark.parametrize("private", ["refuse", "skip-and-report"])
@pytest.mark.parametrize("unreviewable", ["refuse", "skip-and-report"])
def test_the_gate_and_its_preflight_give_each_path_the_same_outcome(gate_case, private, unreviewable):
    _gate(gate_case, _files(private=True), private_paths=private, unreviewable_paths=unreviewable)
    repo, base, head = gate_case["repo"], gate_case["base"], gate_case["head"]
    policy = load_model_policy(repo, base, "gate-policy.json", gate_case["pin"])
    try:
        packet = prepare_model_source(repo, base, head, policy)
    except AssistantError as exc:
        built = exc.code
    else:
        built = {item["path"]: ("included", None) for item in packet["files"]}
        built.update({row["path"]: ("omitted", row["reason"]) for row in packet["omitted"]})
    report = policy_preflight(repo, base, head, "gate-policy.json", gate_case["pin"])
    refused = {row["path"]: row["code"] for row in report["paths"] if row["status"] == "refused"}
    if isinstance(built, str):
        assert report["status"] == "blocked" and built in refused.values()
    else:
        rows = _rows(report)
        assert report["status"] == "ready" and not refused
        assert {name: outcome for name, outcome in rows.items() if outcome[0] != "withheld"} == built
        assert sum(outcome[0] == "withheld" for outcome in rows.values()) == packet["withheld"]["count"] == 2
    if private == unreviewable == "skip-and-report":
        # And the same answer as the configuration route gives for the same files.
        config = replace(BOTH, allow_paths=("src/",))
        planned = _plan(repo, base, head, config)
        assert {name: outcome for name, outcome in planned.items() if outcome[0] != "withheld"} == built
