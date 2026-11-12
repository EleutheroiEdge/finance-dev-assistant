"""Wrong setups, one at a time: each gives one named blocker, and each remedy the report offers clears it.

A hint a person cannot follow is a support question. A remedy a program cannot apply is a failing test here.
"""

import copy
import json

import pytest

from conftest import command
from finassist.cli import main
from finassist.config import MAX_PACKET_BYTES, load_config
from finassist.config_preflight import config_preflight
from finassist.onboarding import policy_preflight
from finassist.remedies import MAX_FILE_BYTES, MAX_LISTED_PATHS, attach_remedies

KEY_VALUE = "fictional-provider-value"
KEYS = {"GEMINI_API_KEY": KEY_VALUE}  # Presence/emptiness only; never returned or sent.
EFFECTS = {"sends_more", "spends_more", "leaves_files_out", "none"}
SMALL = {"src/ledger.py": "def total(values):\n    return float(sum(values))\n"}
# name: files the change adds, settings changed first, and the blocker each route must name.
SCENARIOS = {
    "a file over the per-file limit": ({"src/big.py": "x = 1\n" * 60_000}, {"max_file_bytes": 100_000},
                                       {"max_file_bytes": 100_000}, "file_limit_exceeded", "file_limit_exceeded"),
    # The refusal reports the first version it meets (44 bytes at base); the head version is larger (51 bytes).
    # A limit raised only to the reported size would be refused again.
    "a changed file over the limit at both versions": ({}, {"max_file_bytes": 20}, {"max_file_bytes": 20},
                                                       "file_limit_exceeded", "file_limit_exceeded"),
    "a private file in the range": ({"src/data/rows.csv": "a,b\n1,2\n"}, {}, {},
                                    "private_or_binary_path", "private_or_binary_path"),
    "a denied file type in the range": ({"src/report.pdf": "%PDF-1.4\n"}, {}, {},
                                        "private_or_binary_path", "private_or_binary_path"),
    "a file outside the scope": ({"tools/extra.py": "y = 2\n"}, {}, {}, "scope_incomplete", "gate_path_not_allowed"),
    "a change over the size limit": ({"src/more.py": "z = 3\n" * 2_000}, {"max_packet_bytes": 5_000},
                                     {"max_request_bytes": 5_000}, "packet_limit_exceeded",
                                     "gate_request_bytes_exceeded"),
    "a run budget under the reserve": ({}, {"max_run_usd": 0.000001}, {"max_run_usd": 0.000001},
                                       "run_budget_exceeded", "run_budget_exceeded"),
    # The gate has no packet setting: its packet limit is the larger of 2,000,000 bytes and max_request_bytes.
    # Found on a real 45-file change, where the refusal named a setting a gate policy does not have.
    "a change over the gate's packet floor": (
        {"src/first_half.py": "# filler\n" * 125_000, "src/second_half.py": "# filler\n" * 125_000}, None,
        {"max_file_bytes": 1_500_000, "max_request_bytes": 1_000_000}, None, "packet_limit_exceeded"),
}
CASES = [(name, route) for name, scenario in SCENARIOS.items()
         for route, expected in (("configuration", scenario[3]), ("gate", scenario[4])) if expected is not None]


def _git(repo, *args) -> str:
    return command(repo, *args)  # The shared helper: a scrubbed environment, no hooks, the same on every platform.


@pytest.fixture(scope="module")
def drafted(tmp_path_factory):
    """A small repository, its first commit, and the configuration and gate policy detection drafts for it."""
    repo = tmp_path_factory.mktemp("remedies") / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "tests").mkdir()
    # newline="\n" everywhere: the sizes these setups depend on must not change with the platform.
    (repo / "src" / "ledger.py").write_text("def total(values):\n    return sum(values)\n", encoding="utf-8",
                                            newline="\n")
    (repo / "tests" / "test_ledger.py").write_text("def test_total():\n    assert True\n", encoding="utf-8",
                                                   newline="\n")
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.email", "remedies@example.invalid")
    _git(repo, "config", "user.name", "remedies")
    _git(repo, "config", "core.autocrlf", "false")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "first")
    return repo, _git(repo, "rev-parse", "HEAD")


@pytest.fixture
def draft(drafted, capsys):
    repo, base = drafted
    assert main(["init", "--detect", "--repo", str(repo), "--revision", base, "--provider", "google", "--model",
                 "example-model", "--input-usd-per-million", "1", "--output-usd-per-million", "5"]) == 0
    document = json.loads(capsys.readouterr().out.splitlines()[-1])
    return {**document["config"], "allow_network": True}, document["gate_policy_draft"]


def _change(drafted, files: dict) -> tuple:
    repo, base = drafted
    _git(repo, "checkout", "-q", "-B", "work", base)
    for name, text in {**SMALL, **files}.items():
        target = repo / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8", newline="\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "change")
    return repo, base, _git(repo, "rev-parse", "HEAD")


def _preflight(route: str, revisions: tuple, document: dict, folder) -> dict:
    repo, base, head = revisions
    if route == "configuration":
        config = load_config(content=json.dumps(document).encode("utf-8"))
        return config_preflight(repo, base, head, config, environment=KEYS)
    file = folder / "policy.json"
    file.write_text(json.dumps(document), encoding="utf-8")
    return policy_preflight(repo, base, head, "", None, environment=KEYS, policy_file=str(file))


def _settings(route: str, document: dict) -> dict:
    return document if route == "configuration" else document["model_review"]


def _apply(route: str, document: dict, option: dict) -> dict:
    changed = copy.deepcopy(document)
    settings = _settings(route, changed)
    for change in option["changes"]:
        name = change["setting"]
        if "value" in change:
            settings[name] = change["value"]
        elif "at_least" in change:
            settings[name] = change["at_least"]
        elif "add" in change:
            settings[name] = [*settings.get(name, []), *change["add"]]
        else:
            assert change == {"setting": name, "needs_value": True}
            settings[name] = 1.0
    return changed


def _start(route: str, draft, name: str) -> dict:
    document = copy.deepcopy(draft[0] if route == "configuration" else draft[1])
    _settings(route, document).update(SCENARIOS[name][1 if route == "configuration" else 2])
    return document


def _codes(report: dict) -> list[str]:
    return [blocker["code"] for blocker in report["blockers"]]


@pytest.mark.parametrize("name,route", CASES)
def test_each_wrong_setup_gives_one_named_blocker_and_every_remedy_clears_it(drafted, draft, tmp_path, name, route):
    expected = SCENARIOS[name][3 if route == "configuration" else 4]
    revisions = _change(drafted, SCENARIOS[name][0])
    document = _start(route, draft, name)
    report = _preflight(route, revisions, document, tmp_path)
    assert _codes(report) == [expected]
    assert report["blockers"][0]["hint"]
    assert [remedy["code"] for remedy in report["remedies"]] == [expected]
    options = report["remedies"][0]["options"]
    assert options
    for option in options:
        assert option["document"] == ("configuration" if route == "configuration" else "gate policy")
        assert option["effect"] in EFFECTS and option["changes"]
        after = _preflight(route, revisions, _apply(route, document, option), tmp_path)
        assert expected not in _codes(after), option


@pytest.mark.parametrize("name,route", CASES)
def test_following_the_first_option_each_time_reaches_ready(drafted, draft, tmp_path, name, route):
    revisions = _change(drafted, SCENARIOS[name][0])
    document = _start(route, draft, name)
    for _round in range(4):
        report = _preflight(route, revisions, document, tmp_path)
        if report["status"] == "ready":
            break
        assert len(report["remedies"]) == len(report["blockers"]), _codes(report)
        for remedy in report["remedies"]:
            document = _apply(route, document, remedy["options"][0])
    assert report["status"] == "ready" and report["remedies"] == []


def test_the_gate_names_its_own_setting_for_a_packet_over_its_floor(drafted, draft, tmp_path):
    name = "a change over the gate's packet floor"
    report = _preflight("gate", _change(drafted, SCENARIOS[name][0]), _start("gate", draft, name), tmp_path)
    blocker = report["blockers"][0]
    assert blocker["code"] == "packet_limit_exceeded" and blocker["limit"] == 2_000_000
    assert "max_request_bytes" in blocker["hint"] and "max_packet_bytes" not in blocker["hint"]
    assert report["remedies"][0]["options"] == [{"document": "gate policy", "effect": "sends_more", "changes": [
        {"setting": "max_request_bytes", "at_least": blocker["bytes"]}]}]


def test_the_first_option_never_sends_or_spends_more_when_another_does_not(drafted, draft, tmp_path):
    revisions = _change(drafted, SCENARIOS["a file over the per-file limit"][0])
    for route in ("configuration", "gate"):
        report = _preflight(route, revisions, _start(route, draft, "a file over the per-file limit"), tmp_path)
        effects = [option["effect"] for option in report["remedies"][0]["options"]]
        assert effects == ["leaves_files_out", "sends_more"]


def test_missing_prices_name_the_settings_and_propose_no_value(drafted, draft, tmp_path):
    revisions = _change(drafted, {})
    document = {name: value for name, value in draft[0].items() if not name.endswith("_usd_per_million")}
    report = _preflight("configuration", revisions, document, tmp_path)
    assert _codes(report) == ["provider_prices_required"]
    option = report["remedies"][0]["options"][0]
    assert option["effect"] == "none"
    assert option["changes"] == [{"setting": "input_usd_per_million", "needs_value": True},
                                 {"setting": "output_usd_per_million", "needs_value": True}]
    after = _preflight("configuration", revisions, _apply("configuration", document, option), tmp_path)
    assert after["status"] == "ready"


def test_a_blocker_that_needs_a_decision_has_no_remedy(drafted, draft, tmp_path):
    # Approval to use the network is the user's to give, and a credential in the change is theirs to remove.
    revisions = _change(drafted, {})
    refused = _preflight("configuration", revisions, {**draft[0], "allow_network": False}, tmp_path)
    assert _codes(refused) == ["network_not_approved"] and refused["remedies"] == []
    # Assembled, so that this file does not itself hold a value under a credential label.
    label, value = "api" + "_key", "k9" * 12
    secret = _change(drafted, {"src/settings.py": label + ' = "' + value + '"\n'})
    for route in ("configuration", "gate"):
        report = _preflight(route, secret, _start(route, draft, "a private file in the range"), tmp_path)
        assert _codes(report) == ["sensitive_content"] and report["remedies"] == []


KEPT = {"path": "kept.py", "status": "included"}  # Another file of the range that stays in the review.


def _report(blockers: list, paths: list | None = None) -> dict:
    return {"blockers": blockers, "paths": paths or []}


def test_no_setting_is_proposed_past_its_ceiling():
    too_large = _report([{"code": "packet_limit_exceeded", "bytes": MAX_PACKET_BYTES + 1, "limit": 5}])
    attach_remedies(too_large, "configuration")
    assert too_large["remedies"] == []
    at_ceiling = _report([{"code": "gate_request_bytes_exceeded", "bytes": MAX_PACKET_BYTES, "limit": 5}])
    attach_remedies(at_ceiling, "gate")
    assert at_ceiling["remedies"][0]["options"][0]["changes"] == [{"setting": "max_request_bytes",
                                                                   "at_least": MAX_PACKET_BYTES}]
    huge = _report([{"code": "file_limit_exceeded", "count": 1}],
                   [KEPT, {"path": "a.py", "status": "refused", "code": "file_limit_exceeded", "bytes": 10}])
    attach_remedies(huge, "gate", sizes={"a.py": MAX_FILE_BYTES + 1})
    assert [option["effect"] for option in huge["remedies"][0]["options"]] == ["leaves_files_out"]


def _refused(*paths: str, kept: bool = True) -> dict:
    rows = [{"path": path, "status": "refused", "code": "file_limit_exceeded", "bytes": 600} for path in paths]
    return _report([{"code": "file_limit_exceeded", "count": len(paths)}], [*([KEPT] if kept else []), *rows])


def test_leaving_files_out_is_offered_only_when_another_file_stays_in_the_review():
    # With nothing else in the range, leaving the file out leaves nothing to review, and that has no remedy.
    alone = _refused("a.py", kept=False)
    attach_remedies(alone, "configuration", sizes={"a.py": 1_200})
    assert [option["effect"] for option in alone["remedies"][0]["options"]] == ["sends_more"]
    unknown = _refused("a.py", kept=False)
    attach_remedies(unknown, "configuration")
    assert unknown["remedies"] == []
    for rows, expected in (([{"path": "x.csv", "status": "refused", "code": "private_or_binary_path"}], []),
                           ([KEPT, {"path": "x.csv", "status": "refused", "code": "private_or_binary_path"}],
                            ["leaves_files_out"])):
        private = _report([{"code": "private_or_binary_path", "count": 1}], rows)
        attach_remedies(private, "gate")
        assert [option["effect"] for remedy in private["remedies"] for option in remedy["options"]] == expected


def test_a_file_limit_is_proposed_only_when_both_versions_of_every_refused_file_are_known():
    # The row reports 600 bytes, the first version met. The larger version decides.
    known = _refused("a.py", "b.py")
    attach_remedies(known, "configuration", sizes={"a.py": 1_200, "b.py": 700})
    assert known["remedies"][0]["options"][1]["changes"] == [{"setting": "max_file_bytes", "at_least": 1_200}]
    for sizes in (None, {}, {"a.py": 1_200}):
        unknown = _refused("a.py", "b.py")
        attach_remedies(unknown, "configuration", sizes=sizes)
        assert [option["effect"] for option in unknown["remedies"][0]["options"]] == ["leaves_files_out"]


def test_a_refused_fixture_gets_no_file_limit_remedy():
    # A fixture has a limit of its own, and the report does not say which limit refused the file.
    for paths in (("tests/fixtures/example.csv",), ("src/a.py", "tests/fixtures/example.csv"), ("[redacted]",)):
        report = _refused(*paths)
        attach_remedies(report, "gate", sizes={path: 404 for path in paths}, fixture_roots=("tests/fixtures/",))
        assert report["remedies"] == []
    # Without fixture roots, and for a file outside them, both options stand.
    for roots in ((), ("tests/fixtures/",)):
        report = _refused("src/a.py")
        attach_remedies(report, "gate", sizes={"src/a.py": 404}, fixture_roots=roots)
        assert [option["effect"] for option in report["remedies"][0]["options"]] == ["leaves_files_out", "sends_more"]


def test_a_path_the_route_would_refuse_as_an_entry_is_not_proposed():
    rows = [{"path": "tools/a.py", "status": "refused", "code": "gate_path_not_allowed"},
            {"path": "tools/b[1].py", "status": "refused", "code": "gate_path_not_allowed"}]
    refused = _report([{"code": "gate_path_not_allowed", "count": 2}], rows)
    attach_remedies(refused, "gate", valid_path=lambda path: "[" not in path)
    assert refused["remedies"] == []
    accepted = _report([{"code": "gate_path_not_allowed", "count": 2}], rows)
    attach_remedies(accepted, "gate", valid_path=lambda path: True)
    assert accepted["remedies"][0]["options"][0]["changes"] == [{"setting": "allow_paths",
                                                                 "add": ["tools/a.py", "tools/b[1].py"]}]


def test_an_option_that_would_leave_the_document_invalid_is_not_offered():
    report = _report([{"code": "private_or_binary_path", "count": 1}],
                     [KEPT, {"path": "x.csv", "status": "refused", "code": "private_or_binary_path"}])
    attach_remedies(report, "gate", valid_option=lambda option: False)
    assert report["remedies"] == []
    seen = []
    attach_remedies(report, "gate", valid_option=lambda option: seen.append(option) or True)
    assert [remedy["code"] for remedy in report["remedies"]] == ["private_or_binary_path"]
    assert seen == [{"effect": "leaves_files_out", "changes": [{"setting": "private_paths", "value": "skip-and-report"}]}]


@pytest.mark.parametrize("entries,offered", [(127, True), (128, False)])
def test_a_scope_entry_is_offered_only_while_the_gate_list_has_room(drafted, draft, tmp_path, entries, offered):
    # A gate policy holds at most 128 scope entries. One more makes the policy itself invalid.
    revisions = _change(drafted, {"tools/extra.py": "y = 2\n"})
    document = copy.deepcopy(draft[1])
    listed = document["model_review"]["allow_paths"]
    listed.extend("unused%03d/" % number for number in range(entries - len(listed)))
    assert len(listed) == entries
    report = _preflight("gate", revisions, document, tmp_path)
    assert _codes(report) == ["gate_path_not_allowed"]
    assert bool(report["remedies"]) is offered
    for remedy in report["remedies"]:
        after = _preflight("gate", revisions, _apply("gate", document, remedy["options"][0]), tmp_path)
        assert after["status"] == "ready"


def test_a_path_with_brackets_gets_a_scope_remedy_only_where_it_is_a_valid_entry(drafted, draft, tmp_path):
    # A gate policy's prefixes may not hold brackets, so listing this path would make the policy invalid.
    revisions = _change(drafted, {"tools/a[b].py": "y = 2\n"})
    gate = _preflight("gate", revisions, copy.deepcopy(draft[1]), tmp_path)
    assert _codes(gate) == ["gate_path_not_allowed"] and gate["remedies"] == []
    document = copy.deepcopy(draft[0])
    report = _preflight("configuration", revisions, document, tmp_path)
    assert _codes(report) == ["scope_incomplete"]
    for remedy in report["remedies"]:
        for option in remedy["options"]:
            after = _preflight("configuration", revisions, _apply("configuration", document, option), tmp_path)
            assert "scope_incomplete" not in _codes(after)


def test_a_path_that_cannot_be_named_or_a_long_list_gets_no_scope_remedy():
    hidden = _report([{"code": "gate_path_not_allowed", "count": 1}],
                     [{"path": "[redacted]", "status": "refused", "code": "gate_path_not_allowed"}])
    attach_remedies(hidden, "gate")
    assert hidden["remedies"] == []
    rows = [{"path": "tools/file%d.py" % index, "status": "omitted", "reason": "outside_allowlist"}
            for index in range(MAX_LISTED_PATHS + 1)]
    many = _report([{"code": "scope_incomplete", "count": len(rows)}], rows)
    attach_remedies(many, "configuration")
    assert many["remedies"] == []
    attach_remedies(_report([{"code": "scope_incomplete", "count": 1}],
                            [{"path": "x.bin", "status": "omitted", "reason": "generated_path"}]), "configuration")


def test_a_budget_is_rounded_up_to_a_cent_and_a_bad_amount_proposes_nothing():
    report = _report([{"code": "daily_budget_exceeded", "reserved_usd": "1.369944", "limit_usd": "1.0"},
                      {"code": "monthly_budget_exceeded", "reserved_usd": "not a number", "limit_usd": "1.0"},
                      {"code": "run_budget_exceeded", "reserved_usd": "NaN", "limit_usd": "1.0"},
                      {"code": "run_budget_exceeded", "reserved_usd": "Infinity", "limit_usd": "1.0"},
                      {"code": "run_budget_exceeded", "reserved_usd": "-1", "limit_usd": "1.0"},
                      {"code": "run_budget_exceeded", "reserved_usd": "0", "limit_usd": "1.0"},
                      {"code": "run_budget_exceeded", "limit_usd": "1.0"}])
    attach_remedies(report, "configuration")
    assert report["remedies"] == [{"code": "daily_budget_exceeded", "options": [
        {"document": "configuration", "effect": "spends_more",
         "changes": [{"setting": "daily_budget_usd", "at_least": 1.37}]}]}]
