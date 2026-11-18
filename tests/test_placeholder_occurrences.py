"""Reviewed placeholder occurrences. A gate policy may let one credential-named YAML value through the label rules,
bound to its exact place, and only while it is present exactly once at base, at the merge base and at head.
Synthetic Git, synthetic values and a fake provider only.
"""

import json

import pytest

from conftest import command
from test_model_gate import change_policy, gate_case, run  # noqa: F401 - fixture registration
from test_model_policy import model_policy, policy_case  # noqa: F401 - fixture registration
from test_providers_review import envelope, response
from finassist import occurrence_identity, placeholder_occurrences
from finassist.cli import main
from finassist.errors import AssistantError
from finassist.occurrence_identity import (MAX_DEPTH, MAX_TEXT_CHARACTERS, OccurrenceAllowance, allowance_in_effect,
                                           yaml_occurrences)
from finassist.onboarding import policy_preflight
from finassist.placeholder_occurrences import build_allowance, enroll
from finassist.security import canonical, check_credentials, digest, screening_cache

# Built at run time: the repository screens its own source, and these are credential-shaped on purpose.
LABEL = "_".join(("POSTGRES", "PASSWORD"))
VALUE = "-".join(("synthetic", "fixture", "value"))
PATH = "src/ci/service.yml"
SERVICE = ("jobs:\n"
           "  test:\n"
           "    services:\n"
           "      db:\n"
           "        env:\n"
           f"          {LABEL}: {VALUE}\n"
           "    steps:\n"
           "      - name: Example\n"
           "        run: make check\n")
LINE = 6
LATER_STEP = "      - name: Later\n        run: make docs\n"


def _digests(text: str, path: str = PATH) -> list[str]:
    found = yaml_occurrences(path, text)
    assert found is not None
    return [item.digest for item in found]


def _value_digest(text: str, path: str = PATH) -> str:
    """The identity of the first value whose key is the label, in any letter case or quoting."""
    found = yaml_occurrences(path, text)
    return next(item.digest for item in found if str(item.location[-1][-1]).lower() == LABEL.lower())


def _commit(repo, files: dict, message: str = "Synthetic change") -> str:
    for name, content in files.items():
        target = repo / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    command(repo, "add", "--", *files)
    command(repo, "commit", "-q", "-m", message)
    return command(repo, "rev-parse", "HEAD")


def _enrolled(case, before: str, after: str, *, line: int = LINE) -> dict:
    """`before` and an entry for the value on `line` at base, then `after` at head."""
    repo = case["repo"]
    revision = _commit(repo, {PATH: before}, "Synthetic service file")
    entry = enroll(repo, revision, PATH, line)["entry"]
    change_policy(case, placeholder_credential_occurrences=[entry])
    case["head"] = _commit(repo, {PATH: after})
    return entry


def _reviewing_every_file(packet, claim: str | None = None) -> dict:
    """The fake provider's reply, saying it reviewed every file sent."""
    reply = response(packet)
    reply["reviewed_paths"] = [item["path"] for item in packet["files"]]
    if claim is not None:
        reply["findings"][0]["claim"] = claim
    return envelope(json.dumps(reply))


def _row(report: dict, path: str = PATH) -> dict:
    return next(row for row in report["paths"] if row["path"] == path)


# The identity: structural, exact, and never a nearby-line heuristic.

def test_identical_lines_in_identical_steps_have_different_identities():
    """A move between two steps with the same header keeps the line and its count, not its place."""
    def steps(first: bool) -> str:
        env = f"        env:\n          {LABEL}: {VALUE}\n"
        return ("jobs:\n  test:\n    steps:\n"
                + "      - name: Example\n" + (env if first else "        run: make check\n")
                + "      - name: Example\n" + ("        run: make check\n" if first else env))
    assert _value_digest(steps(True)) != _value_digest(steps(False))


def test_a_comment_under_a_job_header_does_not_hide_a_renamed_job():
    text = ("jobs:\n  test:\n  # synthetic comment\n    env:\n" f"      {LABEL}: {VALUE}\n")
    assert _value_digest(text) != _value_digest(text.replace("  test:", "  check:"))


@pytest.mark.parametrize("edit", [
    lambda text: text.replace(VALUE, VALUE + "-other"),  # the value
    lambda text: text.replace(f"{LABEL}: {VALUE}", f"{LABEL}: '{VALUE}'"),  # its quoting
    lambda text: text.replace(f"{LABEL}:", f"{LABEL.lower()}:"),  # its label
    lambda text: text.replace(f"{LABEL}:", f'"{LABEL}":'),  # the label's quoting
    lambda text: text.replace(f"{VALUE}\n", f"{VALUE}  # synthetic note\n"),  # its line
    lambda text: text.replace("      db:", "      cache:"),  # its place
])
def test_any_edit_to_the_value_its_label_line_or_place_changes_the_identity(edit):
    assert _value_digest(SERVICE) != _value_digest(edit(SERVICE))


def test_the_identity_is_stable_and_bound_to_the_path():
    assert _value_digest(SERVICE) == _value_digest(SERVICE)
    assert _value_digest(SERVICE) != _value_digest(SERVICE, "src/ci/other.yml")
    assert _value_digest(SERVICE) == _value_digest(SERVICE + LATER_STEP)  # an unrelated later step


def _deep() -> str:
    return "".join(f"{'  ' * level}k{level}:\n" for level in range(MAX_DEPTH + 1)) + "  " * (MAX_DEPTH + 1) + "v: 1\n"


@pytest.mark.parametrize("text", [
    f"a: &x {VALUE}\n",  # an anchor
    "a: &x synthetic\nb: *x\n",  # an alias
    "base:\n  k: v\nm:\n  <<: {k: v}\n",  # a merge key
    f"a: !custom {VALUE}\n",  # a custom tag
    f"a: !!str {VALUE}\n",  # an explicit standard tag
    "a: 1\na: 2\n",  # a duplicate key
    "? [x]\n: 1\n",  # a complex key
    "a: 1\n---\nb: 2\n",  # two documents
    "%YAML 1.1\n---\na: 1\n",  # a directive
    "a: [1, 2\n",  # malformed
    "a: \x07\n",  # a control character
    "a: 1\0\n",  # NUL
    "a: " + "x" * MAX_TEXT_CHARACTERS + "\n",  # too large
], ids=["anchor", "alias", "merge", "custom-tag", "standard-tag", "duplicate", "complex", "documents", "directive",
        "malformed", "control", "nul", "large"])
def test_a_file_outside_the_supported_subset_lets_nothing_through(text):
    assert yaml_occurrences(PATH, text) is None


def test_a_file_too_deep_lets_nothing_through():
    assert yaml_occurrences(PATH, _deep()) is None


@pytest.mark.parametrize("text", [
    f"env: {{{LABEL}: {VALUE}}}\n",  # inside a flow mapping
    f"env:\n  - {{{LABEL}: {VALUE}}}\n",  # inside a flow mapping in a sequence
    f"{LABEL}: |\n  {VALUE}\n",  # a block scalar
    f"{LABEL}:\n  {VALUE}\n",  # the value on the next line
    f"{LABEL}: \"{VALUE}\n  continued\"\n",  # a quoted value over two lines
    f"- {LABEL}={VALUE}\n",  # a sequence item, not a mapping value
], ids=["flow", "flow-in-sequence", "block-scalar", "next-line", "two-lines", "sequence-item"])
def test_these_values_are_never_occurrences(text):
    found = yaml_occurrences(PATH, text) or ()
    assert not [item for item in found if VALUE in text[item.value_start:item.value_end]]


def test_without_pyyaml_nothing_is_read(monkeypatch):
    monkeypatch.setattr(occurrence_identity, "load_yaml", lambda: None)
    assert yaml_occurrences(PATH, SERVICE) is None


def test_the_screen_remembers_outcomes_per_allowance():
    """A text screened with and without an allowance in one command is never answered from the other's outcome."""
    entry = _value_digest(SERVICE)
    allowance = OccurrenceAllowance({PATH: ({occurrence_identity.text_digest(SERVICE)}, {entry})}, {})
    with screening_cache():
        with pytest.raises(AssistantError, match="^sensitive_content$"):
            check_credentials(SERVICE, source_path=PATH)
        with allowance_in_effect(allowance):
            check_credentials(SERVICE, source_path=PATH)
        with pytest.raises(AssistantError, match="^sensitive_content$"):
            check_credentials(SERVICE, source_path=PATH)


def test_an_allowance_applies_only_to_the_exact_versions_it_checked():
    entry = _value_digest(SERVICE)
    allowance = OccurrenceAllowance({PATH: ({occurrence_identity.text_digest(SERVICE)}, {entry})}, {})
    with allowance_in_effect(allowance):
        check_credentials(SERVICE, source_path=PATH)
        for text, path in ((SERVICE + LATER_STEP, PATH), (SERVICE, "src/ci/other.yml"),
                           (SERVICE.split("    steps:")[0], PATH)):  # another version, path, or a piece
            with pytest.raises(AssistantError, match="^sensitive_content$"):
                check_credentials(text, source_path=path)


# The gate: unchanged without entries; a live entry lets exactly that value through and it is sent.

def test_without_an_entry_the_value_is_refused(gate_case):  # noqa: F811
    change_policy(gate_case)
    gate_case["head"] = _commit(gate_case["repo"], {PATH: SERVICE})
    report, calls = run(gate_case)
    assert report["verdict"] == "BLOCKED" and report["reasons"] == ["sensitive_content"] and not calls


def test_a_live_entry_lets_the_value_through_and_it_is_sent(gate_case):  # noqa: F811
    _enrolled(gate_case, SERVICE, SERVICE + LATER_STEP)
    report, calls = run(gate_case, _reviewing_every_file)
    assert report["verdict"] == "PASS" and len(calls) == 1
    assert VALUE in calls[0].content.decode()  # admitted source is ordinary reviewed source: it is sent
    assert VALUE not in canonical(report).decode()


@pytest.mark.parametrize("after", [
    SERVICE.replace(VALUE, VALUE + "-other"),  # the value edited
    SERVICE.replace(f"{LABEL}: {VALUE}", f"{LABEL}: '{VALUE}'"),  # requoted
    SERVICE.replace("      db:", "      cache:"),  # moved under another key
    SERVICE.replace("  test:", "  check:"),  # its job renamed
    SERVICE + f"  lint:\n    env:\n      {LABEL}: {VALUE}\n",  # copied to another job
], ids=["edited", "requoted", "moved", "renamed", "copied"])
def test_an_edit_move_or_copy_is_refused(gate_case, after):  # noqa: F811
    _enrolled(gate_case, SERVICE, after)
    report, calls = run(gate_case)
    assert report["verdict"] == "BLOCKED" and report["reasons"] == ["sensitive_content"] and not calls


def test_a_value_only_at_head_is_refused_even_when_listed_in_advance(gate_case):  # noqa: F811
    """A policy may name head content reviewed in advance; it still lapses unless present at base too."""
    entry = {"path": PATH, "occurrence_sha256": _value_digest(SERVICE)}
    change_policy(gate_case, placeholder_credential_occurrences=[entry])
    gate_case["head"] = _commit(gate_case["repo"], {PATH: SERVICE})
    report, calls = run(gate_case)
    assert report["verdict"] == "BLOCKED" and report["reasons"] == ["sensitive_content"] and not calls


def test_a_value_absent_at_the_merge_base_is_refused(gate_case):  # noqa: F811
    """Base and head both hold it, each added after the branches diverged. The policy, reviewed in advance, is the
    same at all three, so no policy change stops the gate first."""
    repo = gate_case["repo"]
    without = SERVICE.replace(f"          {LABEL}: {VALUE}\n", "          SYNTHETIC_MODE: test\n")
    document = model_policy()
    document["model_review"]["placeholder_credential_occurrences"] = [
        {"path": PATH, "occurrence_sha256": _value_digest(SERVICE)}]
    merge_base = _commit(repo, {PATH: without, "gate-policy.json": canonical(document).decode()})
    command(repo, "switch", "-q", "-c", "synthetic-feature")
    head = _commit(repo, {PATH: SERVICE, "src/cash.py": "def balance(opening):\n    return opening\n"})
    command(repo, "switch", "-q", "-c", "synthetic-main", merge_base)
    base = _commit(repo, {PATH: SERVICE})
    gate_case.update(base=base, head=head, pin=digest(canonical(document)))
    assert command(repo, "merge-base", base, head) == merge_base
    report, calls = run(gate_case)
    assert report["verdict"] == "BLOCKED" and report["reasons"] == ["sensitive_content"] and not calls
    row = _row(policy_preflight(repo, gate_case["base"], head, "gate-policy.json", gate_case["pin"]))
    assert row["placeholder_occurrences"] == [{"entry": 0, "status": "lapsed", "code": "placeholder_occurrence_lapsed",
                                               "revisions": {"base": "present", "merge_base": "absent",
                                                             "head": "present"}}]


def _key_value() -> str:
    return "AKIA" + "Q" * 16


def _url_login() -> str:
    return "postgres://synthetic:" + "w" * 14 + "@db/test"


@pytest.mark.parametrize("line", ["          AWS_KEY_ID: {}\n", "          DATABASE_URL: {}\n"], ids=["format", "url"])
def test_known_formats_and_url_passwords_are_refused_beside_a_live_entry(gate_case, line):  # noqa: F811
    extra = line.format(_key_value() if "AWS" in line else _url_login())
    after = SERVICE.replace(f"          {LABEL}: {VALUE}\n", f"          {LABEL}: {VALUE}\n{extra}")
    _enrolled(gate_case, SERVICE, after)
    report, calls = run(gate_case)
    assert report["verdict"] == "BLOCKED" and report["reasons"] == ["sensitive_content"] and not calls


def test_model_output_quoting_the_value_is_still_refused(gate_case):  # noqa: F811
    _enrolled(gate_case, SERVICE, SERVICE + LATER_STEP)
    report, calls = run(gate_case, lambda packet: _reviewing_every_file(
        packet, f"The service sets {LABEL}: {VALUE} for tests"))
    assert report["verdict"] == "BLOCKED" and report["reasons"] == ["sensitive_content"] and len(calls) == 1
    assert VALUE not in canonical(report).decode()


def test_without_pyyaml_a_listed_value_is_refused_and_doctor_says_why(gate_case, monkeypatch):  # noqa: F811
    _enrolled(gate_case, SERVICE, SERVICE + LATER_STEP)
    monkeypatch.setattr(occurrence_identity, "load_yaml", lambda: None)
    report, calls = run(gate_case)
    assert report["verdict"] == "BLOCKED" and report["reasons"] == ["sensitive_content"] and not calls
    doctor = policy_preflight(gate_case["repo"], gate_case["base"], gate_case["head"], "gate-policy.json",
                              gate_case["pin"])
    assert _row(doctor)["placeholder_occurrences"] == [
        {"entry": 0, "status": "lapsed", "code": "placeholder_occurrence_lapsed", "reason": "yaml_unavailable"}]


def test_doctor_names_a_live_entry_and_a_lapsed_one_without_any_value(gate_case):  # noqa: F811
    _enrolled(gate_case, SERVICE, SERVICE + LATER_STEP)
    live = policy_preflight(gate_case["repo"], gate_case["base"], gate_case["head"], "gate-policy.json",
                            gate_case["pin"])
    assert _row(live)["status"] == "included" and _row(live)["placeholder_occurrences"] == [
        {"entry": 0, "status": "live", "revisions": {"base": "present", "merge_base": "present", "head": "present"}}]
    gate_case["head"] = _commit(gate_case["repo"], {PATH: SERVICE.replace(VALUE, VALUE + "-other")})
    lapsed = policy_preflight(gate_case["repo"], gate_case["base"], gate_case["head"], "gate-policy.json",
                              gate_case["pin"])
    row = _row(lapsed)
    assert row["status"] == "refused" and row["code"] == "sensitive_content" and row["rule"] == "credential_label"
    assert row["placeholder_occurrences"] == [{"entry": 0, "status": "lapsed", "code": "placeholder_occurrence_lapsed",
                                               "revisions": {"base": "present", "merge_base": "present",
                                                             "head": "absent"}}]
    for report in (live, lapsed):
        assert VALUE not in canonical(report).decode()


def test_a_path_the_gate_would_not_review_is_never_read(tmp_path, monkeypatch):
    def never(*_args, **_kwargs):
        raise AssertionError("read")
    monkeypatch.setattr(placeholder_occurrences, "read_entry", never)
    allowance = build_allowance(tmp_path, (("base", "0" * 40),), [{"path": PATH, "occurrence_sha256": "0" * 64}],
                                None, lambda _path: False)
    assert allowance.explain(PATH) == [{"entry": 0, "status": "lapsed", "code": "placeholder_occurrence_lapsed",
                                        "reason": "not_reviewed"}]


@pytest.mark.parametrize("entry", [
    {"path": "src/ci/service.toml", "occurrence_sha256": "a" * 64},  # not YAML: TOML is not supported
    {"path": "src/ci/*.yml", "occurrence_sha256": "a" * 64},  # a pattern
    {"path": "../outside.yml", "occurrence_sha256": "a" * 64},  # not a repository path
], ids=["toml", "pattern", "outside"])
def test_an_entry_that_names_no_exact_yaml_file_is_refused(gate_case, entry):  # noqa: F811
    change_policy(gate_case, placeholder_credential_occurrences=[entry])
    report, calls = run(gate_case)
    assert report["verdict"] == "BLOCKED" and report["reasons"] == ["invalid_placeholder_credential_occurrences"]
    assert not calls


@pytest.mark.parametrize("entries", [
    [{"path": PATH, "occurrence_sha256": "A" * 64}],
    [{"path": PATH, "occurrence_sha256": "a" * 64, "value": "synthetic"}],
    [{"path": PATH}],
    [{"path": f"src/ci/s{index}.yml", "occurrence_sha256": "a" * 64} for index in range(65)],
], ids=["digest-case", "extra-field", "no-digest", "too-many"])
def test_a_malformed_entry_list_is_an_invalid_policy(gate_case, entries):  # noqa: F811
    change_policy(gate_case, placeholder_credential_occurrences=entries)
    report, calls = run(gate_case)
    assert report["verdict"] == "BLOCKED" and report["reasons"] == ["gate_policy_invalid"] and not calls


# Enrolment: a committed file, one line, the digest and never the value.

def test_enrolment_prints_the_entry_and_never_the_value(gate_case, capsys):  # noqa: F811
    revision = _commit(gate_case["repo"], {PATH: SERVICE})
    assert main(["placeholder-occurrence", "--repo", str(gate_case["repo"]), "--revision", revision,
                 "--path", PATH, "--line", str(LINE)]) == 0
    printed = capsys.readouterr().out
    assert VALUE not in printed
    result = json.loads(printed.splitlines()[-1])
    assert result["entry"] == {"path": PATH, "occurrence_sha256": _value_digest(SERVICE)}
    assert result["revision"] == revision and set(result) == {"path", "revision", "line", "entry", "qualification"}
    assert LABEL not in printed and "services" not in printed  # no key is printed


@pytest.mark.parametrize("content,line,path,code", [
    (SERVICE, 1, PATH, "placeholder_occurrence_not_found"),  # no credential-named value on that line
    (SERVICE, 99, PATH, "placeholder_occurrence_not_found"),
    # The key's own value is too short to match; a label match later on the line is not the key's.
    (SERVICE.replace(VALUE, "synthetic api_key=" + "k" * 16), LINE, PATH, "placeholder_occurrence_ambiguous"),
    (SERVICE.replace(f"{LABEL}: {VALUE}", f"{LABEL}: &x {VALUE}"), LINE, PATH, "placeholder_occurrence_unsupported"),
    (SERVICE, LINE, "src/ci/service.toml", "placeholder_occurrence_unsupported"),
], ids=["not-a-value", "past-the-end", "two-matches", "anchor", "toml"])
def test_enrolment_refuses_what_it_cannot_bind_exactly(gate_case, capsys, content, line, path, code):  # noqa: F811
    revision = _commit(gate_case["repo"], {path: content})
    assert main(["placeholder-occurrence", "--repo", str(gate_case["repo"]), "--revision", revision,
                 "--path", path, "--line", str(line)]) == 2
    assert json.loads(capsys.readouterr().err)["code"] == code


def test_enrolment_refuses_a_known_format(gate_case):  # noqa: F811
    revision = _commit(gate_case["repo"], {PATH: SERVICE.replace(VALUE, _key_value())})
    with pytest.raises(AssistantError, match="^placeholder_occurrence_known_format$"):
        enroll(gate_case["repo"], revision, PATH, LINE)


def test_enrolment_without_pyyaml_is_refused(gate_case, monkeypatch):  # noqa: F811
    revision = _commit(gate_case["repo"], {PATH: SERVICE})
    monkeypatch.setattr(occurrence_identity, "load_yaml", lambda: None)
    with pytest.raises(AssistantError, match="^placeholder_occurrence_yaml_unavailable$"):
        enroll(gate_case["repo"], revision, PATH, LINE)


def test_the_counterexample_texts_bind_one_value_each():
    """Each supported value has one identity: the digests of a file are all different."""
    found = _digests(SERVICE)
    assert len(found) == len(set(found)) and _value_digest(SERVICE) in found


def test_an_unchanged_policy_reads_no_yaml(gate_case, monkeypatch):  # noqa: F811
    def never(*_args, **_kwargs):
        raise AssertionError("parsed")
    monkeypatch.setattr(occurrence_identity, "_walk", never)
    change_policy(gate_case)
    gate_case["head"] = _commit(gate_case["repo"], {"src/ci/plain.yml": "jobs:\n  test:\n    run: make\n"})
    report, calls = run(gate_case, _reviewing_every_file)
    assert report["verdict"] == "PASS" and len(calls) == 1


# Review findings: ignored files are never read; no key text is printed; keys are typed; the parser is the reviewed one.

def _reads(monkeypatch) -> list[str]:
    """Every path the occurrence reader asks Git for."""
    seen, real = [], placeholder_occurrences.read_entry

    def spy(repo, revision, path, *args, **kwargs):
        seen.append(path)
        return real(repo, revision, path, *args, **kwargs)
    monkeypatch.setattr(placeholder_occurrences, "read_entry", spy)
    return seen


def _ignored_base(case) -> None:
    """A tracked service file that the committed ignore rules exclude, then a policy listing its value."""
    repo = case["repo"]
    (repo / ".gitignore").write_text(PATH + "\n", encoding="utf-8")
    target = repo / PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(SERVICE, encoding="utf-8")
    command(repo, "add", ".gitignore")
    command(repo, "add", "--force", "--", PATH)
    command(repo, "commit", "-q", "-m", "Synthetic ignored service file")
    change_policy(case, placeholder_credential_occurrences=[{"path": PATH, "occurrence_sha256": _value_digest(SERVICE)}])


def test_an_unchanged_listed_file_the_ignore_rules_exclude_is_never_read(gate_case, monkeypatch):  # noqa: F811
    _ignored_base(gate_case)
    reads = _reads(monkeypatch)
    report, calls = run(gate_case, _reviewing_every_file)
    assert report["verdict"] == "PASS" and len(calls) == 1 and PATH not in reads
    policy_preflight(gate_case["repo"], gate_case["base"], gate_case["head"], "gate-policy.json", gate_case["pin"])
    assert PATH not in reads


def test_a_changed_listed_file_the_ignore_rules_exclude_is_never_read(gate_case, monkeypatch):  # noqa: F811
    _ignored_base(gate_case)
    repo = gate_case["repo"]
    (repo / PATH).write_text(SERVICE + LATER_STEP, encoding="utf-8")
    command(repo, "add", "--force", "--", PATH)
    command(repo, "commit", "-q", "-m", "Synthetic ignored change")
    gate_case["head"] = command(repo, "rev-parse", "HEAD")
    reads = _reads(monkeypatch)
    report, calls = run(gate_case)
    assert report["verdict"] == "BLOCKED" and report["reasons"] == ["gate_ignored_path"] and not calls
    assert PATH not in reads


def test_a_separate_policy_repositorys_ignore_rules_also_stop_the_read(gate_case, tmp_path, monkeypatch):  # noqa: F811
    from finassist.model_gate import placeholder_occurrence_allowance
    from finassist.model_policy import load_model_policy
    repo = gate_case["repo"]
    base = _commit(repo, {PATH: SERVICE}, "Synthetic service file")
    head = _commit(repo, {PATH: SERVICE + LATER_STEP})
    other = tmp_path / "policies"
    other.mkdir()
    command(other, "init", "-q")
    document = model_policy()
    document["model_review"]["placeholder_credential_occurrences"] = [
        {"path": PATH, "occurrence_sha256": _value_digest(SERVICE)}]
    (other / "gate-policy.json").write_bytes(canonical(document))
    (other / ".gitignore").write_text(PATH + "\n", encoding="utf-8")
    command(other, "add", "gate-policy.json", ".gitignore")
    command(other, "-c", "user.name=Synthetic", "-c", "user.email=synthetic@example.invalid",
            "commit", "-q", "-m", "Synthetic policy repository")
    policy = load_model_policy(other, command(other, "rev-parse", "HEAD"), "gate-policy.json",
                               digest(canonical(document)))
    reads = _reads(monkeypatch)
    allowance = placeholder_occurrence_allowance(repo, base, head, policy, other)
    assert allowance.explain(PATH) == [{"entry": 0, "status": "lapsed", "code": "placeholder_occurrence_lapsed",
                                        "reason": "not_reviewed"}]
    assert reads == []
    assert placeholder_occurrence_allowance(repo, base, head, policy).explain(PATH)[0]["status"] == "live"


def test_enrolment_refuses_a_file_its_commit_ignores_before_reading(gate_case, monkeypatch):  # noqa: F811
    repo = gate_case["repo"]
    (repo / ".gitignore").write_text(PATH + "\n", encoding="utf-8")
    (repo / PATH).parent.mkdir(parents=True, exist_ok=True)
    (repo / PATH).write_text(SERVICE, encoding="utf-8")
    command(repo, "add", ".gitignore")
    command(repo, "add", "--force", "--", PATH)
    command(repo, "commit", "-q", "-m", "Synthetic ignored service file")
    reads = _reads(monkeypatch)
    with pytest.raises(AssistantError, match="^gate_ignored_path$"):
        enroll(repo, command(repo, "rev-parse", "HEAD"), PATH, LINE)
    assert reads == []


def test_enrolment_prints_no_key_text_even_a_credential_shaped_ancestor(gate_case, capsys):  # noqa: F811
    ancestor = "AKIA" + "Q" * 16  # a fake key-shaped mapping key above the value
    revision = _commit(gate_case["repo"], {PATH: SERVICE.replace("      db:", f"      {ancestor}:")})
    assert main(["placeholder-occurrence", "--repo", str(gate_case["repo"]), "--revision", revision,
                 "--path", PATH, "--line", str(LINE)]) == 0
    streams = capsys.readouterr()
    for text in (streams.out, streams.err):
        assert ancestor not in text and LABEL not in text and VALUE not in text


@pytest.mark.parametrize("before,after", [("true:", '"true":'), ("null:", '"null":'), ("on:", "'on':")])
def test_a_key_is_bound_by_its_resolved_type(before, after):
    text = f"{before}\n  env:\n    {LABEL}: {VALUE}\n"
    assert _value_digest(text) != _value_digest(text.replace(before, after))


@pytest.mark.parametrize("text", [
    f"1:\n  env:\n    {LABEL}: {VALUE}\n",  # a numeric key
    f"2026-11-13:\n  env:\n    {LABEL}: {VALUE}\n",  # a date key
    "true:\n  a: x\nyes:\n  b: y\n",  # the same boolean twice
    "null:\n  a: x\n~:\n  b: y\n",  # the same null twice
    "1:\n  a: x\n01:\n  b: y\n",  # numbers, the same one twice
], ids=["number", "date", "true-yes", "null-tilde", "one-zero-one"])
def test_untyped_or_semantically_repeated_keys_are_outside_the_subset(text):
    assert yaml_occurrences(PATH, text) is None


def test_a_github_workflow_with_an_on_key_is_read():
    text = f"on:\n  push:\n    branches: [main]\njobs:\n  test:\n    env:\n      {LABEL}: {VALUE}\n"
    assert _value_digest(text)


def test_a_key_type_change_lapses_a_live_entry_at_the_gate(gate_case):  # noqa: F811
    before = f"true:\n  env:\n    {LABEL}: {VALUE}\n"
    _enrolled(gate_case, before, before.replace("true:", '"true":'), line=3)
    report, calls = run(gate_case)
    assert report["verdict"] == "BLOCKED" and report["reasons"] == ["sensitive_content"] and not calls


@pytest.mark.parametrize("module", [type("Parser", (), {"__version__": "5.4.1"}), type("Parser", (), {})],
                         ids=["other-version", "no-version"])
def test_another_pyyaml_is_not_used(gate_case, monkeypatch, module):  # noqa: F811
    _enrolled(gate_case, SERVICE, SERVICE + LATER_STEP)
    monkeypatch.setattr(occurrence_identity, "load_yaml", lambda: module)
    assert yaml_occurrences(PATH, SERVICE) is None
    report, calls = run(gate_case)
    assert report["verdict"] == "BLOCKED" and report["reasons"] == ["sensitive_content"] and not calls
    doctor = policy_preflight(gate_case["repo"], gate_case["base"], gate_case["head"], "gate-policy.json",
                              gate_case["pin"])
    assert _row(doctor)["placeholder_occurrences"][0]["reason"] == "yaml_unsupported_version"
    with pytest.raises(AssistantError, match="^placeholder_occurrence_yaml_unavailable$"):
        enroll(gate_case["repo"], gate_case["head"], PATH, LINE)


def test_the_yaml_extra_pins_the_reviewed_and_locked_parser():
    import tomllib
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    assert project["project"]["optional-dependencies"]["yaml"] == [f"PyYAML=={occurrence_identity.SUPPORTED_PYYAML}"]
    lock = (root / "requirements-dev.lock").read_text(encoding="utf-8")
    assert f"\npyyaml=={occurrence_identity.SUPPORTED_PYYAML} \\\n" in lock
    assert "yaml" not in " ".join(project["project"]["dependencies"]).lower()  # the core install stays without it


def test_enrolment_reads_no_configuration(gate_case, tmp_path, capsys):  # noqa: F811
    revision = _commit(gate_case["repo"], {PATH: SERVICE})
    broken = tmp_path / "broken-configuration.json"
    broken.write_text("{not json", encoding="utf-8")
    assert main(["--config", str(broken), "placeholder-occurrence", "--repo", str(gate_case["repo"]),
                 "--revision", revision, "--path", PATH, "--line", str(LINE)]) == 0
    assert json.loads(capsys.readouterr().out.splitlines()[-1])["entry"]["path"] == PATH


# Second review: no listed file is read before the gate's own guards; an admitted literal is never a reference quote.

@pytest.mark.parametrize("stop", ["file-count", "rule-file"])
@pytest.mark.parametrize("caller", ["gate", "doctor"])
def test_a_guard_that_stops_the_run_reads_no_listed_file(gate_case, monkeypatch, stop, caller):  # noqa: F811
    _enrolled(gate_case, SERVICE, SERVICE + LATER_STEP)
    if stop == "file-count":
        files, expected = {f"src/p{index}.py": f"v = {index}\n" for index in range(11)}, "gate_file_count_exceeded"
    else:
        files, expected = {".gitignore": ".finassist/\n!src/keep.py\n"}, "gate_ignore_change_requires_review"
    gate_case["head"] = _commit(gate_case["repo"], files)
    reads = _reads(monkeypatch)
    if caller == "gate":
        report, calls = run(gate_case)
        assert expected in report["reasons"] and not calls
    else:
        doctor = policy_preflight(gate_case["repo"], gate_case["base"], gate_case["head"], "gate-policy.json",
                                  gate_case["pin"])
        assert expected in [blocker["code"] for blocker in doctor["blockers"]]
    assert PATH not in reads


@pytest.mark.parametrize("claim", [f"{LABEL}: {VALUE}", f"{LABEL}: {VALUE}\n", f"Example:\n{LABEL}: {VALUE}",
                                   f"The service sets {LABEL}: {VALUE} for tests"],
                         ids=["exact", "trailing-newline", "after-a-line", "in-prose"])
def test_an_admitted_literal_is_never_lent_as_a_reference_quote(gate_case, claim):  # noqa: F811
    _enrolled(gate_case, SERVICE, SERVICE + LATER_STEP)
    report, calls = run(gate_case, lambda packet: _reviewing_every_file(packet, claim))
    assert len(calls) == 1 and report["verdict"] == "BLOCKED" and report["reasons"] == ["sensitive_content"]
    assert VALUE not in canonical(report).decode()


@pytest.mark.parametrize("claim,verdict,repeated", [
    ("A note about other code", "PASS", False),
    (f"{LABEL} is a fixture key", "PASS", False),
    (f"export {LABEL}={VALUE}", "BLOCKED", False),
    (f'"{LABEL}": "{VALUE}"', "BLOCKED", False),
    (f"Fixture value {VALUE}", "PASS", True),  # the documented disclosure: a bare value may be repeated
], ids=["unrelated", "key-name", "shell", "json", "bare-value"])
def test_what_output_may_repeat(gate_case, claim, verdict, repeated):  # noqa: F811
    _enrolled(gate_case, SERVICE, SERVICE + LATER_STEP)
    report, calls = run(gate_case, lambda packet: _reviewing_every_file(packet, claim))
    assert len(calls) == 1 and report["verdict"] == verdict
    assert (VALUE in canonical(report).decode()) == repeated


def test_a_whole_file_placeholder_listing_keeps_its_exact_quote(gate_case):  # noqa: F811
    """The separately specified path listing still lends an exact quote of a value it covers."""
    repo = gate_case["repo"]
    _commit(repo, {PATH: SERVICE}, "Synthetic service file")
    change_policy(gate_case, placeholder_credential_paths=[PATH])
    gate_case["head"] = _commit(repo, {PATH: SERVICE + LATER_STEP})
    report, calls = run(gate_case, lambda packet: _reviewing_every_file(packet, f"{LABEL}: {VALUE}"))
    assert len(calls) == 1 and report["verdict"] == "PASS"
