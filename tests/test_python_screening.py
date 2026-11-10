"""Python-aware screening (#61): tokenize for figures, the AST for credentials.

Synthetic values only. Secret-shaped values are assembled at runtime so this file
contains no credential-shaped literal of its own.
"""
import hashlib
import json
import re
import sys
import warnings

import pytest

from finassist.errors import AssistantError
from finassist.forbidden_tokens import TokenSnapshot, normalize_numeric_token, screen_packet, screen_source
from finassist.python_source import number_text, python_screen, python_tokens
from finassist.security import check_context_document, check_text
from test_forbidden_token_gate import candidate
from test_model_gate import change_policy, run
from test_providers_review import envelope

pytest_plugins = ("test_model_gate", "test_model_policy")

KEY = "".join(["Zq7Lm2", "Xp9Rt4", "Vw8"])
CAPS = "".join(["ZQLMXP", "RTVWYBCDEF"])
TOKEN = "ghp_" + "a" * 36
# Labels are split so this file's own strings never pair a label with a value.
SK, PK, PW = "signing_" + "key", "private_" + "key", "pass" + "word"
Q = '"'
FIGURE = "6729102.50"
SNAPSHOT = TokenSnapshot(frozenset({hashlib.sha256(normalize_numeric_token(FIGURE).encode()).hexdigest()}))
WHOLE = TokenSnapshot(frozenset({hashlib.sha256(b"6729102").hexdigest()}))
LISTED_42 = TokenSnapshot(frozenset({hashlib.sha256(b"42").hexdigest()}))
UNTOKENIZABLE = 'note = "unterminated\n'


def refuses(text, path):
    with pytest.raises(AssistantError, match="^sensitive_content$"):
        check_text(text, source_path=path)


# --- Credentials in parseable Python: the AST reads code ---------------------

@pytest.mark.parametrize("source", [
    f"password: str = {Q}{KEY}{Q}\n",                          # 0.7.0 miss
    f"api_key: str = {Q}{KEY}{Q}\n",                           # 0.7.0 miss
    f"def connect(api_key: str = {Q}{KEY}{Q}):\n    pass\n",    # 0.7.0 miss: typed default
    f"def connect(*, password={Q}{KEY}{Q}):\n    pass\n",
    f"client.connect(password={Q}{KEY}{Q})\n",
    f"CONFIG = {{{Q}api_key{Q}: {Q}{KEY}{Q}}}\n",
    f"self.signing_key = {Q}{KEY}{Q}\n",
    f"os.environ[{Q}API_KEY{Q}] = {Q}{KEY}{Q}\n",
    f"user, password = {Q}alice{Q}, {Q}{KEY}{Q}\n",
    f"if (password := {Q}{KEY}{Q}):\n    pass\n",
    f"password = os.getenv({Q}PW{Q}, {Q}{KEY}{Q})\n",
    f"{PW} = os.environ.get({Q}PW{Q}, {Q}{KEY}{Q})\n",
    f"api_key: str = Field(default={Q}{KEY}{Q})\n",
    f"apiKey = {Q}{KEY}{Q}\n",
    f"auth_key = {Q}{CAPS}{Q}\n",                               # quoted all-caps literal
    f"secret = b{Q}{KEY}{Q}\n",
    "account_number: int = 12345678\n",
    f"routing_number = {Q}021000021{Q}\n",
    f"# signing_key: {KEY}\n",                                 # comments are text
    f"s = {Q}signing_key: {KEY}{Q}\n",                         # strings are text
    f'"""\napi_key: {KEY}/x+y==\n"""\n',                      # docstring YAML is text
])
def test_python_credential_literals_refuse(source):
    refuses(source, "src/settings.py")


@pytest.mark.parametrize("source", [
    f"{SK}: Ed25519PrivateKey | None = None\n",                # annotation only
    f"def sign({PK}: X25519PrivateKey | None = None):\n    pass\n",
    f'{SK}: "Ed25519PrivateKey"\n',                           # forward reference
    "signing_key: Optional[SigningKey] = None\n",
    f"signing_key = {KEY}\n",                                  # unquoted name, not a literal
    f"auth_key = {CAPS}\n",
    f"{PW} = get_password_from_vault()\n",                     # call result, not a literal
    f"{PW} = request.form.get({Q}password{Q})\n",
    f"api_key = os.environ[{Q}API_KEY{Q}]\n",
    f"password = {Q}short{Q}\n",                               # under the length threshold
    f"password_hash = {Q}{KEY}{Q}\n",                          # name does not end in a credential word
    f"token_type = {Q}{KEY}{Q}\n",                             # outside the vocabulary
    'primary_key = "transaction_id"\n',
])
def test_python_non_literals_and_annotations_pass(source):
    check_text(source, source_path="src/settings.py")


def test_python_known_formats_and_custom_patterns_still_read_raw_text():
    refuses(f"bootstrap = {Q}{TOKEN}{Q}\n", "src/settings.py")
    with pytest.raises(AssistantError, match="^project_content_blocked$"):
        check_text(f"{SK}: Ed25519PrivateKey\n", source_path="a.py", extra_patterns=("Ed25519",))


def test_unparseable_python_keeps_the_strict_text_rules():
    refuses(f"{SK}: Ed25519PrivateKey\nif x\n", "src/broken.py")
    refuses(f"password = {KEY} (\n", "src/broken.py")  # unparseable: the text rule reads unquoted values


@pytest.mark.parametrize("name,source,refused", [
    ("c.yaml", f"aws_secret_access_key: {KEY}Yb3\n", True),
    ("c.yaml", f"{SK}: Ed25519PrivateKey\n", True),             # documented text-rule limit
    ("README.md", f"```python\n{SK}: Ed25519PrivateKey\n```\n", True),
    ("README.md", f"```python\npassword: str = {Q}{KEY}{Q}\n```\n", False),  # documented gap
    ("c.yaml", f"auth_key: {CAPS}\n", False),                   # documented gap
])
def test_non_python_files_keep_the_text_rules(name, source, refused):
    if refused:
        refuses(source, name)
    else:
        check_text(source, source_path=name)


def test_context_document_does_not_undo_python_decisions():
    document = {"files": [{"path": "a.py", "before": None,
                           "after": f"{SK}: Ed25519PrivateKey | None = None\n"
                                    f"{PW} = get_password_from_vault()\n"}]}
    check_context_document(document)
    document["files"][0]["after"] += f"api_key: str = {Q}{KEY}{Q}\n"
    with pytest.raises(AssistantError, match="^sensitive_content$"):
        check_context_document(document)


def test_python_parsing_never_warns_or_echoes_source():
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        assert python_screen('pattern = "\\d+"\n') is not None
    assert not caught


def test_typed_default_never_dispatches_or_reserves(gate_case):
    candidate(gate_case, f"def connect(api_key: str = {Q}{KEY}{Q}):\n    pass\n")
    report, calls = run(gate_case)
    assert report["verdict"] == "BLOCKED" and report["reasons"] == ["sensitive_content"] and not calls
    assert not (gate_case["state"] / "audit.sqlite").exists()


def test_annotations_and_call_results_pass_the_gate(gate_case):
    source = (f"{SK}: Ed25519PrivateKey | None = None\n"
              f"{PW} = get_password_from_vault()\n")
    candidate(gate_case, source)

    def clear(packet):
        return envelope(json.dumps({"head": packet["head"], "summary": "Synthetic coverage",
                                   "reviewed_paths": [f["path"] for f in packet["files"]], "findings": []}))
    report, calls = run(gate_case, clear)
    assert report["verdict"] == "PASS" and len(calls) == 1


# --- Figures: text screen everywhere, plus Python's own reading of numbers ----

@pytest.mark.parametrize("source", [
    "total = 6_729_102.50\n", "total = 67_29_102.50\n", "total = 6729_102.5\n",
    "total = 67291025e-1\n", "total = 6729102.50j\n", "total = -6729102.50\n",
    f"total = Decimal({Q}6,729,102.50{Q})\n", "# reconciled 6,729,102.50\n",
    '"""Opening balance 6 729 102.50."""\n', "msg = f" + Q + "{6729102.50}" + Q + "\n",
    "t = (6,729,102.50)\n",                                     # text still reads as the figure
])
def test_python_figures_refuse(source):
    with pytest.raises(AssistantError, match="^forbidden_token_present$"):
        screen_source(source, "src/cash.py", SNAPSHOT)


@pytest.mark.parametrize("literal", [hex(6729102), oct(6729102), bin(6729102), "6_729_102"])
def test_python_integers_in_any_base_compare_by_value(literal):
    with pytest.raises(AssistantError, match="^forbidden_token_present$"):
        screen_source(f"n = {literal}\n", "src/cash.py", WHOLE)
    screen_text_only = f"n = {literal}\n"
    if literal.startswith("0x"):
        screen_source(screen_text_only, "notes.md", WHOLE)  # text does not read hexadecimal


@pytest.mark.parametrize("source", ["total = 6729102.51\n", "total = 16_729_102.50\n", "n = 0x1F\n"])
def test_python_near_misses_pass(source):
    screen_source(source, "src/cash.py", SNAPSHOT)


def test_untokenizable_python_is_refused_only_while_screening():
    with pytest.raises(AssistantError, match="^forbidden_token_python_unreadable$"):
        screen_source(UNTOKENIZABLE, "src/cash.py", SNAPSHOT)
    screen_source(UNTOKENIZABLE, "src/cash.py", TokenSnapshot(frozenset()))
    screen_source(UNTOKENIZABLE, "notes.txt", SNAPSHOT)
    with pytest.raises(AssistantError, match="^forbidden_token_python_unreadable$"):
        screen_packet({"files": [{"path": "src/cash.py", "before": None, "after": UNTOKENIZABLE}]},
                      "review", SNAPSHOT)


@pytest.mark.parametrize("name,source,refused", [
    ("data.csv", "id,amount\n7,6729102.50\n", True),
    ("notes.md", "Total: 6.729.102,50\n", False),                # documented gap: decimal commas
    ("notes.md", "six million seven hundred twenty-nine thousand one hundred two\n", False),
])
def test_non_python_figures_use_the_text_screen(name, source, refused):
    if refused:
        with pytest.raises(AssistantError, match="^forbidden_token_present$"):
            screen_source(source, name, SNAPSHOT)
    else:
        screen_source(source, name, SNAPSHOT)


def test_untokenizable_python_is_refused_before_key_or_ledger(gate_case, monkeypatch):
    change_policy(gate_case, forbidden_token_hashes=[hashlib.sha256(b"6729102.5").hexdigest()])
    candidate(gate_case, UNTOKENIZABLE)
    monkeypatch.delenv("REVIEW_PROVIDER_KEY")
    report, calls = run(gate_case)
    assert not calls and report["reasons"] == ["forbidden_token_python_unreadable"]
    assert not (gate_case["state"] / "audit.sqlite").exists()
    assert "6729102" not in json.dumps(report)


def test_hexadecimal_whole_figure_is_refused_before_key_or_ledger(gate_case, monkeypatch):
    change_policy(gate_case, forbidden_token_hashes=[hashlib.sha256(b"6729102").hexdigest()])
    candidate(gate_case, f"LIMIT = {hex(6729102)}\n")
    monkeypatch.delenv("REVIEW_PROVIDER_KEY")
    report, calls = run(gate_case)
    assert not calls and report["reasons"] == ["forbidden_token_present"]
    assert not (gate_case["state"] / "audit.sqlite").exists()


# --- Tokenizer helpers ----------------------------------------------------------

@pytest.mark.parametrize("token,expected", [
    ("6_729_102.50", "6729102.5"), ("67291025e-1", "6729102.5"), ("6729102.50j", "6729102.5"),
    ("0x1F", "31"), ("0b101", "5"), ("0o17", "15"),
    ("0x" + "0" * 300 + "2A", "42"), ("6729102.5" + "0" * 300, "6729102.5"),  # padding is value-neutral
    ("1e999999999", None), ("9" * 400, None), ("0x" + "F" * 240, None),     # beyond any listed value
])
def test_number_text_reads_exact_values_within_bounds(token, expected):
    assert number_text(token) == expected


def test_unterminated_source_never_yields_a_partial_token_stream():
    assert python_tokens(UNTOKENIZABLE) is None
    assert python_tokens("x = (1,\n") is None
    assert python_tokens("x = 1\r\ny = 2\r") is not None


# --- Codex review of #62: findings 1-5 -------------------------------------------

@pytest.mark.parametrize("source", [
    'message = f"{0x2A}"\n',
    'message = f"{value:{0x2A}}"\n',            # format-spec expression
    'message = f"{0b101010!r} total"\n',
])
def test_numbers_inside_fstring_fields_compare_by_value(source):
    with pytest.raises(AssistantError, match="^forbidden_token_present$"):
        screen_source(source, "src/cash.py", LISTED_42)


@pytest.mark.skipif(sys.version_info >= (3, 12), reason="3.12+ tokenizes f-string fields")
def test_unparseable_fstring_fields_are_unreadable_before_python_312():
    with pytest.raises(AssistantError, match="^forbidden_token_python_unreadable$"):
        screen_source('message = f"{0x2A}"\nif x\n', "src/cash.py", LISTED_42)


def test_fstring_field_number_is_refused_before_key_or_ledger(gate_case, monkeypatch):
    change_policy(gate_case, forbidden_token_hashes=[hashlib.sha256(b"42").hexdigest()])
    candidate(gate_case, 'message = f"{0x2A}"\n')
    monkeypatch.delenv("REVIEW_PROVIDER_KEY")
    report, calls = run(gate_case)
    assert not calls and report["reasons"] == ["forbidden_token_present"]
    assert not (gate_case["state"] / "audit.sqlite").exists()


def test_padded_python_literals_compare_by_value():
    with pytest.raises(AssistantError, match="^forbidden_token_present$"):
        screen_source("n = 0x" + "0" * 300 + "2A\n", "src/cash.py", LISTED_42)
    with pytest.raises(AssistantError, match="^forbidden_token_present$"):
        screen_source("total = 6729102.5" + "0" * 300 + "\n", "src/cash.py", SNAPSHOT)
    big = 10 ** 93 + 7                                   # a 94-digit synthetic integer
    listed = TokenSnapshot(frozenset({hashlib.sha256(str(big).encode()).hexdigest()}))
    assert len(bin(big)) > 300
    with pytest.raises(AssistantError, match="^forbidden_token_present$"):
        screen_source(f"n = {bin(big)}\n", "src/cash.py", listed)


@pytest.mark.parametrize("source", ["amount\n6729102.5" + "0" * 300 + "\n", "amount\n0000006729102.50\n"])
def test_zero_padded_text_figures_are_refused(source):
    with pytest.raises(AssistantError, match="^forbidden_token_present$"):
        screen_source(source, "data.csv", SNAPSHOT)


def test_huge_integers_stay_bounded():
    huge = "0x" + "F" * 4000
    screen_source(f"n = {huge}\n", "src/cash.py", LISTED_42)   # too large to be a listed figure
    refuses(f"{PW} = {huge}\n", "src/settings.py")             # a literal, refused without int-to-str


@pytest.mark.parametrize("path", ["notes.txt", "src/notes.py"])
def test_custom_patterns_read_the_intact_serialized_packet(path):
    document = {"files": [{"path": path, "before": None, "after": "marker-left\nmarker-right\n"}]}
    # Matches only the serialized packet: a literal backslash then "n", the JSON escape.
    serialized_only = re.escape("marker-left" + "\\" + "nmarker-right")
    assert not re.search(serialized_only, document["files"][0]["after"])
    check_context_document(document)
    with pytest.raises(AssistantError, match="^project_content_blocked$"):
        check_context_document(document, extra_patterns=(serialized_only,))


def test_long_credential_names_keep_the_vocabulary():
    name = "x" * 250 + "_" + PW
    refuses(f"{name} = {Q}synthetic_example{Q}\n", "src/settings.py")
    check_text(f"{name}_hash = {Q}synthetic_example{Q}\n", source_path="src/settings.py")


@pytest.mark.parametrize("source", ["account_" + "number = 12345678.0\n", "routing_" + "number = 12345678j\n"])
def test_numeric_account_literals_keep_their_source_spelling(source):
    refuses(source, "src/settings.py")


def test_tokens_read_numbers_when_the_file_does_not_parse():
    # No f-string fields, so the token stream alone is complete on every version.
    with pytest.raises(AssistantError, match="^forbidden_token_present$"):
        screen_source(f"n = {hex(6729102)}\nif x\n", "src/cash.py", WHOLE)


# --- Codex review of #62, round 2: findings 1-6 ----------------------------------

def _listing(*values):
    return TokenSnapshot(frozenset(hashlib.sha256(normalize_numeric_token(v).encode()).hexdigest()
                                   for v in values))


@pytest.mark.parametrize("source", ['m = f"{.1234567890123456789}"\n', "m = .1234567890123456789\n"])
def test_precise_decimals_keep_their_spelling(source):
    with pytest.raises(AssistantError, match="^forbidden_token_present$"):
        screen_source(source, "src/cash.py", _listing("0.1234567890123456789"))
    # The float rounding of the same literal is a different value and must not refuse.
    screen_source(source, "src/cash.py", _listing("0.12345678901234568"))


def test_exponent_policy_entries_cover_base_prefixed_literals(tmp_path):
    from finassist.forbidden_tokens import load_token_snapshot
    entry = tmp_path / "figures.txt"
    entry.write_text("1000000000000e128\n1e128\n", encoding="utf-8")
    snapshot = load_token_snapshot({"forbidden_token_file": str(entry)}, ())
    for source in (f"n = {hex(10 ** 140)}\n", f"n = {hex(10 ** 128)}\n", f"n = {10 ** 140}\n"):
        with pytest.raises(AssistantError, match="^forbidden_token_present$"):
            screen_source(source, "src/cash.py", snapshot)
    with pytest.raises(AssistantError, match="^forbidden_token_present$"):
        screen_source(f"amount\n{10 ** 140}\n", "data.csv", snapshot)


def test_exponent_policy_entry_is_refused_before_key_or_ledger(gate_case, monkeypatch):
    listed = normalize_numeric_token("1000000000000e128")
    change_policy(gate_case, forbidden_token_hashes=[hashlib.sha256(listed.encode()).hexdigest()])
    candidate(gate_case, f"LIMIT = {hex(10 ** 140)}\n")
    monkeypatch.delenv("REVIEW_PROVIDER_KEY")
    report, calls = run(gate_case)
    assert not calls and report["reasons"] == ["forbidden_token_present"]
    assert not (gate_case["state"] / "audit.sqlite").exists()


@pytest.mark.parametrize("path", ["src/cash.py", "data.csv"])
def test_separated_decimals_keep_their_value(path):
    listed = _listing("1.21")
    screen_source("n = 1.20_1\n", path, listed)          # 1.201, not 1.21
    with pytest.raises(AssistantError, match="^forbidden_token_present$"):
        screen_source("n = 1.2_1\n", path, listed)       # 1.21


@pytest.mark.alone
@pytest.mark.parametrize("path", ["src/cash.py", "data.csv"])
def test_long_zero_runs_screen_in_linear_time(path):
    import time
    started = time.perf_counter()
    screen_source("n = 1." + "0" * 200_000 + "1\n", path, SNAPSHOT)
    assert time.perf_counter() - started < 5


def test_unicode_credential_names_keep_released_coverage():
    refuses(f"café_{PW} = {Q}synthetic_example{Q}\n", "src/settings.py")
    refuses("café_account_" + "number = 12345678\n", "src/settings.py")


@pytest.mark.parametrize("value,refused", [("123_456_789", True), ("0x1E240", True), ("0x1869F", False)])
def test_account_integers_compare_by_magnitude(value, refused):
    source = "account_" + f"number = {value}\n"
    if refused:
        refuses(source, "src/settings.py")
    else:
        check_text(source, source_path="src/settings.py")   # 99,999: under six digits


# --- Codex review of #62, round 3: findings 1-3 ----------------------------------

ARABIC_INDIC_PADDED_42 = "٠" * 300 + "٤٢"   # 42, padded with Arabic-Indic zeros


@pytest.mark.parametrize("path,source", [
    ("data.csv", "amount\n" + ARABIC_INDIC_PADDED_42 + "\n"),
    ("src/cash.py", f"amount = {Q}{ARABIC_INDIC_PADDED_42}{Q}\n"),
])
def test_unicode_zero_padding_cannot_hide_a_listed_figure(path, source):
    with pytest.raises(AssistantError, match="^forbidden_token_present$"):
        screen_source(source, path, LISTED_42)


def test_unicode_padded_fixture_is_refused_before_key_or_ledger(gate_case, monkeypatch):
    from test_policy_text_fixtures import candidate as fixture_candidate
    change_policy(gate_case, forbidden_token_hashes=[hashlib.sha256(b"42").hexdigest()],
                  allow_paths=["src/", "tests/"], fixture_roots=["tests/fixtures/"])
    fixture_candidate(gate_case, "tests/fixtures/padded.csv",
                      ("symbol,value\nSYNTHETIC," + ARABIC_INDIC_PADDED_42 + "\n").encode("utf-8"))
    monkeypatch.delenv("REVIEW_PROVIDER_KEY")
    report, calls = run(gate_case)
    assert not calls and report["reasons"] == ["forbidden_token_present"]
    assert not (gate_case["state"] / "audit.sqlite").exists()


@pytest.mark.parametrize("template", ["x = {}\n", 'm = f"{{{}}}"\n'])
def test_out_of_range_exact_values_are_not_their_rounded_neighbours(template):
    listed_one = _listing("1")
    near_miss = "1." + "0" * 270 + "1"          # greater than 1; beyond the figure bounds
    exactly_one = "1." + "0" * 270              # equal to 1
    screen_source(template.format(near_miss), "src/cash.py", listed_one)
    with pytest.raises(AssistantError, match="^forbidden_token_present$"):
        screen_source(template.format(exactly_one), "src/cash.py", listed_one)


@pytest.mark.alone
def test_many_numeric_credential_values_screen_in_linear_time():
    import time
    account, api = "account_" + "id", "api_" + "key"
    # Every value passes: account values under six digits, secret values under 12 characters.
    passing = f"{account} = 7\n{account} = 7.5\n{api} = 7\n{SK} = 7.25\n" * 5_000
    started = time.perf_counter()
    check_text(passing, source_path="src/settings.py")
    assert time.perf_counter() - started < 5
    # A qualifying literal late in the same file still refuses.
    refuses(passing + f"{account} = 12_345_678\n", "src/settings.py")
    refuses(passing + f"{account} = 12345678.0\n", "src/settings.py")
    refuses(passing + f"{api} = 123456789012\n", "src/settings.py")


@pytest.mark.alone
def test_many_literals_screen_in_linear_time():
    import time
    source = "x = 7\n" * 20_000 + 'y = f"{7}"\n' * 20_000
    started = time.perf_counter()
    screen_source(source, "src/cash.py", LISTED_42)
    assert time.perf_counter() - started < 5
