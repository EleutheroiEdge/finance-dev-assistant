"""Python-aware screening (#61): tokenize for figures, the AST for credentials.

Synthetic values only. Secret-shaped values are assembled at runtime so this file
contains no credential-shaped literal of its own.
"""
import hashlib
import json
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
    ("6_729_102.50", "6729102.50"), ("67291025e-1", "6729102.5"), ("6729102.50j", "6729102.50"),
    ("0x1F", "31"), ("0b101", "5"), ("0o17", "15"),
    ("1e999999999", None), ("9" * 400, None), ("0x" + "F" * 200, None),
])
def test_number_text_reads_exact_values_within_bounds(token, expected):
    assert number_text(token) == expected


def test_unterminated_source_never_yields_a_partial_token_stream():
    assert python_tokens(UNTOKENIZABLE) is None
    assert python_tokens("x = (1,\n") is None
    assert python_tokens("x = 1\r\ny = 2\r") is not None
