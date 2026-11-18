"""Credential labels the A8 corpus found missing: token kinds beside the access token, and the marks real
passwords hold inside an unquoted value. Values are put together at run time."""

import pytest

from finassist.errors import AssistantError
import base64
import hashlib
import hmac

from finassist.security import check_context_document, check_output_document, check_text

VALUE = "Qm4vT8" + "zR2kW6nB9x"
MARKED = "Qm4vT8" + "!zR2kW6%nB9x"


@pytest.mark.parametrize("label", ["AUTH_TOKEN", "refresh_token", "SESSION_TOKEN", "bearer_token", "oauth_token"])
@pytest.mark.parametrize("path,frame", [
    ("deploy/.env.production", "{label}={value}\n"),
    ("config/service.yaml", "service:\n  {label}: {value}\n"),
])
def test_a_token_label_with_a_literal_is_refused(label, path, frame):
    with pytest.raises(AssistantError) as refused:
        check_text(frame.format(label=label, value=VALUE), source_path=path)
    assert refused.value.code == "sensitive_content"


@pytest.mark.parametrize("path,frame", [
    ("deploy/.env.production", "DB_PASSWORD={value}\n"),
    ("config/database.yaml", "database:\n  password: {value}\n"),
])
def test_an_unquoted_password_with_marks_is_refused(path, frame):
    with pytest.raises(AssistantError):
        check_text(frame.format(value=MARKED), source_path=path)


@pytest.mark.parametrize("text", [
    "AUTH_TOKEN=${AUTH_TOKEN}\n",
    "service:\n  session_token: ${{ secrets.SESSION_TOKEN }}\n",
    "valid_token_count: 12\n",
    "id_token_issuer: accounts.example.com\n",
    "DB_PASSWORD=\n",
])
def test_what_names_no_literal_is_not_refused(text):
    check_text(text, source_path="config/service.yaml")


PLACEHOLDERS = ["YOUR_API_TOKEN_HERE", "your-api-key", "<your-api-key>", "insert_token_here", "replace-me-before-use",
                "changeme", "change_me_in_production", "placeholder-secret", "dummy_password_1",
                "example-secret-value", "redacted"]
# Near misses: a word that only begins like a placeholder, and real-looking values that happen to contain one.
STILL_REFUSED = ["my_secret_password_1234", "Yours3cretPassw0rd", "examples" + "Qm4vT8zR2kW6", "Qm4vT8zR2kW6_here_x",
                 "xxxxxxx" + "Qm4vT8zR2", "x" * 16]


@pytest.mark.parametrize("value", PLACEHOLDERS)
@pytest.mark.parametrize("path,frame", [
    ("src/app/settings.py", 'API_TOKEN = "{value}"\n'),
    ("config/service.yaml", "service:\n  api_token: {value}\n"),
    ("config/service.json", '{{"password": "{value}"}}\n'),
])
def test_a_placeholder_is_not_a_credential(value, path, frame):
    check_text(frame.format(value=value), source_path=path)


@pytest.mark.parametrize("value", STILL_REFUSED)
@pytest.mark.parametrize("path,frame", [
    ("src/app/settings.py", 'API_TOKEN = "{value}"\n'),
    ("config/service.yaml", "service:\n  api_token: {value}\n"),
])
def test_a_value_that_only_looks_like_a_placeholder_is_refused(value, path, frame):
    with pytest.raises(AssistantError):
        check_text(frame.format(value=value), source_path=path)


URL = "postgresql" + "://app:" + VALUE + "@db.internal:5432/app"


@pytest.mark.parametrize("path,frame", [
    ("tests/test_db.py", 'DATABASE_URL = "{url}"\n'),
    ("tests/fixtures/settings.yaml", "database:\n  url: {url}\n"),
])
def test_a_url_password_in_a_listed_test_path_is_a_placeholder(path, frame):
    # Like every label rule, the URL password is not applied where the configuration says logins are made up.
    with pytest.raises(AssistantError):
        check_text(frame.format(url=URL), source_path=path)
    check_text(frame.format(url=URL), source_path=path, placeholders=("tests/",))


def test_a_url_password_is_refused_in_prose_and_in_a_request():
    with pytest.raises(AssistantError) as refused:
        check_text("We connected with " + URL + " once.\n", source_path="docs/notes.md")
    assert refused.value.local_details["rule"] == "url_password"
    files = [{"path": "src/cash.py", "before": None, "after": "x = 1\n"}]
    with pytest.raises(AssistantError):
        check_context_document({"files": files, "note": "see " + URL})


# An opaque value with a placeholder's prefix or suffix is still a credential.
OPAQUE = "Qm4vT8" + "zR2kW6nB9x"


@pytest.mark.parametrize("value", ["dummy_" + OPAQUE, "example_" + OPAQUE, "YOUR_" + OPAQUE, OPAQUE + "_here"])
@pytest.mark.parametrize("path,frame", [
    ("src/app/settings.py", 'DB_PASSWORD = "{value}"\n'),
    ("config/service.yaml", "service:\n  password: {value}\n"),
    ("config/service.json", '{{"password": "{value}"}}\n'),
])
def test_a_placeholder_affix_does_not_exempt_an_opaque_value(value, path, frame):
    with pytest.raises(AssistantError):
        check_text(frame.format(value=value), source_path=path)


# A URL password is read as written; only a complete template is left alone.
@pytest.mark.parametrize("url", [
    "postgresql" + "://app:" + "Qm4vT8zR$2kW6nB9x" + "@db.internal/app",
    "postgresql" + "://app:" + "Qm4vT8zR%212kW6nB9x" + "@db.internal/app",
    "postgresql" + "://user%40example.invalid:" + VALUE + "@db.internal/app",
    "redis" + "://:" + VALUE + "@cache.internal:6379/0",
    "rediss" + "://:" + VALUE + "@cache.internal:6380/0",
])
@pytest.mark.parametrize("path,frame", [
    ("src/app/settings.py", 'DATABASE_URL = "{url}"\n'),
    ("docs/notes.md", "We connected with {url} once.\n"),
])
def test_a_url_password_with_marks_or_escapes_is_refused(url, path, frame):
    with pytest.raises(AssistantError):
        check_text(frame.format(url=url), source_path=path)
    files = [{"path": "src/cash.py", "before": None, "after": "x = 1\n"}]
    with pytest.raises(AssistantError):
        check_context_document({"files": files, "note": url})


@pytest.mark.parametrize("template", ["${DB_PASSWORD}", "$DB_PASSWORD", "%(db_password)s", "{db_password}",
                                      "{{ db_password }}", "<database-password>"])
def test_a_complete_template_password_is_left_alone(template):
    check_text("url: postgresql" + "://app:" + template + "@db.internal/app\n", source_path="config/db.yaml")
    check_text("url: redis" + "://:" + template + "@cache.internal:6379/0\n", source_path="config/cache.yaml")


@pytest.mark.parametrize("text", ["http" + "://:8080/path@other", "http" + "://host:8080/path@other",
                                  "ssh" + "://:22/repository@main", "file" + "://:memory:"])
def test_a_port_or_path_after_an_empty_user_name_is_no_password(text):
    check_text("We connected with " + text + " once.\n", source_path="docs/notes.md")


# A signed web token is found by its structure, however its JSON is spaced or however short it is.
def _token(header: bytes, payload: bytes) -> str:
    def part(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    signing = part(header) + "." + part(payload)
    signature = hmac.new(b"synthetic-" + b"signing-key", signing.encode(), hashlib.sha256).digest()
    return signing + "." + part(signature)


@pytest.mark.parametrize("header,payload", [
    (b'{"alg":"HS256","typ":"JWT"}', b'{"a":1}'),
    (b'{ "alg":"HS256","typ":"JWT"}', b'{"sub":"12345"}'),
    (b'{"alg":"HS256","typ":"JWT"}', b'{ "sub":"12345"}'),
    (b'{\n "alg": "HS256"\n}', b'{\n "sub": "12345"\n}'),
])
def test_a_signed_web_token_variant_is_refused(header, payload):
    token = _token(header, payload)
    for path, text in (("src/app.py", 'TOKEN = "%s"\n' % token), ("docs/notes.md", "Use %s once.\n" % token)):
        with pytest.raises(AssistantError) as refused:
            check_text(text, source_path=path)
        assert refused.value.local_details["rule"] == "signed_web_token"


# A placeholder that passed the source and request screens may be quoted back exactly.
def test_an_admitted_placeholder_can_be_quoted_back_exactly():
    text = 'DB_PASSWORD = "YOUR_API_TOKEN_HERE"\n'
    check_text(text, source_path="src/settings.py")
    files = [{"path": "src/settings.py", "before": None, "after": text}]
    check_context_document({"files": files, "note": "review"})
    check_output_document({"note": text}, files)  # an exact quote, ending where the source line ends
    with pytest.raises(AssistantError):  # a value the source never held is still refused
        check_output_document({"note": 'DB_PASSWORD = "' + OPAQUE + '"'}, files)


# Same-case letter runs and number runs are not placeholder words.
@pytest.mark.parametrize("value", ["dummy_qmvzrkwnbxhptjfs", "YOUR_QMVZRKWNBXHPTJFS", "qmvzrkwnbxhptjfs_here",
                                   "dummy_123_456_789_123", "my_secret_password", "your_password_1234"])
@pytest.mark.parametrize("path,frame", [
    ("src/app/settings.py", 'DB_PASSWORD = "{value}"\n'),
    ("config/service.yaml", "service:\n  password: {value}\n"),
    ("config/service.json", '{{"password": "{value}"}}\n'),
])
def test_only_placeholder_words_make_a_placeholder(value, path, frame):
    with pytest.raises(AssistantError):
        check_text(frame.format(value=value), source_path=path)


# Zero claims and white space before a brace are valid JSON, so still a token.
@pytest.mark.parametrize("header,payload", [
    (b'{"alg":"HS256","typ":"JWT"}', b"{}"),
    (b' {"alg":"HS256","typ":"JWT"}', b'{"sub":"12345"}'),
    (b'{"alg":"HS256","typ":"JWT"}', b' {"sub":"12345"}'),
    (b'\t{"alg":"HS256"}', b'\n{}'),
])
def test_a_signed_web_token_with_spaced_or_empty_json_is_refused(header, payload):
    token = _token(header, payload)
    for path, text in (("src/app.py", "value = '%s'\n" % token), ("docs/notes.md", "Use %s once.\n" % token)):
        with pytest.raises(AssistantError) as refused:
            check_text(text, source_path=path)
        assert refused.value.local_details["rule"] == "signed_web_token"
    files = [{"path": "src/cash.py", "before": None, "after": "x = 1\n"}]
    with pytest.raises(AssistantError):
        check_context_document({"files": files, "note": token})


@pytest.mark.parametrize("text", [
    "finassist.security.check_credentials_and_more_words",
    "www.example.com/a.b.c",
    "eyJhbGciOiJIUzI1NiJ9.not-json-at-all.c2lnbmF0dXJlc2lnbmF0dXJl",
    "e30.e30.c2lnbmF0dXJlc2lnbmF0dXJl",  # a header with no algorithm is not a signed token
])
def test_dotted_text_that_is_not_a_token_is_not_refused(text):
    check_text("note = '%s'\n" % text, source_path="docs/notes.md")


# A token whose JSON the decoder cannot settle within its limits is refused, on every Python.
_ALGORITHM = b'{"alg":"HS256","typ":"JWT"}'


@pytest.mark.parametrize("header,payload", [
    (_ALGORITHM, b'{"a":' + b"7" * 5000 + b"}"),  # past the default integer conversion limit
    (_ALGORITHM, b'{"a":' + b"[" * 1100 + b"0" + b"]" * 1100 + b"}"),  # past the 3.11 recursion limit
    (_ALGORITHM, b'{"a":' + b"[" * 65 + b"]" * 65 + b"}"),  # past the depth that is decoded
    (_ALGORITHM, b'{"a":1e999999,"b":-0.000e-99999}'),
    (_ALGORITHM, b'{"a":' + b"[" * 3000),  # unbalanced and deep: not decided, so refused
    (b'{"alg":"HS256","x":' + b"[" * 100 + b"]" * 100 + b"}", b'{"sub":"12345"}'),
])
def test_a_token_the_decoder_cannot_settle_is_refused(header, payload):
    token = _token(header, payload)
    for path, text in (("src/app.py", "value = '%s'\n" % token), ("docs/notes.md", "Use %s once.\n" % token)):
        with pytest.raises(AssistantError) as refused:
            check_text(text, source_path=path)
        assert refused.value.local_details["rule"] == "signed_web_token"
    files = [{"path": "src/cash.py", "before": None, "after": "x = 1\n"}]
    with pytest.raises(AssistantError):
        check_context_document({"files": files, "note": token})
    with pytest.raises(AssistantError):
        check_output_document({"note": token}, files)


def test_nesting_within_the_bound_is_decoded():
    shallow = _token(_ALGORITHM, b'{"a":' + b"[" * 63 + b"]" * 63 + b"}")
    with pytest.raises(AssistantError):
        check_text("Use %s once.\n" % shallow, source_path="docs/notes.md")
    # Brackets inside strings are not nesting, and a header without an algorithm is still not a token.
    quoted = _token(b'{"typ":"' + b"[" * 200 + b'"}', b"{}")
    check_text("note = '%s'\n" % quoted, source_path="docs/notes.md")


def test_the_depth_bound_separates_decoded_from_undecided():
    # Without an algorithm the header is no token once decoded, so only an undecided header is refused.
    def header(depth):
        return b'{"typ":' + b"[" * (depth - 1) + b"]" * (depth - 1) + b"}"

    check_text("Use %s once.\n" % _token(header(64), b"{}"), source_path="docs/notes.md")
    with pytest.raises(AssistantError) as refused:
        check_text("Use %s once.\n" % _token(header(65), b"{}"), source_path="docs/notes.md")
    assert refused.value.local_details["rule"] == "signed_web_token"
