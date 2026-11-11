"""Known credential formats: each is refused wherever it stands, and its near misses are not.

Every token here is made up and is put together at run time, so that this file holds none.
"""
import pytest

from finassist.errors import AssistantError
from finassist.security import check_context_document, check_output_document, check_text


def run(length: int) -> str:
    """Letters and digits of that length, with no meaning."""
    return ("aB3dE6gH9" * length)[:length]


FORMATS = {
    "stripe secret": ("stripe_live_key", "sk_" + "live_" + run(24)),
    "stripe restricted": ("stripe_live_key", "rk_" + "live_" + run(32)),
    "slack bot": ("slack_token", "xox" + "b-" + "123456789012-" + run(24)),
    "slack user": ("slack_token", "xox" + "p-" + run(40)),
    "slack app": ("slack_token", "xapp" + "-1-" + run(30)),
    "google": ("google_api_key", "AI" + "za" + run(35)),
    "npm": ("npm_token", "npm" + "_" + run(36)),
    "pypi": ("pypi_token", "pypi-" + "AgEIcHlwaS5vcmc" + run(60)),
    "gitlab": ("gitlab_token", "gl" + "pat-" + run(20)),
    "sendgrid": ("sendgrid_key", "SG" + "." + run(22) + "." + run(43)),
    "azure storage": ("azure_storage_key", "Account" + "Key=" + run(86) + "=="),
    # Codex P113-1: the field name is read in any letter case, as the service's own parser reads it.
    "azure storage, lower case": ("azure_storage_key", "account" + "key=" + run(86) + "=="),
    "azure storage, upper case": ("azure_storage_key", "ACCOUNT" + "KEY=" + run(86) + "=="),
    "azure storage, mixed case": ("azure_storage_key", "aCcOuNt" + "KeY=" + run(86) + "=="),
    "encrypted key block": ("private_key_block", "-----BEGIN " + "ENCRYPTED PRIVATE KEY-----"),
    "pgp key block": ("private_key_block", "-----BEGIN PGP " + "PRIVATE KEY BLOCK-----"),
}
NEAR = {
    "stripe test key": "sk_" + "test_" + run(24),
    "stripe publishable key": "pk_" + "live_" + run(24),
    "stripe, one short": "sk_" + "live_" + run(23),
    "slack, too short": "xox" + "b-" + run(12),
    "slack, another letter": "xox" + "z-" + run(40),
    "google, one short": "AI" + "za" + run(34),
    "google, one long": "AI" + "za" + run(36),
    "npm, one short": "npm" + "_" + run(35),
    "npm, one long": "npm" + "_" + run(37),
    "npm script name": "npm" + "_config_user_agent_and_more_words_here",
    "pypi, another issuer": "pypi-" + run(70),
    "gitlab, one short": "gl" + "pat-" + run(19),
    "sendgrid, short tail": "SG" + "." + run(22) + "." + run(42),
    "azure, short key": "Account" + "Key=" + run(79),
    "azure, short key in lower case": "account" + "key=" + run(79),
    "azure, another field": "Account" + "Name=" + run(86),
    "public key block": "-----BEGIN " + "PUBLIC KEY-----",
    "pgp public key block": "-----BEGIN PGP " + "PUBLIC KEY BLOCK-----",
    "pgp message": "-----BEGIN PGP " + "MESSAGE-----",
}
each_format = pytest.mark.parametrize("rule,token", FORMATS.values(), ids=FORMATS.keys())
PLACES = {
    "a Python string": ("src/settings.py", 'NOTE = "one"\nvalue = "%s"\n', 2),
    "a Python comment": ("src/settings.py", "x = 1\ny = 2\n# see %s\n", 3),
    "a settings file": ("deploy/values.yml", "name: demo\nsetting: %s\n", 2),
    "prose": ("docs/notes.md", "A note.\n\nWe used %s once.\n", 3),
    "a script": ("web/client.ts", 'const one = 1;\nconst value = "%s";\n', 2),
}


@each_format
@pytest.mark.parametrize("path,frame,line", PLACES.values(), ids=PLACES.keys())
def test_a_known_format_is_refused_wherever_it_stands(rule, token, path, frame, line):
    for source_path, placeholders in ((path, ()), (None, ()), ("tests/" + path, ("tests/",))):
        with pytest.raises(AssistantError, match="^sensitive_content$") as refusal:
            check_text(frame % token, source_path=source_path, placeholders=placeholders)
        assert refusal.value.local_details["rule"] == rule
        if source_path is not None:
            assert refusal.value.local_details["lines"] == [line]


@pytest.mark.parametrize("text", NEAR.values(), ids=NEAR.keys())
@pytest.mark.parametrize("path,frame,_line", PLACES.values(), ids=PLACES.keys())
def test_what_is_only_near_a_format_is_not_refused(text, path, frame, _line):
    check_text(frame % text, source_path=path)
    check_text(frame % text)


@each_format
def test_a_known_format_is_refused_in_a_request_and_in_a_reply(rule, token):
    files = [{"path": "src/cash.py", "before": None, "after": "x = 1\n"}]
    with pytest.raises(AssistantError, match="^sensitive_content$"):
        check_context_document({"files": files, "note": "see " + token})
    with pytest.raises(AssistantError, match="^sensitive_content$"):
        check_context_document({"files": [{"path": "docs/notes.md", "before": None, "after": "We used %s once.\n" % token}]})
    for reply in ({"summary": "The change adds " + token}, {"summary": "x", "findings": [{"claim": "`%s`" % token}]}):
        with pytest.raises(AssistantError, match="^sensitive_content$"):
            check_output_document(reply, files)


def test_no_token_stands_in_this_file():
    """The file is published. Its tokens exist only once the pieces above are joined."""
    source = open(__file__, encoding="utf-8").read()
    for _rule, token in FORMATS.values():
        assert token not in source
    check_text(source, source_path="tests/test_credential_formats.py")
