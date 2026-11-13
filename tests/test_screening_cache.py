"""A text screened once per command under the same rules: the same outcomes, fresh refusals, no shared state."""

import contextvars
import threading

import pytest

import finassist.security as security
from finassist.errors import AssistantError
from finassist.security import check_credentials, screening_cache

# Synthetic texts only, each screened as the file named beside it. The values are joined at run time, so this file
# holds no credential-shaped literal of its own: the tool reviews its own tree.
_VALUE = "Zq7xP2mN" + "8vL4kR9tW3yB6cD1"
_FIXTURE = "fixture-" + "password-1234567890"
CASES = [
    ("src/app.py", "def total(rows):\n    return sum(rows)\n"),
    ("src/app.py", "API_TOKEN = '" + _VALUE + "'\n"),
    ("src/app.py", "token = os.environ['SERVICE_TOKEN']\n"),
    ("src/app.py", "def broken(:\n    pass\n"),
    ("config/app.yaml", "pass" + "word: " + _VALUE + "\n"),
    ("docs/notes.md", "Nothing to see here.\n"),
    ("src/client.ts", "const sec" + "ret = process.env.CLIENT_SECRET;\n"),
    ("tests/test_login.py", "PASS" + "WORD = '" + _FIXTURE + "'\n"),
]


def outcome(text, path, **rules):
    try:
        check_credentials(text, source_path=path, **rules)
    except AssistantError as exc:
        return exc.code, dict(exc.public_details)
    return None


@pytest.mark.parametrize("rules", [{}, {"placeholders": ("tests/",)}, {"extra_patterns": ("fixture-",)}])
def test_cached_outcomes_equal_uncached_outcomes(rules):
    plain = [outcome(text, path, **rules) for path, text in CASES]
    with screening_cache():
        first = [outcome(text, path, **rules) for path, text in CASES]
        again = [outcome(text, path, **rules) for path, text in CASES]
    assert first == plain and again == plain
    assert any(result is not None for result in plain) and any(result is None for result in plain)


def test_a_remembered_refusal_is_a_fresh_error_each_time():
    path, text = CASES[4]  # The YAML password: refused.
    with screening_cache():
        with pytest.raises(AssistantError) as first:
            check_credentials(text, source_path=path)
        first.value.local_details["added_by_a_caller"] = "first file"
        with pytest.raises(AssistantError) as second:
            check_credentials(text, source_path=path)
    assert second.value is not first.value and second.value.code == first.value.code
    assert "added_by_a_caller" not in second.value.local_details


def test_each_text_is_screened_once_per_set_of_rules(monkeypatch):
    calls = []
    real = security._screen_credentials

    def counting(*arguments):
        calls.append(arguments[2])
        return real(*arguments)

    monkeypatch.setattr(security, "_screen_credentials", counting)
    path, text = CASES[0]
    with screening_cache():
        check_credentials(text, source_path=path)
        check_credentials(text, source_path=path)
        assert len(calls) == 1
        check_credentials(text, source_path="docs/other.md")  # Another path is another rule set.
        check_credentials(text, source_path=path, placeholders=("src/",))
        assert len(calls) == 3
    # Outside a command nothing is remembered.
    check_credentials(text, source_path=path)
    check_credentials(text, source_path=path)
    assert len(calls) == 5


def test_nothing_is_kept_after_the_command():
    with screening_cache():
        check_credentials("x = 1\n", source_path="a.py")
        assert security._SCREENED.get().outcomes
    assert security._SCREENED.get() is None


def _counting(monkeypatch) -> list:
    calls = []
    real = security._screen_credentials

    def counting(*arguments):
        calls.append(arguments[2])
        return real(*arguments)

    monkeypatch.setattr(security, "_screen_credentials", counting)
    return calls


def test_a_context_copied_inside_the_command_does_not_outlive_it(monkeypatch):
    calls = _counting(monkeypatch)
    path, text = CASES[0]
    refused_path, refused = CASES[4]
    with screening_cache():
        check_credentials(text, source_path=path)
        copied = contextvars.copy_context()
        copied.run(check_credentials, text, source_path=path)
        assert len(calls) == 1  # inside the command the copy shares what was remembered
    for _ in range(2):
        copied.run(check_credentials, text, source_path=path)
        with pytest.raises(AssistantError):
            copied.run(check_credentials, refused, source_path=refused_path)
    assert len(calls) == 5  # after it, the copy screens every time
    scope = copied.run(security._SCREENED.get)
    assert scope.open is False and scope.outcomes == {}


def test_a_thread_started_inside_the_command_screens_again_after_it(monkeypatch):
    calls = _counting(monkeypatch)
    path, text = CASES[0]
    ended = threading.Event()
    seen = []

    def later():
        ended.wait(10)
        check_credentials(text, source_path=path)
        check_credentials(text, source_path=path)
        seen.append(security._SCREENED.get().outcomes)

    with screening_cache():
        check_credentials(text, source_path=path)
        worker = threading.Thread(target=contextvars.copy_context().run, args=(later,))
        worker.start()
    ended.set()
    worker.join(10)
    assert not worker.is_alive()
    assert len(calls) == 3 and seen == [{}]
