"""Synthetic numeric grammar cases; provider integration is tested separately."""

import pytest

from finassist.errors import AssistantError
from finassist.forbidden_tokens import normalize_numeric_token


@pytest.mark.parametrize(("raw", "expected"), [
    ("6729102.50", "6729102.5"), ("$6,729,102.500", "6729102.5"),
    ("6 729 102.50", "6729102.5"), ("6\u00a0729\u00a0102.50", "6729102.5"),
    ("6\u202f729\u202f102.50", "6729102.5"), ("６７２９１０２.５０", "6729102.5"),
    ("٦٧٢٩١٠٢.٥٠", "6729102.5"), ("6729100", "6729100"),
    ("00012.000", "12"), ("-0.000", "0"), ("+0", "0"), ("(0.0)", "0"),
    ("-£12.50", "-12.5"), ("£-12.50", "-12.5"), ("($12.50)", "-12.5"),
    ("1.250e3", "1250"), ("125e-3", "0.125"), ("1e-4", "0.0001"),
    (" 12.50 ", "12.5"), ("1,000.01", "1000.01"),
])
def test_numeric_normalization(raw, expected):
    assert normalize_numeric_token(raw) == expected


@pytest.mark.parametrize("raw", [
    "", " ", "1,23", "1 23", "1,234 567", "1\u00a0234 567",
    "12,50", "1.2.3", "nan", "Infinity", "--12", "(+12)", "(-12)",
    "1e999", "1e129", "1e-129", "1" * 129, "1" * 257, "12\n", "12\t",
    "$$12", "12USD", "0x10", None, 12,
])
def test_invalid_numeric_token_is_not_disclosed(raw):
    with pytest.raises(AssistantError) as error:
        normalize_numeric_token(raw)
    assert str(error.value) == "forbidden_token_invalid"


def test_integer_zeros_and_sign_are_significant():
    assert normalize_numeric_token("6729100") != normalize_numeric_token("67291")
    assert normalize_numeric_token("-12") != normalize_numeric_token("12")


def test_external_tokens_union_hashes_without_plaintext_repr(tmp_path):
    import hashlib
    from finassist.forbidden_tokens import load_token_snapshot
    root = tmp_path / "repo"
    root.mkdir()
    tokens = tmp_path / "numbers.txt"
    tokens.write_bytes(b"$6,729,102.500\r\n12.00\r\n")
    extra = hashlib.sha256(b"89").hexdigest()
    snapshot = load_token_snapshot({"forbidden_token_file": str(tokens), "forbidden_token_hashes": [extra]}, (root,))
    assert snapshot.hashes == frozenset(hashlib.sha256(s.encode()).hexdigest() for s in ("6729102.5", "12", "89"))
    assert snapshot.line_count == 2
    assert "6729102" not in repr(snapshot) and str(tokens) not in repr(snapshot)
    assert extra not in repr(snapshot)


@pytest.mark.parametrize("data", [b"", b"\n", b"12\n\n", b"secret-value", b"12\r13", b"\xff", b"1\n" * 1025, b"1" * 131073])
def test_malformed_token_files_fail_closed_without_content(tmp_path, data):
    from finassist.forbidden_tokens import load_token_snapshot
    path = tmp_path / "numbers.txt"
    path.write_bytes(data)
    with pytest.raises(AssistantError) as error:
        load_token_snapshot({"forbidden_token_file": str(path)}, ())
    assert str(error.value) == "forbidden_token_file_invalid"


def test_no_configuration_or_hash_only_needs_no_file(tmp_path, monkeypatch):
    from finassist.forbidden_tokens import load_token_snapshot
    monkeypatch.setattr("finassist.forbidden_tokens._read_token_file", lambda *_: pytest.fail("file access"))
    assert not load_token_snapshot({}, (tmp_path,)).hashes
    assert load_token_snapshot({"forbidden_token_hashes": ["a" * 64]}, ()).hashes == frozenset(["a" * 64])


@pytest.mark.parametrize("values", [None, "a" * 64, ["A" * 64], ["a" * 63], [12], ["a" * 64] * 1025])
def test_invalid_hashes_are_refused(values):
    from finassist.forbidden_tokens import load_token_snapshot
    with pytest.raises(AssistantError, match="^forbidden_token_hashes_invalid$"):
        load_token_snapshot({"forbidden_token_hashes": values}, ())


def test_repository_relative_missing_directory_and_git_paths_refused(tmp_path):
    from finassist.forbidden_tokens import load_token_snapshot
    repo = tmp_path / "repo"
    repo.mkdir()
    tokens = repo / "numbers.txt"
    tokens.write_text("12")
    admin = tmp_path / ".git"
    admin.mkdir()
    hidden = admin / "numbers.txt"
    hidden.write_text("12")
    for candidate in (tokens, "numbers.txt", tmp_path / "missing.txt", tmp_path, hidden):
        with pytest.raises(AssistantError, match="^forbidden_token_file_invalid$"):
            load_token_snapshot({"forbidden_token_file": str(candidate)}, (repo,))


def test_linked_and_hardlinked_files_refused(tmp_path):
    import os
    from finassist.forbidden_tokens import load_token_snapshot
    path = tmp_path / "numbers.txt"
    path.write_text("12")
    linked = tmp_path / "link.txt"
    try:
        linked.symlink_to(path)
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(AssistantError, match="^forbidden_token_file_invalid$"):
        load_token_snapshot({"forbidden_token_file": str(linked)}, ())
    linked.unlink()
    os.link(path, linked)
    with pytest.raises(AssistantError, match="^forbidden_token_file_invalid$"):
        load_token_snapshot({"forbidden_token_file": str(linked)}, ())


def test_replacement_during_read_is_refused(tmp_path, monkeypatch):
    import os
    from finassist.forbidden_tokens import load_token_snapshot
    path = tmp_path / "numbers.txt"
    path.write_text("12")
    original = os.read
    changed = False

    def replace_during_read(fd, amount):
        nonlocal changed
        result = original(fd, amount)
        if not changed:
            replacement = tmp_path / "replacement.txt"
            replacement.write_text("89")
            os.replace(replacement, path)
            changed = True
        return result

    monkeypatch.setattr("finassist.forbidden_tokens.os.read", replace_during_read)
    with pytest.raises(AssistantError, match="^forbidden_token_file_invalid$"):
        load_token_snapshot({"forbidden_token_file": str(path)}, ())


def test_all_excluded_roots_are_enforced(tmp_path):
    from finassist.forbidden_tokens import load_token_snapshot
    source, policy, admin = (tmp_path / name for name in ("source", "policy", "admin"))
    for root in (source, policy, admin):
        root.mkdir()
        path = root / "numbers.txt"
        path.write_text("12")
        with pytest.raises(AssistantError, match="^forbidden_token_file_invalid$"):
            load_token_snapshot({"forbidden_token_file": str(path)}, (source, policy, admin))


def test_fifo_is_refused_before_open(tmp_path, monkeypatch):
    import os
    from finassist.forbidden_tokens import load_token_snapshot
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO unavailable")
    path = tmp_path / "numbers.txt"
    os.mkfifo(path)
    monkeypatch.setattr("finassist.forbidden_tokens.os.open", lambda *_: pytest.fail("opened FIFO"))
    with pytest.raises(AssistantError, match="^forbidden_token_file_invalid$"):
        load_token_snapshot({"forbidden_token_file": str(path)}, ())


@pytest.fixture
def synthetic_snapshot():
    import hashlib
    from finassist.forbidden_tokens import TokenSnapshot
    return TokenSnapshot(frozenset([hashlib.sha256(b"6729102.5").hexdigest()]))


@pytest.mark.parametrize("text", [
    "value = 6729102.50", "# $6,729,102.500", 'value = "6 729 102.50"',
    "fixture: ６７２９１０２.５０", "6729102.50 2", "6.7291025e6",
    "# src/6729102.50.py", "value6729102.50suffix",
    "1 6 729 102.50", "6 729 102.50 2",
    "total = approx(6729102.50)", "# Q3 balance (6,729,102.50)",
    "loss = -6729102.50", "round(6729102.50, 2)", "values = [6729102.50,2]",
    "SYNTHETIC,6729102.50,100", "SYNTHETIC,100,6729102.50",
    "Rs.6729102.50", "# see ledger.6729102.50.csv",
])
def test_content_candidates_refused(text, synthetic_snapshot):
    from finassist.forbidden_tokens import screen_text
    with pytest.raises(AssistantError, match="^forbidden_token_present$"):
        screen_text(text, synthetic_snapshot)


@pytest.mark.parametrize("text", ["6729102.51", "16729102.50", "6729102.501", "unrelated = 12"])
def test_distinct_values_pass(text, synthetic_snapshot):
    from finassist.forbidden_tokens import screen_text
    screen_text(text, synthetic_snapshot)


def test_typed_path_exemption_does_not_exempt_source_spelling(synthetic_snapshot):
    from finassist.forbidden_tokens import screen_packet
    packet = {"files": [{"path": "src/6729102.50.py", "before": "value = 12", "after": "value = 13"}]}
    screen_packet(packet, "review carefully", synthetic_snapshot)
    packet["files"][0]["before"] = "# src/6729102.50.py"
    with pytest.raises(AssistantError, match="^forbidden_token_present$"):
        screen_packet(packet, "review carefully", synthetic_snapshot)


def test_changed_list_invalidates_guard_before_dispatch(tmp_path):
    from finassist.forbidden_tokens import TokenGuard, load_token_snapshot
    path = tmp_path / "numbers.txt"
    path.write_text("12")
    rules = {"forbidden_token_file": str(path)}
    guard = TokenGuard(rules, (), load_token_snapshot(rules, ()))
    packet = {"files": [{"before": "value = 89", "after": None}]}
    guard.recheck(packet, "review")
    path.write_text("89")
    with pytest.raises(AssistantError, match="^forbidden_token_configuration_changed$"):
        guard.recheck(packet, "review")



def test_stat_and_fstat_ctime_semantics_can_differ(tmp_path, monkeypatch):
    import os
    from types import SimpleNamespace
    from finassist.forbidden_tokens import load_token_snapshot
    path = tmp_path / "numbers.txt"
    path.write_bytes(b"12\r\n34\r\n")
    original = os.fstat

    def descriptor_stat(fd):
        st = original(fd)
        values = {key: getattr(st, key) for key in ("st_dev", "st_ino", "st_mode", "st_nlink",
                                                   "st_size", "st_mtime_ns", "st_ctime_ns")}
        values["st_ctime_ns"] += 1
        return SimpleNamespace(**values)

    monkeypatch.setattr("finassist.forbidden_tokens.os.fstat", descriptor_stat)
    snapshot = load_token_snapshot({"forbidden_token_file": str(path)}, ())
    assert snapshot.line_count == 2


def test_token_file_uses_exact_binary_bytes(tmp_path):
    import hashlib
    from finassist.forbidden_tokens import load_token_snapshot
    path = tmp_path / "numbers.txt"
    raw = b"12\r\n34\r\n"
    path.write_bytes(raw)
    snapshot = load_token_snapshot({"forbidden_token_file": str(path)}, ())
    assert snapshot.file_digest == hashlib.sha256(raw).hexdigest()
    path.write_bytes(b"12\n\x1a89")
    with pytest.raises(AssistantError, match="^forbidden_token_file_invalid$"):
        load_token_snapshot({"forbidden_token_file": str(path)}, ())


@pytest.mark.parametrize("listed", ["6729102.5", "-6729102.5"])
@pytest.mark.parametrize("candidate", ["6729102.50", "-6729102.50", "(6729102.50)"])
def test_hash_only_tokens_compare_both_magnitudes(listed, candidate):
    import hashlib
    from finassist.forbidden_tokens import TokenSnapshot, screen_text
    snapshot = TokenSnapshot(frozenset([hashlib.sha256(listed.encode()).hexdigest()]))
    with pytest.raises(AssistantError, match="^forbidden_token_present$"):
        screen_text(candidate, snapshot)


def test_plain_pass_fails_closed_on_grouped_short_figure():
    import hashlib
    from finassist.forbidden_tokens import TokenSnapshot, screen_text
    snapshot = TokenSnapshot(frozenset([hashlib.sha256(b"234").hexdigest()]))
    with pytest.raises(AssistantError, match="^forbidden_token_present$"):
        screen_text("amount = 1,234", snapshot)
