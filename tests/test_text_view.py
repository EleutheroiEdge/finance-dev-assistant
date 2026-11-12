"""Tests for the human view of a doctor report.

The five literal reports below stand for the three report shapes, and each
expected screen is the same text as the mock screens in
docs/design/doctor-text-view.md. Nothing here calls the product's builders.
"""

from finassist.text_view import render

READY_RANGE = {'schema_version': 1,
 'mode': 'config-preflight',
 'status': 'ready',
 'base': 'main',
 'head': 'feature/add-cash-check',
 'config': {'source': 'file',
            'config_hash': 'c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3'},
 'blockers': [],
 'warnings': [],
 'paths': [{'path': 'src/finance/cash.py', 'status': 'included'},
           {'path': 'tests/test_cash.py', 'status': 'included'}],
 'coverage_complete': True,
 'packet': {'bytes': 41230,
            'limit': 240000,
            'packet_hash': 'abababababababababababababababababababababababababababababababab'},
 'request': {'bytes': 45120, 'reserved_usd': '0.0413', 'prior_spend_checked': False},
 'provider': {'provider': 'openai',
              'model_configured': True,
              'network_enabled': True,
              'key_variable': 'OPENAI_API_KEY',
              'key_variable_set': True,
              'prices_configured': True},
 'network_used': False,
 'key_value_read': False,
 'ledger_opened': False,
 'next_step': {'commands': [['finassist',
                             '--config',
                             'finassist.json',
                             'plan',
                             '--repo',
                             '.',
                             '--base',
                             'main',
                             '--head',
                             'feature/add-cash-check',
                             '--output',
                             '<new packet file>'],
                            ['finassist',
                             '--config',
                             'finassist.json',
                             'review',
                             '--packet',
                             '<packet file>',
                             '--approve-packet',
                             '<packet_hash shown by plan, after you inspect the packet>',
                             '--allow-network',
                             '--output',
                             '<new review file>']]}}

BLOCKED_FILE = {'schema_version': 1,
 'mode': 'config-preflight',
 'status': 'blocked',
 'base': 'main',
 'head': 'feature/quarterly-metrics',
 'config': {'source': 'file',
            'config_hash': 'c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3'},
 'blockers': [{'code': 'file_limit_exceeded',
               'count': 1,
               'paths': ['data/metrics.csv'],
               'hint': 'Raise `max_file_bytes` (up to 2,000,000; `fixture_max_file_bytes` for gate '
                       "fixtures) or keep the file out of the range. The error's `limit` shows the "
                       'cap.'}],
 'warnings': [],
 'paths': [{'path': 'src/finance/metrics.py', 'status': 'included'},
           {'path': 'data/metrics.csv',
            'status': 'refused',
            'code': 'file_limit_exceeded',
            'bytes': 360000,
            'limit': 60000}],
 'coverage_complete': False,
 'packet': None,
 'request': None,
 'provider': {'provider': 'openai',
              'model_configured': True,
              'network_enabled': True,
              'key_variable': 'OPENAI_API_KEY',
              'key_variable_set': True,
              'prices_configured': True},
 'remedies': [{'code': 'file_limit_exceeded',
               'options': [{'document': 'configuration',
                            'effect': 'leaves_files_out',
                            'changes': [{'setting': 'unreviewable_paths',
                                         'value': 'skip-and-report'}]},
                           {'document': 'configuration',
                            'effect': 'sends_more',
                            'changes': [{'setting': 'max_file_bytes', 'at_least': 360000}]}]}],
 'network_used': False,
 'key_value_read': False,
 'ledger_opened': False,
 'next_step': 'Fix every blocker listed, then run this preflight again.'}

BLOCKED_THREE = {'schema_version': 1,
 'mode': 'config-preflight',
 'status': 'blocked',
 'base': 'main',
 'head': 'feature/rebalance',
 'config': {'source': 'defaults',
            'config_hash': 'c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3'},
 'blockers': [{'code': 'private_or_binary_path',
               'count': 1,
               'paths': ['secrets/ledger.csv'],
               'hint': 'Keep such files out of the range, or set `private_paths` to '
                       '`skip-and-report` to withhold them unread.'},
              {'code': 'run_budget_exceeded',
               'reserved_usd': '0.42',
               'limit_usd': '0.25',
               'hint': 'Review a smaller range, lower `max_output_tokens`, or raise `max_run_usd` '
                       'in the reviewed configuration or gate policy after checking the prices.'},
              {'code': 'provider_key_missing',
               'variable': 'FINASSIST_API_KEY',
               'hint': 'Set the variable named by `api_key_env` in this shell. Never put the key '
                       'itself in a config or policy file.'}],
 'warnings': [],
 'paths': [{'path': 'src/finance/rebalance.py', 'status': 'included'},
           {'path': 'secrets/ledger.csv', 'status': 'refused', 'code': 'private_or_binary_path'}],
 'coverage_complete': False,
 'packet': None,
 'request': {'bytes': 45120, 'reserved_usd': '0.42', 'prior_spend_checked': False},
 'provider': {'provider': 'openai',
              'model_configured': True,
              'network_enabled': True,
              'key_variable': 'FINASSIST_API_KEY',
              'key_variable_set': False,
              'prices_configured': True},
 'remedies': [{'code': 'private_or_binary_path',
               'options': [{'document': 'configuration',
                            'effect': 'leaves_files_out',
                            'changes': [{'setting': 'private_paths', 'value': 'skip-and-report'}]},
                           {'document': 'configuration',
                            'effect': 'sends_more',
                            'changes': [{'setting': 'text_suffixes', 'add': ['.csv']}]}]},
              {'code': 'run_budget_exceeded',
               'options': [{'document': 'configuration',
                            'effect': 'spends_more',
                            'changes': [{'setting': 'max_run_usd', 'at_least': 0.42}]}]}],
 'network_used': False,
 'key_value_read': False,
 'ledger_opened': False,
 'next_step': 'Fix every blocker listed, then run this preflight again.'}

HEALTHY = {'version': '0.12.0',
 'python': '3.13.1',
 'platform': 'Linux',
 'provider': 'offline',
 'model_configured': False,
 'network_enabled': False,
 'key_present': None,
 'docker_binary_present': False,
 'podman_binary_present': False,
 'container_daemon_checked': False,
 'recipes': [],
 'profile': 'general',
 'deprecated_config_options': [],
 'config_source': 'file',
 'config_warnings': [],
 'updates': {'latest': None, 'checked_at': None, 'stale': False},
 'private_state_protection': 'private',
 'next_step': 'inspect a plan packet before enabling any provider or running a recipe'}

READY_GATE = {'schema_version': 1,
 'mode': 'gate-preflight',
 'status': 'ready',
 'base': 'main',
 'head': 'feature/rebalance',
 'policy': {'path': 'gate-policy.json',
            'source': 'base',
            'sha256': '9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f',
            'pin': 'matches'},
 'blockers': [],
 'warnings': [{'code': 'private_paths_withheld',
               'count': 2,
               'hint': 'Nothing to fix if that is intended: the rest of the range is reviewed and '
                       'the report counts what was withheld. Set `private_paths` to `refuse` to '
                       'require complete coverage.'},
              {'code': 'unreviewable_paths_left_out',
               'count': 1,
               'hint': 'Nothing to fix if that is intended: the rest of the range is reviewed, and '
                       'the packet names each file left out with its reason. Set '
                       '`unreviewable_paths` to `refuse` to require complete coverage.'}],
 'paths': [{'path': 'src/finance/rebalance.py', 'status': 'included'},
           {'path': 'docs/portfolio.md', 'status': 'included'},
           {'path': 'data/holdings.csv', 'status': 'withheld', 'reason': 'private'},
           {'path': 'data/prices.csv', 'status': 'withheld', 'reason': 'private'},
           {'path': 'build/output.txt', 'status': 'omitted', 'reason': 'non_text_blob'}],
 'coverage_complete': False,
 'request': {'bytes': 45120,
             'limit': 120000,
             'reserved_usd': '0.0413',
             'prior_spend_checked': False},
 'provider': {'provider': 'openai',
              'key_variable': 'OPENAI_API_KEY',
              'key_variable_set': True,
              'allowed_host': 'api.openai.com',
              'prices_configured': True},
 'network_used': False,
 'key_value_read': False,
 'ledger_opened': False,
 'next_step': {'command': ['finassist',
                           'gate',
                           'run',
                           '--repo',
                           '.',
                           '--base',
                           'main',
                           '--head',
                           'feature/rebalance',
                           '--policy',
                           'gate-policy.json',
                           '--policy-sha256',
                           '9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f',
                           '--state-dir',
                           '<private state directory>',
                           '--output',
                           '<new report file>']}}

EXPECTED_READY_RANGE = """finassist doctor - configuration preflight
Verdict: READY
Range: main..feature/add-cash-check; 2 included; coverage complete
Provider: openai; model configured; network enabled; prices set
Key variable OPENAI_API_KEY: set
Packet: 41,230 of 240,000 bytes
Request: 45,120 bytes; reserves $0.0413
This run used no network, read no key value and opened no ledger.

Next steps:
  finassist --config finassist.json plan --repo . --base main --head
      feature/add-cash-check --output <new packet file>
  finassist --config finassist.json review --packet <packet file>
      --approve-packet <packet_hash shown by plan, after you inspect the packet>
      --allow-network --output <new review file>
"""

EXPECTED_BLOCKED_FILE = """finassist doctor - configuration preflight
Verdict: BLOCKED - 1 blocker
Range: main..feature/quarterly-metrics; 1 included; 1 refused; coverage
  incomplete
Provider: openai; model configured; network enabled; prices set
Key variable OPENAI_API_KEY: set
This run used no network, read no key value and opened no ledger.

Blockers
1. file_limit_exceeded
  1 file: data/metrics.csv
  Fix: Raise `max_file_bytes` (up to 2,000,000; `fixture_max_file_bytes` for
    gate fixtures) or keep the file out of the range. The error's `limit` shows
    the cap.
  Remedies:
  a) In the configuration, set unreviewable_paths to "skip-and-report".
     Effect: files are left out, so coverage is incomplete.
  b) In the configuration, set max_file_bytes to at least 360,000.
     Effect: more is sent to the provider.

Next step: Fix every blocker listed, then run this preflight again.
"""

EXPECTED_BLOCKED_THREE = """finassist doctor - configuration preflight
Verdict: BLOCKED - 3 blockers
Range: main..feature/rebalance; 1 included; 1 refused; coverage incomplete
Provider: openai; model configured; network enabled; prices set
Key variable FINASSIST_API_KEY: not set
Request: 45,120 bytes; reserves $0.42
This run used no network, read no key value and opened no ledger.

Blockers
1. private_or_binary_path
  1 file: secrets/ledger.csv
  Fix: Keep such files out of the range, or set `private_paths` to
    `skip-and-report` to withhold them unread.
  Remedies:
  a) In the configuration, set private_paths to "skip-and-report".
     Effect: files are left out, so coverage is incomplete.
  b) In the configuration, add ".csv" to text_suffixes.
     Effect: more is sent to the provider.

2. run_budget_exceeded
  reserves $0.42; limit $0.25
  Fix: Review a smaller range, lower `max_output_tokens`, or raise `max_run_usd`
    in the reviewed configuration or gate policy after checking the prices.
  Remedies:
  a) In the configuration, set max_run_usd to at least $0.42.
     Effect: a larger spend is allowed.

3. provider_key_missing
  key variable FINASSIST_API_KEY is not set
  Fix: Set the variable named by `api_key_env` in this shell. Never put the key
    itself in a config or policy file.

Next step: Fix every blocker listed, then run this preflight again.
"""

EXPECTED_HEALTHY = """finassist doctor - installation health
Status: healthy

finassist 0.12.0 on Python 3.13.1 (Linux)
Provider: offline; no model configured; network disabled
Provider key: no key variable configured
Configuration: file; profile: general; recipes: none
Containers: no docker or podman binary found
Updates: not checked

Next step: inspect a plan packet before enabling any provider or running a
  recipe
"""

EXPECTED_READY_GATE = """finassist doctor - gate preflight
Verdict: READY
Range: main..feature/rebalance; 2 included; 2 withheld; 1 left out; coverage
  incomplete
Policy: gate-policy.json; from base; sha256 9f9f9f9...9f9f9f; pin matches
Provider: openai; prices set; allowed host api.openai.com
Key variable OPENAI_API_KEY: set
Request: 45,120 of 120,000 bytes; reserves $0.0413
This run used no network, read no key value and opened no ledger.

Warnings
1. private_paths_withheld
  2 files
  Fix: Nothing to fix if that is intended: the rest of the range is reviewed and
    the report counts what was withheld. Set `private_paths` to `refuse` to
    require complete coverage.
2. unreviewable_paths_left_out
  1 file
  Fix: Nothing to fix if that is intended: the rest of the range is reviewed,
    and the packet names each file left out with its reason. Set
    `unreviewable_paths` to `refuse` to require complete coverage.

Next step:
  finassist gate run --repo . --base main --head feature/rebalance --policy
      gate-policy.json --policy-sha256
      9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f
      --state-dir <private state directory> --output <new report file>
"""

ALL_REPORTS = (READY_RANGE, BLOCKED_FILE, BLOCKED_THREE, HEALTHY, READY_GATE)


def test_ready_range_renders_as_designed():
    assert render(READY_RANGE) == EXPECTED_READY_RANGE


def test_blocked_range_with_remedies_renders_as_designed():
    assert render(BLOCKED_FILE) == EXPECTED_BLOCKED_FILE


def test_three_blockers_render_as_designed():
    assert render(BLOCKED_THREE) == EXPECTED_BLOCKED_THREE


def test_healthy_installation_renders_as_designed():
    assert render(HEALTHY) == EXPECTED_HEALTHY


def test_ready_gate_with_warnings_renders_as_designed():
    assert render(READY_GATE) == EXPECTED_READY_GATE


def test_no_line_exceeds_the_width():
    for report in ALL_REPORTS:
        for width in (60, 80, 100):
            for line in render(report, width=width).splitlines():
                assert len(line) <= width


def test_no_escape_sequences_without_color():
    for report in ALL_REPORTS:
        assert "\x1b" not in render(report)


def test_color_only_when_asked():
    assert "\x1b[" in render(READY_RANGE, color=True)


def test_missing_and_unknown_fields_never_raise():
    render({})
    render(None)
    render({"mode": "config-preflight"})
    render({"mode": "gate-preflight", "blockers": [{"code": None}], "warnings": "nope"})
    render({"mode": "never-heard-of-it", "whatever": object()})
    render({"remedies": [{"code": "x", "options": "nope"}, "nope"]})


def test_unknown_fields_are_ignored():
    out = render({"version": "1.0", "totally_unknown": {"nested": [1, 2]}})
    assert "totally_unknown" not in out
    assert "nested" not in out


def test_a_key_value_or_file_content_can_never_appear():
    report = dict(READY_RANGE)
    report["api_key_value"] = "sk-live-secret-value"
    report["provider"] = {**report["provider"], "key_value": "sk-live-secret-value"}
    report["paths"] = [{"path": "src/finance/cash.py", "status": "included",
                        "content": "SECRET FILE BODY"}]
    report["blockers"] = [{"code": "file_limit_exceeded", "hint": "see the guide",
                           "content": "SECRET FILE BODY"}]
    out = render(report)
    assert "sk-live-secret-value" not in out
    assert "SECRET FILE BODY" not in out


def test_commits_are_shown_by_their_first_twelve_characters():
    report = {"mode": "config-preflight", "status": "ready", "base": "a" * 40, "head": "b" * 40, "blockers": []}
    assert "Range: aaaaaaaaaaaa..bbbbbbbbbbbb" in render(report)
    named = {"mode": "config-preflight", "status": "ready", "base": "main", "head": "feature/x", "blockers": []}
    assert "Range: main..feature/x" in render(named)


def test_the_key_line_follows_key_state_and_an_older_report_still_renders():
    def line(provider):
        report = {"mode": "gate-preflight", "status": "ready", "blockers": [], "provider": provider}
        return [text for text in render(report).splitlines() if text.startswith("Key variable")]

    assert line({"provider": "google", "key_variable": "K", "key_variable_set": True, "key_state": "empty"}) == [
        "Key variable K: set but empty"]
    assert line({"provider": "google", "key_variable": "K", "key_variable_set": False, "key_state": "missing"}) == [
        "Key variable K: not set"]
    assert line({"provider": "google", "key_variable": "K", "key_variable_set": True}) == ["Key variable K: set"]
    blocked = {"mode": "gate-preflight", "status": "blocked",
               "blockers": [{"code": "provider_key_empty", "variable": "K", "hint": "Set it."}]}
    assert "key variable K is set but empty" in render(blocked)


def test_a_remedy_names_where_its_setting_is_from_the_pointer():
    report = {"mode": "gate-preflight", "status": "blocked",
              "blockers": [{"code": "gate_request_bytes_exceeded", "bytes": 900, "limit": 500, "hint": "Raise it."}],
              "remedies": [{"code": "gate_request_bytes_exceeded", "options": [
                  {"document": "gate policy", "effect": "sends_more", "changes": [
                      {"setting": "max_request_bytes", "at_least": 900, "pointer": "/model_review/max_request_bytes"}]}]}]}
    text = render(report)
    assert "In the gate policy, set model_review.max_request_bytes to at least 900." in text
    top = {"mode": "config-preflight", "status": "blocked",
           "blockers": [{"code": "file_limit_exceeded", "count": 1, "paths": ["a.py"], "hint": "Raise it."}],
           "remedies": [{"code": "file_limit_exceeded", "options": [
               {"document": "configuration", "effect": "leaves_files_out", "changes": [
                   {"setting": "unreviewable_paths", "value": "skip-and-report", "pointer": "/unreviewable_paths"}]}]}]}
    assert 'In the configuration, set unreviewable_paths to "skip-and-report".' in render(top)


def test_real_doctor_reports_render_within_the_width(tmp_path):
    """The renderer on reports the product itself writes: a healthy installation and a blocked range."""
    import json
    import os
    import subprocess
    import sys

    from conftest import command

    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "ledger.py").write_text("def total(rows):\n    return sum(rows)\n", encoding="utf-8", newline="\n")
    command(tmp_path, "init", "-q", "-b", "main", str(repo))
    command(repo, "config", "user.email", "view@example.invalid")
    command(repo, "config", "user.name", "view")
    command(repo, "add", "-A")
    command(repo, "commit", "-q", "-m", "base")
    base = command(repo, "rev-parse", "HEAD")
    (repo / "src" / "big.py").write_text("x = 1\n" * 40000, encoding="utf-8", newline="\n")
    (repo / "src" / "ledger.py").write_text("def total(rows):\n    return sum(r for r in rows)\n", encoding="utf-8",
                                            newline="\n")
    command(repo, "add", "-A")
    command(repo, "commit", "-q", "-m", "change")
    head = command(repo, "rev-parse", "HEAD")
    environment = {**os.environ, "FINASSIST_NO_UPDATE_CHECK": "1"}
    reports = []
    for arguments in (["doctor"], ["doctor", "--repo", str(repo), "--base", base, "--head", head]):
        done = subprocess.run([sys.executable, "-m", "finassist", *arguments], cwd=repo, env=environment,
                              capture_output=True, text=True, check=False)
        reports.append(json.loads(done.stdout.splitlines()[-1]))
    for report in reports:
        for width in (60, 80, 100):
            text = render(report, width=width)
            assert max(len(line) for line in text.splitlines()) <= width
            assert "\x1b" not in text
    blocked = render(reports[1])
    assert "file_limit_exceeded" in blocked and base[:12] in blocked and base not in blocked


def test_health_view_shows_the_environment_blockers_and_warnings():
    warnings = [
        {"code": "provider_proxy_not_used", "variables": ["HTTPS_PROXY"], "hint": "Unset it."},
        {"code": "doctor_directory_unusable", "path_role": "user_cache", "hint": "Make it writable."},
        {"code": "provider_key_host_mismatch", "variable": "EXAMPLE_KEY", "host": "api.example.invalid",
         "hint": "Use one host."},
    ]
    report = {"version": "0.0.0", "python": "3.13", "platform": "linux", "config_warnings": [],
              "next_step": "Inspect a packet next.",
              "environment": {"blockers": [{"code": "git_executable_missing", "hint": "Install Git."}],
                              "warnings": warnings}}
    text = render(report)
    assert "Status: BLOCKED - 1 blocker" in text and "healthy" not in text
    assert "1. git_executable_missing" in text and "Fix: Install Git." in text
    assert "variables: HTTPS_PROXY" in text and "the user_cache folder" in text
    assert "key variable EXAMPLE_KEY; configured for api.example.invalid" in text and "is not set" not in text
    # A blocked installation is not told to go on to its next step.
    assert "Inspect a packet next." not in text and "fix every blocker listed" in text
    warned = render({**report, "environment": {"blockers": [], "warnings": warnings[:1]}})
    assert "Status: 1 warning" in warned and "Inspect a packet next." in warned
    assert render({**report, "environment": {}}).count("healthy") == 1
