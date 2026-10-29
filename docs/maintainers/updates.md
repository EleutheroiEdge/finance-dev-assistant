# Updates and configuration compatibility

Design note, 2026-10-29. This records how comparable developer tools handle updates and which choices finledgerpoli makes. Sources are listed at the end. Third-party pages are marked; verify version-specific details against the official docs.

## 1. What comparable tools do

| Tool | How users learn of an update | How they update | Config safety |
|---|---|---|---|
| **Claude Code** | Native install auto-updates in the background. Channel `latest` or `stable` (about a week old, skips releases with major regressions). Opt out with `DISABLE_AUTOUPDATER`. | `claude update`; `claude doctor` shows the last update attempt and whether auto-update is on. | User settings live outside the install. `minimumVersion` is a floor, so switching channel never downgrades. |
| **OpenClaw** | Background checks; a failed check is logged and retried later. | `openclaw update` detects the install method (npm, pnpm, Bun, git), stages the new version while the old one keeps serving, then verifies. Supports `--dry-run`, `--json`, `update status`, channels (beta, dev, extended-stable), `update repair`. | `openclaw doctor --fix` runs migrations after an update and keeps the original bytes. `--non-interactive` applies only safe migrations. It stops before rewriting a config that has retired keys and points to a "bridge" release. Rollback refuses when the old version can't read the newer database. |
| **Codex CLI** (third-party sources) | Async, non-blocking startup check against the registry. Off with `check_for_update_on_startup = false`. | `codex update` detects Homebrew or npm and runs the right command. `codex doctor` covers install and config problems. | Updating replaces the program only; config and credentials stay. |
| **GitHub CLI** | Checks at most once every 24 hours. The notice goes to stderr. Off with `GH_NO_UPDATE_NOTIFIER`. | Through the package manager. | Not applicable. |
| **npm update-notifier** (common library) | A cached check every 24 hours in a background process. Silent in CI. Off with `NO_UPDATE_NOTIFIER`. | Prints the exact command. | Not applicable. |
| **pip** | Self version check, cached in a local file. Off with `--disable-pip-version-check` or `PIP_DISABLE_PIP_VERSION_CHECK`. | `pip install -U pip` | Not applicable. |
| **Terraform (Checkpoint)** | Version check plus security bulletins, with an anonymous ID. `CHECKPOINT_DISABLE` turns it off. `disable_checkpoint_signature` keeps security alerts but drops the ID. | Package manager or download. | Strict state versioning. |
| **pre-commit** | None. | `pre-commit autoupdate` (hooks). | `migrate-config` rewrites old formats, and `autoupdate` calls it automatically. `minimum_pre_commit_version` is now checked before the rest of the config is parsed, so an old install says "upgrade" instead of a confusing parse error (fixed in 3.6.0). |
| **Ruff** | None. | Package manager. | Deprecated settings keep working and warn with the exact new key (`ignore` → `lint.ignore`) for several releases before they are removed. |

## 2. The industry pattern

1. **Separate the program from the user's data.** Every tool above keeps config and state outside the install, so an upgrade never edits them. finledgerpoli already does this.
2. **Check, don't install, by default.** CLIs that run inside other people's repos and CI (gh, npm tools, pip, Codex) notify; only consumer-style agents (Claude Code, OpenClaw) auto-install. Notifiers are cached, at most daily, non-blocking, print to stderr, are silent in CI and non-interactive shells, and have one documented off switch.
3. **One update command that knows how you installed it** (`claude update`, `codex update`, `openclaw update`). It prints or runs the right command for the install method, with `--dry-run` and `--json`.
4. **Doctor is the post-upgrade step.** It reports version, update status and config health, and applies only safe, reversible migrations without asking.
5. **Config evolves additively.** New keys are optional. Renamed keys warn for several releases with the exact replacement. Removal needs an explicit migration that shows a diff, keeps a backup and preserves original bytes.
6. **Minimum version, checked first.** A project can require a version (`minimumVersion`, `minimum_pre_commit_version`), and the check runs before parsing, so an outdated install gets "please upgrade to X" instead of an error.
7. **Downgrade is guarded.** A newer state or database schema is never opened by an older version; the tool says why and how to recover.
8. **Security notices are distinct from feature updates** (Terraform's bulletins). They can stay on when feature notices are off.

## 3. Where finledgerpoli stands (main c6a267e)

- Already done: config separated from the install; offline `finassist doctor`; `schema_version: 1`.
- Gaps:
  - no update signal and no upgrade docs;
  - unknown config options are a hard error that doesn't say "upgrade" (the pre-commit 3.6.0 bug);
  - no minimum version;
  - no deprecation or migration path;
  - the evidence store (SQLite) has no schema guard against downgrade;
  - no upgrade test across released versions.

## 4. Recommended design (finance-specific choices noted)

1. **`finassist update`** (`status`, `--dry-run`, `--json`). Detect pipx, uv tool or pip and print the exact command; run it only with `--yes`. No background auto-install, ever: finance teams need to choose when their tooling changes.
2. **Update notice, off until the user turns it on.** This keeps the offline promise. `update_check: off | notify` in user config (not project config), plus `FINASSIST_NO_UPDATE_CHECK`. When on, the check is:
   - at most daily and cached;
   - non-blocking;
   - printed to stderr;
   - always silent in CI or a non-interactive shell, or when the network is disallowed.
   It sends only a GET to the PyPI JSON API: no ID, no telemetry. `finassist doctor --check-updates` is a one-shot manual check. A later option could check yanked releases and security advisories even when feature notices are off.
3. **`min_version` in project config, checked before anything else is parsed.** An unknown option names its key and says to upgrade, and names the release that introduced it when known.
4. **Deprecation policy.** A renamed key keeps working and warns with the exact replacement for at least two minor releases. `finassist doctor` lists deprecated keys.
5. **Migration.** `finassist config migrate --dry-run` shows the diff. A real run writes a timestamped backup that keeps the original bytes. `doctor --fix` applies only safe, reversible migrations. Nothing migrates silently on load.
6. **Evidence store schema version.** Migrations only go forward, with a backup. An older version refuses a newer store with a clear message and does not change it.
7. **Upgrade test in CI:**
   - install each released version (0.3.1, 0.4.0) from PyPI;
   - run `init` and a demo;
   - upgrade to the candidate wheel;
   - assert the config is byte-identical, doctor passes and the evidence store verifies.
   Keep the old configs as golden fixtures.
8. **Every release note has an "Upgrading" section**, usually "no action needed".

## Sources

- Claude Code setup (official): https://code.claude.com/docs/en/setup
- Claude Code settings (official): https://code.claude.com/docs/zh-TW/settings
- Claude Code update guides (third party): https://wmedia.es/en/tips/claude-code-how-to-update , https://inventivehq.com/knowledge-base/claude/how-to-update-claude-code
- Claude Code issue on disable keys: https://github.com/anthropics/claude-code/issues/56723
- OpenClaw updating (official): https://docs.openclaw.ai/install/updating.md
- OpenClaw doctor (official): https://docs.openclaw.ai/gateway/doctor
- Codex CLI startup and update (third party): https://codex.danielvaughan.com/2026/05/12/codex-cli-startup-sequence-binary-to-first-model-call/ , https://inventivehq.com/knowledge-base/openai/how-to-update-codex-cli
- GitHub CLI environment (official): https://cli.github.com/manual/gh_help_environment
- update-notifier: https://github.com/lbevilacqua/update-notifier
- pip options: https://man.archlinux.org/man/extra/python-pip/pip-check.1.en
- Terraform commands and Checkpoint: https://docs.w3cub.com/terraform/commands/ , https://pkg.go.dev/github.com/hashicorp/go-checkpoint
- pre-commit: https://www.mankier.com/1/pre-commit-migrate-config , https://newreleases.io/project/pypi/pre-commit/release/1.0.0 , https://redirect.github.com/espressif/esp-idf/commit/09ba070b7e7a6ec9a7e7fcfcf5f3ef0d95752149
- Ruff 0.2.0 deprecations: https://astral.sh/blog/ruff-v0.2.0
