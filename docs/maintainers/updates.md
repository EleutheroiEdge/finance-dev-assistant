# Updates and configuration compatibility

Design note started 2026-10-29, primary-source comparisons refreshed 2026-10-30. This records selected update patterns and the contracts chosen for finledgerpoli.

## 1. Verified examples from comparable tools

Primary documentation checked 2026-10-30. These are selected documented
behaviors, not guarantees about every version or installation. Each design
input is our inference; no other tool's migration or security guarantees are
inherited by finledgerpoli.

| Tool | Documented behavior | Design input |
|---|---|---|
| **Claude Code** | Native/npm installs expose an update control and manual `claude update`. `DISABLE_AUTOUPDATER` suppresses background checks. `minimumVersion` constrains updates; separate managed version-range settings control startup. [Setup](https://code.claude.com/docs/en/setup) | Distinguish update policy from a reader's startup/configuration floor. |
| **OpenClaw** | `openclaw update --dry-run` previews and `update status --json` inspects state. Recovery retains artifacts when rollback is incompatible with migrated databases. [Updating](https://docs.openclaw.ai/install/updating) | Preview changes and preserve uncertain/recovery state; historical updaters cannot acquire future guards retroactively. |
| **Codex CLI** | Official examples update through npm or Homebrew; the configuration reference documents `check_for_update_on_startup`. [Upgrade commands](https://developers.openai.com/cookbook/examples/codex/using_goals_in_codex), [configuration](https://learn.chatgpt.com/docs/config-file/config-reference) | Preserve package-manager ownership and provide an explicit check switch. |
| **GitHub CLI** | Checks every 24 hours, prints an available-version notice on stderr and honors `GH_NO_UPDATE_NOTIFIER`. [Environment](https://cli.github.com/manual/gh_help_environment) | Cache a low-noise notice and provide an environment off switch. |
| **pip** | Periodic self checks can be disabled with `PIP_DISABLE_PIP_VERSION_CHECK`; `pip install --upgrade` replaces a selected package. [Options](https://pip.pypa.io/en/stable/cli/pip/), [install](https://pip.pypa.io/en/stable/cli/pip_install/) | Separate checking from explicit installation. |
| **Terraform** | `disable_checkpoint` disables upgrade/security checks; `disable_checkpoint_signature` disables their anonymous de-duplication identifier. [CLI configuration](https://developer.hashicorp.com/terraform/cli/config/config-file) | Our check sends no identifier and remains off by default. |
| **pre-commit** | Documents `minimum_pre_commit_version` and a separate `migrate-config` command for the old list format. [Configuration and commands](https://pre-commit.com/) | Name a minimum reader and expose explicit migration. |
| **Ruff** | The v0.2.0 migration describes moving lint settings to `tool.ruff.lint`, with warnings identifying replacement locations. [Migration](https://astral.sh/blog/ruff-v0.2.0) | Warnings should name the replacement rather than merely rejecting an old key. |

## 2. Design choices inferred from these examples

Keep the installed program separate from project files. Preview installation,
then run only the owning manager after explicit confirmation. Keep optional
public checks separate from model requests and package installation: no source,
credentials, identifiers or telemetry belong in an update query.

Use a private daily reservation/cache for automatic checks, and keep interactive
notices on stderr. Suppress them in CI, redirected shells and network-disabled
projects. A pending attempt remains pending instead of triggering an automatic
retry. A fresh manual check is a separate explicit action.

Make new configuration additive, check reader floors early and preserve renamed
options for a tested window. Preview migrations, keep original bytes and verify
the result. A historical binary without a guard cannot be made safe by adding a
check to a later release; use the versioned-file barrier described in
[compatibility](compatibility.md). These are finledgerpoli's chosen contracts,
not a claim that every compared tool implements the same behavior.

## 3. Verified baseline before implementation

The main baseline inspected for issue #27 had offline doctor with no update
status, schema version 1, no upgrade section, unknown-option errors without an
upgrade hint and no evidence downgrade guard. That observation describes the
pre-implementation baseline. The 0.5.0 development implementation, tests and
current operational limits are documented in [Upgrading](../upgrading.md).

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

## Sources and scope

Primary links appear next to each supported comparison above. This note uses
only the narrow documented behaviors stated there. Detailed channel timing,
installer detection and migration internals are version-dependent; re-check the
upstream source before adopting them. The implementation follows issue #27 and
its explicit historical-downgrade ruling where they refine this design.
