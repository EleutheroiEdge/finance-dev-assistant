# Upgrading finledgerpoli

Choose when to replace the installed program. No installation step rewrites
project configuration or evidence, and nothing migrates silently on load.

Use the package manager that owns the installation:

| Installation | Upgrade command |
|---|---|
| pipx | `pipx upgrade finledgerpoli` |
| uv tool | `uv tool upgrade finledgerpoli` |
| pip in the active environment | `python -m pip install --upgrade finledgerpoli` |

Run `finassist doctor` afterwards. Package upgrades and explicit local data
migrations are separate operations. You can keep using old configuration without
reformatting it. New options remain optional and default to the earlier behavior.

## Status, preview and explicit install

`finassist update status --json` reports the installed and last checked latest
versions, timestamp/stale flag, installation method and exact upgrade command
and argv/environment. Managed homes are bound to the installation running the
command, so a custom pipx or uv directory does not upgrade an unrelated default
environment. Windows command previews use PowerShell syntax.
A missing or failed check says `not checked`, with a null latest version.
Status and `finassist update --dry-run` make no request, run no installer and
create no audit state. JSON is also the default output.

`finassist update --yes` explicitly runs that package manager once, records
metadata in the command audit and never migrates project data. The result reports
the installer exit status; restart the command to observe the installed version.
Installer output is not copied into logs or JSON. A timeout can leave a partial
installation and an open audit run: inspect and reconcile before another attempt.
There is no automatic retry, fallback, privilege elevation or background install.

Omit project `--config`: the update command works independently of configuration
that may require a newer reader. Manager marker filenames identify pipx/uv tool
environments without reading their potentially private saved records. Unrecognized or
custom-named managed environments, missing tools, batch shims and editable source
installations refuse execution. Update an editable installation through its
reviewed source workflow. Package managers execute under your account; this is
not an installer sandbox or a substitute for reviewing a release.

## Optional update checks

Doctor and dashboard health reports read cached metadata only. To request one
public check, allow network use in reviewed project configuration and run
`finassist --config finassist.json doctor --check-updates`. A network-disabled
project returns `not checked` with `network-disabled`. Manual checks can bypass
the daily cache but never enable a provider, approve a model request or install
anything. `doctor --fix --check-updates` refuses so local fixes remain offline.

Automatic notices are **off** by default. Create a user-level `settings.json`
with `{"update_check":"notify"}` to opt in, or `off` to disable them. This is
separate from project `finassist.json` and cannot enable automatic installs.

| Platform | User settings file |
|---|---|
| Linux | `$XDG_CONFIG_HOME/finledgerpoli/settings.json`, default `~/.config/finledgerpoli/settings.json` |
| macOS | `~/Library/Application Support/finledgerpoli/settings.json` |
| Windows | `%APPDATA%\finledgerpoli\settings.json` |

With `notify`, interactive `doctor`, `demo` and `init` commands may start a
one-shot check when project network use is allowed. A private cache reserves the
attempt atomically before launch, at most once per 24 hours across processes.
Pending and failed attempts count; there is no automatic retry. The worker makes
one GET to `https://pypi.org/pypi/finledgerpoli/json` with short HTTP timeouts and
a response-size limit. No identifiers, source, credentials or telemetry are sent;
proxies, redirects and retries are disabled. Failure means `not checked`. HTTP
deadlines do not replace host DNS/runtime controls.

The parent never waits for HTTP. A later eligible invocation prints the cached
notice on stderr, at most once per UTC day. Notices/checks stay silent in CI,
non-interactive or redirected shells, network-disabled projects and sensitive
workflow/gate operations. The dashboard starts no check. Cache/launch failures
do not fail the user's command.

The presence of `FINASSIST_NO_UPDATE_CHECK`, even empty, disables automatic and
manual checks. It does not affect a separately explicit package-manager upgrade.
The cache lives under `$XDG_CACHE_HOME/finledgerpoli` (default
`~/.cache/finledgerpoli`) on Linux, `~/Library/Caches/finledgerpoli` on macOS, or
`%LOCALAPPDATA%\finledgerpoli` on Windows. Windows inherits directory ACLs; use
a private user directory.

## Team pinning and rollback

For a team, install an exact reviewed release, for example
`pipx install finledgerpoli==0.4.0`. Record the version in team setup instructions;
use the corresponding `uv tool install finledgerpoli==0.4.0` or
`python -m pip install finledgerpoli==0.4.0` for those installation methods.

To replace an existing pipx installation with a chosen older release, use
`pipx install finledgerpoli==0.4.0 --force`. The uv equivalent is
`uv tool install finledgerpoli==0.4.0 --force`; for pip, install the exact pin
with the Python interpreter for the intended environment. Reinstalling a package
does not restore state or authorize an automatic rollback of data.

## Version floors and migrations

A project may set `min_version` to a stable `X.Y.Z`. Versions starting with
0.5.0 check that floor before validating other options and explain how to
upgrade. Published 0.3.x/0.4.0 readers do not have this check; they report
`unknown_config_option` for the new field. An unknown option in a guarded
reader includes its name and an upgrade hint without echoing its value.

Preview a supported configuration rename with
`finassist config migrate --path finassist.json --dry-run`. Apply explicitly by
omitting `--dry-run`; the original bytes go to a timestamped backup first.
A no-op preserves the original file exactly. Doctor lists deprecated keys
and their replacements. No production key has been renamed in this release.

For evidence, first close writers, then run
`finassist evidence verify --state-dir .finassist` and preview
`finassist evidence migrate --state-dir .finassist --dry-run`.
Omitting `--dry-run` writes a new versioned file such as `evidence.v2.sqlite`;
the original `evidence.sqlite` remains its byte-identical backup.
`finassist doctor --fix --state-dir .finassist` explicitly preflights and applies
only these safe reversible migrations, using `--config` or local `finassist.json`.

The closed-writer/sidecar check applies to migration, including its dry run.
Ordinary evidence opens and verification allow SQLite's normal hot-journal
rollback recovery and wait up to 15 seconds for a conflicting writer. Recovery
discards an interrupted transaction; it does not migrate the evidence schema or
approve observations. Do not delete journal, WAL or shared-memory files by hand.
Recover through a normal open, then close writers before retrying migration.

Existing empty or partial evidence stores are refused with
`evidence_store_schema_invalid` rather than initialized, unlike 0.4.0. Preserve
the file and inspect a recovery copy; this release does not repair its layout.

Guarded readers refuse a newer unsupported schema without changing it. Old
0.3.x/0.4.0 binaries cannot discover the new filename and see only stale,
pre-migration evidence. They do not gain a guard retroactively. A full rollback
must restore the preserved backup and select the older package. Keep the new
versioned file as a recovery artifact outside the active store directory when
returning a guarded reader to the original file; otherwise it selects the new
file again. Writes made on the two branches are not merged automatically.

Read the [compatibility policy](maintainers/compatibility.md) for deprecation
windows, concurrent-writer limits and the installed historical-wheel tests.
