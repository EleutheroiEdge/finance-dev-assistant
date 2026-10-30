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

Guarded readers refuse a newer unsupported schema without changing it. Old
0.3.x/0.4.0 binaries cannot discover the new filename and see only stale,
pre-migration evidence. They do not gain a guard retroactively. A full rollback
must restore the preserved backup and select the older package. Keep the new
versioned file as a recovery artifact outside the active store directory when
returning a guarded reader to the original file; otherwise it selects the new
file again. Writes made on the two branches are not merged automatically.

Read the [compatibility policy](maintainers/compatibility.md) for deprecation
windows, concurrent-writer limits and the installed historical-wheel tests.
