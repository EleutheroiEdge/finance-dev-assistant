# Configuration compatibility for finledgerpoli

Keep configuration changes additive within a schema version. New options are
optional and their defaults preserve the previous behavior. Existing option
names and meanings do not change within that schema. No configuration migration
or evidence migration happens silently during load or installation.

`min_version` is an optional stable `X.Y.Z` reader floor. After JSON syntax is
decoded, the floor is checked before schema hints, other option validation or
profile-file reads. An incompatible reader reports the required version and an
upgrade hint. Unknown options name the option and suggest an upgrade; a known
introduction release is included when available. Values are never echoed in
these errors. Historical releases without this feature still report
`unknown_config_option` for `min_version`; no retroactive guard is claimed.

Register a real rename in `DEPRECATED_OPTIONS` only after review. The old name
must retain the same meaning, warn with its exact replacement and keep working
for at least two minor releases. The registry enforces that minimum window.
Do not invent production renames just to test the framework. Doctor lists the
deprecated options observed while loading the configuration.

`finassist config migrate --path FILE --dry-run` reports the exact unified diff
in its JSON `diff` field and writes nothing. Without `--dry-run`, it validates
the migration again, preserves the original bytes in a timestamped backup and
then applies supported key renames. A no-op keeps all original whitespace and
creates no backup. Ambiguous aliases, future version floors, content-screening
failures and stale plans refuse the write. Nothing lowers a version floor.

Backups and replacement use private local files. Windows inherits directory
ACLs; POSIX modes do not replace that boundary. As with existing configuration
saves, the final atomic replacement is not an atomic compare-and-swap against
other same-user writers. Coordinate concurrent edits; a backup alone does not
authorize overwriting a newer file or automatic rollback.

Evidence-store migrations and historical downgrade behavior follow the explicit
versioned-file barrier: preserve the original file and write a new versioned
file, so historical unguarded readers continue to see stale-but-intact original
evidence. Guarded readers refuse stores newer than they support without changing
their bytes. Restoring the preserved backup is a separate explicit rollback.

## Evidence-store versions and explicit migration

`finassist evidence verify --state-dir PRIVATE_STATE` reads and verifies the
selected store without creating an audit file or updating evidence. It checks
SQLite integrity, stored hashes, decision references and revision lineage;
these checks do not establish the truth of analyst observations. Existing
legacy schema headers remain unchanged during ordinary reads.

Use `finassist evidence migrate --state-dir PRIVATE_STATE --dry-run` to preview
the source hash, target schema and destination without writes. Without
`--dry-run`, the migration verifies the source and copies it to a new versioned
filename such as `evidence.v2.sqlite`. The original `evidence.sqlite` remains
the byte-identical backup. Existing destinations are never overwritten.
Guarded readers choose the latest migrated sibling; if its declared version
exceeds their support, they refuse rather than falling back to the old file.
Close concurrent writers first: active WAL, shared-memory or rollback-journal
sidecars are refused. A busy or corrupted store is not repaired silently.

`doctor --fix` explicitly preflights both configuration and evidence before any
write, then applies only these reversible migrations. It uses `--config` (or a
local `finassist.json` if present) and `--state-dir`. A newer floor/schema is
refused; no field is lowered to make it readable. Multiple local file changes
are not one atomic transaction. If a later operation fails, retain the existing
backup and versioned artifacts and inspect them before retrying or rolling back.

Downgrading below 0.5.0 after migration exposes only the pre-migration evidence
in the original filename. Historical binaries do not acquire the new reader
guard retroactively. To roll back fully, restore the preserved backup and
select the older package; keep the newer versioned file as a separate recovery
artifact. A later guarded reader will select that versioned file while it is
still in the active directory. Divergent post-downgrade writes are not merged
automatically. Newer stores and original backups must not be deleted by an
automatic upgrade or rollback command.

## Installed historical-wheel regression

The existing native CI wheel check also runs `scripts/upgrade_smoke.py` with
the built candidate wheel. It installs the actual public 0.3.1 and 0.4.0 wheels
in separate temporary environments using hash-locked runtime dependencies.
`examples/upgrade-fixtures/wheels.json` records their fixed PyPI download URLs,
sizes and SHA-256 hashes. Downloads and cached bytes must match those pins;
there is no moving "latest" dependency or fallback release. These hashes are
byte-integrity checks, not a claim of cryptographic provenance verification.

Each environment generates configuration with the old `init` and compares it
with the corresponding byte-exact golden JSON fixture, then runs the old demo
and seeds fictional evidence. Installing the candidate must preserve those
configuration bytes; doctor and evidence verification must succeed. Explicit
migration must leave the original store intact and verify the new file. After
adding a new revision, reinstalling the historical wheel must read the old
observation without changing either file. The candidate is reinstalled to test
a simulated older guarded reader and the new version-floor error before other
configuration validation. Published historical readers retain their original
`unknown_config_option` behavior. No live provider or user data is involved.

To run only this check locally after building a wheel:

```sh
python scripts/upgrade_smoke.py dist/finledgerpoli-0.5.0-py3-none-any.whl
```

The check executes installed packages from isolated temporary projects with
temporary homes and a minimal environment. An optional `--cache DIRECTORY`
reuses historical downloads only after checking their reviewed hashes again.
