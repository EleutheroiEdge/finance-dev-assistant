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
sidecars are refused during migration, including its dry run. Ordinary opens and
verification retain SQLite's 15-second busy timeout and normal hot-journal
rollback recovery. This recovers transaction state without migrating the schema
or approving observations. Do not delete sidecars manually. Existing empty or
partial stores are refused rather than having their layout initialized or
repaired, a deliberate change from historical 0.4.0 initialization behavior.

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
the built candidate wheel. It installs each public wheel that
`examples/upgrade-fixtures/wheels.json` lists, now 0.3.1, 0.4.0, 0.9.0 and
0.10.0, in separate temporary environments using hash-locked runtime
dependencies. The manifest records their fixed PyPI download URLs, sizes and
SHA-256 hashes, in release order. Downloads and cached bytes must match those
pins; there is no moving "latest" dependency or fallback release. A download is
written whole into the cache, never through a link, and every install names
the `finledgerpoli` distribution and passes the pinned hash to pip, so a file
changed after it was verified, or one whose metadata names another
distribution, is refused.
These hashes are byte-integrity checks, not a claim of cryptographic provenance
verification.

Each environment generates configuration with the old `init` and compares it
with the corresponding byte-exact golden JSON fixture, then runs the old demo
and seeds fictional evidence. Installing the candidate must preserve those
configuration bytes, pass `pip check`, report a canonical version no older than
the newest pinned one (a pre-release of that version is older), and accept the
same configuration with `min_version` set to the old version; doctor, the demo and evidence verification must succeed. The manifest pins the schema of each version's store and the
version-floor code its reader answers, so the candidate never decides either. A
store an older version wrote at schema 0 (0.3.1 and 0.4.0) is migrated
explicitly: the original must stay intact and the new file must verify. A store
already at the current schema (0.9.0 and 0.10.0) needs no migration, and a real
migration must write nothing. Either way the candidate must read the upgraded
store's observation, then its own new revision. Reinstalled, an older
historical wheel must still read the old observation, and a reader of the
current schema the candidate's revision, without changing any file. The
candidate is reinstalled to test a simulated guarded reader one schema behind,
and the version-floor error before other configuration validation: 0.3.1 and
0.4.0 answer the floor with `unknown_config_option`, 0.9.0 and 0.10.0 with
`minimum_version_required`, as pinned.

A version listed with a gate policy is also checked on the gate route: 0.9.0
and 0.10.0, with the example policy they published
(`gate-policy-0.10.0.json`). On a synthetic repository, `doctor` runs that
policy as published, and the same policy with a private figure file, each
pinned by its bytes, under the historical wheel and then under the candidate.
The verdicts must be the same, and no policy or figure file may change, so a
pin set under the old version stays valid. A clean change is ready, and one that
adds the listed figure is refused with `forbidden_token_present`. No live
provider or user data is involved.

Two limits. Each environment holds the candidate's locked runtime dependencies
(`requirements-action.lock`), and the historical wheels run with them, so a
dependency change that breaks an old version's own code shows here as a failure
to look into, not as a user's upgrade breaking. And a historical reader that
guards its evidence schema (0.9.0 and 0.10.0 do, as the manifest's
`schema_guard` records) behind the candidate's would stop the check with a
message until its expected downgrade is written down; today the candidate's
schema is theirs.

To run only this check locally after building a wheel:

```sh
python scripts/upgrade_smoke.py dist/finledgerpoli-<version>-py3-none-any.whl
```

`<version>` is the version you built. It must be no older than the newest version the manifest pins, and the
wheel's name must carry the version it reports.

The check executes installed packages from isolated temporary projects with
temporary homes and a minimal environment. An optional `--cache DIRECTORY`
reuses historical downloads only after checking their reviewed hashes again.
