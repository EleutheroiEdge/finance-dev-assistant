# Changelog

All notable changes to finledgerpoli are documented here, following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## 0.5.0 - 2026-10-30

- Add an explicitly opted-in model-review gate with pinned base policy bytes,
  exact request approval, mandatory source screening, retained budget state,
  advisory PASS/FAIL/BLOCKED reports, shared CLI/Action core and generic examples.
  Existing offline and v1 checks defaults remain unchanged. Synthetic transports
  exercise this feature; live providers and project-wide hosted state are not supplied.

- Add optional early configuration version floors, safe unknown-option upgrade
  hints, tested deprecation windows and explicit configuration migration previews
  with byte-exact backups. Ordinary configuration loads preserve original files.
- Version evidence stores, verify their integrity read-only and copy forward
  migrations to a new versioned filename while preserving the original backup.
  Guarded readers refuse newer unsupported stores without changes; explicit
  doctor fixes preflight reversible local migrations without network calls.
- Test upgrades from the hash-pinned public 0.3.1 and 0.4.0 wheels in isolated
  environments, retaining their original configuration as golden fixtures.
- Inspect installation/update status offline, preview exact package-manager
  commands and run them only with explicit confirmation. Add separately opted-in
  daily cached PyPI notices, a network-gated manual doctor check, and cached
  dashboard update status without browser install actions or external requests.

- Allow 20 minutes in existing Windows Python CI jobs for native tests,
  clean-wheel validation and historical upgrades. Other CI jobs retain
  15-minute limits; the matrix and permissions are unchanged.

### Fixed

- Keep strict SQLite sidecar refusal in explicit evidence migrations. Ordinary
  evidence opens and verification recover hot journals and wait for conflicting
  writers while preserving unsupported-schema refusal.

### Upgrading

No action needed for existing configuration or evidence. Package upgrades never
edit them, and data migrations are separate explicit commands. After an explicit
evidence migration, downgrading below 0.5.0 sees only pre-migration evidence in
the preserved original file. Restore that backup for a full rollback and retain
the new versioned file separately; post-downgrade writes are not merged.
Historical releases do not acquire the newer schema or `min_version` guards.

## 0.4.0 - 2026-10-29

### Added

- Run isolated PR checks under a hash-pinned base policy with explicit fork/branch/scope/resource rules, failing closed on missing review or unfinished state; add a composite GitHub Action with reduced summaries and hash-locked trusted-source bootstrap.
- Exercise the installed CLI and full trusted-source Action bootstrap with passing synthetic financial checks and a seeded cash defect that must block, using the existing hosted OCI smoke job.
- Inspect workflow audit timelines through verified read-only snapshots, bounded metadata pages and recorded dependency/recovery explanations without loading configuration or executing actions.
- Resolve pinned local workflow/profile/check/policy packs into inspectable configuration, templates and provenance, preserving restrictive base policies and existing plan formats.
- Execute approved workflow checks with audit-backed checkpoints, dependency ordering, process-held locks and verified artifact reuse; require explicit reconciliation/retry after uncertain outcomes.
- Expose durable run inspection and cancellation, block readiness on unfinished workflows, and exercise pause/resume from installed wheels with synthetic checks.
- Add offline versioned workflow plans and preflight checks binding project methodology, check dependencies, source packets and configuration hashes.
- Let `verify-gate --workflow-plan` require extra audited financial check evidence, with named missing obligations; export a synthetic cash template and bundled workflow-plans guide.

### Changed

- Include the GitHub Action wrapper and its hash-locked dependencies in source distributions, with an archive-level packaging regression check.
- Compare guarded CI content against both the PR change set and current base tree, refusing stale checks or methodology; parse pinned configuration bytes without workspace file probes and normalize direct repository identities.
- Reject Actions output-path control characters before filesystem inspection, including invalid Windows filenames.
- Drain remaining nonblocking process output after POSIX group cleanup so an early exit notification cannot lose final bytes or hide an output-limit failure.
- Preserve refusal responses for small framed GET and unauthorized request bodies on Windows through bounded raw cleanup, without parsing rejected content or changing authorization.
- Allow 15 minutes for the platform test job, including native dependency builds and clean-wheel checks; retain the existing matrix, read-only permissions and pinned actions.
- Preserve dashboard oversized-request refusals on Windows with byte- and deadline-bounded authenticated-body cleanup; payload and authorization limits are unchanged.

## 0.3.1 - 2026-10-29

### Changed

- Apply the reviewed f mark and brand artwork to the README, packaged dashboard icons and synthetic documentation media.

- Polish the full-height dashboard sidebar, readable UTC times and Statistics labels; rebalance the social preview and refresh screenshots.
- Explain the finance developer workflow in plain language, with audience examples, current guide links and package metadata for discovery.
- Brand the dashboard as finledgerpoli, clarify pending charges and human review, and retain explicit configuration confirmation.
- Add a reproducible synthetic demo GIF, five-step flow and social preview; refresh light-theme screenshots and bind all public media to the catalogue.
- Remove legacy documentation redirect pages and define technical record terminology once while keeping command and JSON field names stable.

- PyPI page: absolute links and images, project URLs, badge.
- Clarify user guides and safety limits, add AI coding-agent recipes and offline `finassist guide` topics, and organize maintainer documentation.

### Security

- Update vulnerable build/test tools and hash-verify CI/release dependency installs, including the package-manager bootstrap and pinned runner image.

## 0.3.0 - 2026-10-28

First public release. The distribution is `finledgerpoli`; the Python import and primary command are `finassist`, with a `finledgerpoli` command alias.

### Added

- Offline synthetic demo, deterministic financial and evidence checks, append-only observation revisions and explicit hash-bound decisions.
- Configurable source paths and file types, review profiles loaded from bounded JSON files, provider settings, GitHub Enterprise hosts and a generated configuration JSON Schema.
- Native Windows, macOS and Linux support with UTF-8 text, CRLF-aware patches, portable process cleanup, Git mode checks and Docker Desktop-compatible mounts.
- Prebuilt offline dashboard with configuration previews, explicit saves, private recovery copies, audit statistics and health checks; Node is unnecessary at runtime.
- Model-neutral review and patch proposals, screened committed snapshots, isolated check recipes and guarded rollback.
- Hash-linked private audit records, concurrent budget reservations, per-run/daily/monthly limits and readiness checks that block on unknown outcomes.
- Tag-only release builds with SBOMs, provenance and human-approved PyPI Trusted Publishing.
- Weekly grouped dependency updates, CodeQL, OpenSSF Scorecard, contributor templates, security guidance, customization walkthroughs, CLI contracts and synthetic demo media.

### Security

- Require explicit network, outgoing-request and patch-hash approvals; protect policy, build and dependency paths and default branches.
- Screen both source versions, sensitive assignments, private paths, Git modes and links. Bind configuration, coverage, generated exclusions and source hashes to review and check evidence.
- Validate patch structure and complete changed-path lists before mutation; preserve exact backups and executable modes where supported.
- Retain uncertain billing and interrupted operations for reconciliation. Verify audit state and fresh complete evidence before readiness can pass.

## Earlier development

Earlier development introduced the portable CLI, synthetic checks, provider adapters, evidence store, isolated recipes and approved patch workflow included in the first public release.
