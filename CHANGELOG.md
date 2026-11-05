# Changelog

All notable changes to finledgerpoli are documented here, following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Unreleased

### Changed

- In parseable `.py`/`.pyi` files, credential screening reads code with Python's own
  parser instead of regex (#61). A credential-named target given a literal value
  refuses: assignments, typed assignments, walrus targets, keyword arguments,
  function defaults, dictionary keys, attributes and subscripts, including literal
  `os.getenv`/`os.environ.get` fallbacks and `default=` arguments. Type annotations
  are never inspected. Comments and strings keep the text rules, known secret
  formats are screened across the whole file, and Python that does not tokenize and
  parse keeps the strict text rules.
- In Python files, each numeric literal, including one inside an f-string field, is
  also read with Python's tokenizer and parser and its exact value compared with the
  confidential-figure deny list (#61). Every file is still screened as text, and
  leading or trailing zero padding no longer hides a listed figure in text or code.
- Known formats and custom patterns also read the complete serialized packet (#61).
- Document that secret and figure screening is a backstop behind path allowlists,
  gitignored secrets and the policy, and list the text rules' known limits (#61).

### Upgrading

Content that 0.7.1 accepted can now be refused:

- `forbidden_token_python_unreadable` for a `.py` file that Python cannot tokenize,
  while confidential-figure screening is enabled.
- `forbidden_token_present` for a listed whole figure written in Python as a
  hexadecimal, octal or binary literal.
- `sensitive_content` for a credential literal in Python assigned through a
  subscript or tuple unpacking, or given as an `os.getenv`/`os.environ.get` fallback
  or a `default=` argument.

No longer refused in parseable Python: an unquoted name, expression or call result
assigned to a credential-named target, such as a `password` set from
`get_password_from_vault()`.
These are not literals. Other files keep the text rule, which still refuses unquoted
values.

## 0.7.1 - 2026-11-04

### Security

- Close the confidential-figure gap for underscore-written figures (#59). A listed
  figure now refuses with `forbidden_token_present` when underscores separate its
  digits in any position, as in `6_729_102.50`, `6729_102.50` or `67_29_102.50`.
  Other malformed grouping stays unsupported.
- Close the credential-key gap for unquoted values that start with a capital
  letter (#59). Such a value is screened when it contains a digit or continues
  into `/`, `+`, `=`, `-`, `:` or `@`. A digit-free whole identifier, such as a
  constant or type name, is not.
- Screen typed Python assignments (#59). `password: str = "..."`,
  `api_key: str = "..."`, typed parameter defaults and `account_number: int = ...`
  now refuse. 0.7.0 missed them because the annotation separated the label from
  its value.
- In parseable `.py`/`.pyi` files, the credential-key rule ignores type
  annotations, including unions, forward references and digit-bearing names such
  as `Ed25519PrivateKey` (#59). Review output and proposed patches may quote the
  reviewed source's own annotations, but a new value written after such a quote
  still refuses. Patches and rollback screen each complete file with its path.
- Refuse look-alike and hidden spellings of reserved paths (#58, #47 items 12–14).
  - Reserved directories and private filenames are compared after Unicode
    compatibility normalisation, case folding, trailing dot/space removal and a
    pinned Unicode 18 confusable table. So Cyrillic-letter spellings of
    `holdings`, `client.json.` and `secrets ./` stay private.
  - Path components containing control, format, line or paragraph separator, or
    default-ignorable characters, or the blank fillers U+2800, U+13441, U+13442,
    U+16FE4 and U+1BC9D, refuse with `unsafe_path`.
  - Look-alike `data`, `tests` and `fixtures` components inside an opted-in
    fixture path or root are refused, so fixture markers keep their exact
    lowercase spelling.
  - Four more blank-looking profile characters (U+13441, U+13442, U+16FE4 and
    U+1BC9D) are refused.
  - Actual Git names and request hashes are unchanged.

### Fixed

- `report trace` neutralises `GH-<n>` autolinks (#59).
- `score --evaluation --labels --adjudications` reports `score_input_mode_conflict`
  (#59).
- Publish the strict legacy v1 gate report schema in `schemas/` and in
  `export-kit` (#59).

### Upgrading

No evidence-store migration is needed, and the report format is unchanged (gate
report schema version 2). Upgrades never edit project configuration or evidence.

Content that 0.7.0 accepted can now be refused:

- `forbidden_token_present` when a listed confidential figure is written with
  underscores between its digits.
- `sensitive_content` for:
  - an unquoted credential-key value that starts with a capital letter and
    either contains a digit or continues into `/`, `+`, `=`, `-`, `:` or `@`;
  - a typed Python assignment or parameter default that holds a password, token,
    credential key or account/routing number.
- `unsafe_path` for a path component containing control, format, line or
  paragraph separator, or default-ignorable characters, or the blank fillers
  U+2800, U+13441, U+13442, U+16FE4 and U+1BC9D.
- `private_path`, `gate_private_path` or `private_profile_path` for look-alike,
  case-variant or trailing-dot/space spellings of reserved names.
- `fixture_root_contains_data` for a look-alike `data` component inside an
  opted-in fixture path or fixture root.
- `fixture_root_invalid` for a look-alike `tests` or `fixtures` component inside
  an opted-in fixture path or root. These markers must use exact lowercase
  spelling.
- `gate_profile_line_invalid` for the four additional blank-looking profile
  characters.

Markdown, TypeScript, Kotlin and other text without parsed Python context keep
strict credential screening, and a key written as a Python annotation itself is
not detected. Quote literal credentials.

`score --evaluation --labels --adjudications` returned `score_labels_required` in
0.7.0. It now returns `score_input_mode_conflict`.

Install the release requirements with
`python -m pip install --require-hashes -r finledgerpoli-0.7.1-requirements.txt`.

## 0.7.0 - 2026-11-04

### Added

- Add offline advisory triage contracts (#44, #50). `finassist triage validate`
  binds a supplied routing report to its exact request and a separately pinned
  model manifest, and `finassist triage evaluate` scores independent gold without
  calling a model. Missing, contract-invalid, declared-invalid, abstained,
  candidate-omitted and budget-infeasible cases count as routing misses. Reports
  bind canonical hashes of the complete request, gold and prediction collections
  and the expected model; CLI reports also hash the exact input file bytes that
  were parsed. Reports are advisory only and grant no execution authority.
- Give gate findings stable `f-<sha256>` IDs bound to the request hash, in
  `gate run`, the Action and history evaluation (#54). `finassist report trace`
  renders a private Markdown adjudication table (`| # | Reviewer claim | Trace | Result |`)
  from a report and a local adjudications file, escaping model text as literal
  table text. `score --report` counts Confirmed, Partly right, Refuted and
  unresolved findings. Foreign IDs, malformed adjudications and blocked reviews
  never score as complete.
- Document building and pinning a consumer runner image with exact hash-locked
  dependencies, and selecting exact pytest node IDs on the read-only workspace (#55).

### Security

- Add the optional base-policy `forbidden_token_file` and `forbidden_token_hashes`
  (#53). Policy-approved model gates and history evaluation refuse with
  `forbidden_token_present` when a listed confidential figure appears, including
  in common grouping, currency, sign, parenthesis and trailing-zero forms.
  - Source, fixture and profile text is screened before credential lookup, budget
    reservation or transport. A refusal there writes no ledger. A request that
    proceeds records only the token file path and line count in the private audit.
    Typed filenames are exempt.
  - Provider-returned free text is screened after the call, before findings are
    exposed. A refusal there happens after dispatch, so it keeps the recorded usage
    and settled charge.
- Detect credential-bearing key assignments such as `secret_key`, `access_key` and
  `aws_secret_access_key` (#56). Ordinary database, cache and idempotency keys are
  not treated as credentials, and scanning stays linear on adversarial input.
- Pin exact refusal codes for profile and fixture-marker rejections, and add
  regression tests for marker deletion, mode change, symlink replacement and
  pre-marker forks (#56).

### Upgrading

No evidence-store migration; upgrades never edit project configuration or evidence.

- Gate reports now use schema version 2, with a finding `id`. Update consumers
  that accept only version 1. Archived version-1 reports remain readable;
  `report trace` derives IDs for them that differ from the IDs stored in archived
  history evaluations.
- Content that 0.6.0 accepted can now be refused with `sensitive_content` if it
  assigns a literal value of 12 or more characters to a key label that contains a
  credential word (secret, private, signing, encryption, access, client, master,
  auth or api), for example `signing_key = "..."`. Calls, dotted references and
  type-name annotations are not refused. Move real secrets out of the reviewed source.
- Confidential-figure screening is off unless the base-pinned policy declares
  `forbidden_token_file` or `forbidden_token_hashes`.
- Triage is new in this release. Its evaluation outcomes are `contract_invalid`
  and `declared_invalid`; anyone who tested the unreleased pre-merge #44 revision
  will see that the earlier combined `invalid` bucket has been split in two.
- Install the release requirements with
  `python -m pip install --require-hashes -r finledgerpoli-0.7.0-requirements.txt`.

## 0.6.0 - 2026-10-31

### Added

- Release builds generate and clean-install a hash-locked runtime requirements asset
  from the exact wheel; the approved publication job attaches it to the GitHub release.
- Add default-off, base-pinned synthetic fixture roots to model and checks
  policies. Roots require an exact tests/fixtures component or a reviewed Git
  marker; mandatory private/data, ignore, text, secret and object screening stays
  active. Separate fixture byte caps apply through review and recipe staging.
- Allow v2 model-review policies to own a named checklist through inline text or
  an exact-byte-pinned UTF-8 profile from the reviewed base commit. Bind custom
  instructions to policy/request hashes and refuse head profile changes, unsafe
  paths and sensitive content; built-in and offline defaults remain unchanged.
- Benchmark frozen local PR history with held-out labels, trial-count-bound
  suite approvals, shared gate screening/policy/request/budget controls and
  private attempt journals. Unknown attempts stop all remaining trials.
- Score independently adjudicated history findings with severity weighting,
  negative controls, trial agreement and cost/time per confirmed target hit;
  compare matched source cases across model or external reviewer evaluations.
- Include this repository's own reviewed PR history and two controls, plus
  guidance for keeping adoption holdouts private and avoiding memorized cases.

### Security

- Reject invisible profile characters and nonphysical instruction separators,
  require LF-exact synthetic marker attestation, and reject reserved fixture path
  aliases without extending fixture-only restrictions to ordinary v1 snapshots.
- Reject hidden line breaks and control/format characters in policy instruction
  lines, and document profile-author trust, protected review and raw Git blob pins.
- Avoid quadratic secret/account assignment scans on long hyphenated tokens
  while retaining detection of sensitive suffixes in arbitrarily long labels.

### Upgrading

No evidence-store migration; upgrades never edit project configuration or evidence.
Policy profile text is now screened more strictly: a profile line with a tab, a BOM,
an invisible, private-use or unassigned character, or a non-LF line separator is refused
with `gate_profile_line_invalid`. Fix the profile text on the base branch before upgrading
a gate that uses one. Synthetic fixture roots are off unless the base-pinned policy lists them.
Each release now ships `finledgerpoli-<version>-requirements.txt`; install with
`python -m pip install --require-hashes -r finledgerpoli-0.6.0-requirements.txt`.

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
