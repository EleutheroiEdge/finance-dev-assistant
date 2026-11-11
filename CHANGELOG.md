# Changelog

All notable changes to finledgerpoli are documented here, following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Unreleased

### Security
- **The confidential-figure screen missed figures written beside ordinary punctuation.** In 0.10.0
  and earlier, a listed figure could pass when it sat against a single parenthesis, as in
  `(48,213.57 before)`, after a dotted prefix, between neighbouring number columns, or inside some
  exponent forms. A generated test (each figure in every notation, sign and surrounding) found
  12,659 of 207,636 cases passing, 6.1%, in the notations 0.10.0 documented as read. The screen is
  rebuilt on one reader of digit runs, and the test, now 291,357 cases, finds none.
  - It also reads decimal commas (`6.729.102,50`), apostrophe, thin-space and figure-space groups,
    fullwidth and Arabic digits and marks, a leading point, character escapes and HTML character
    references.
  - In `.py` files a string or bytes value that differs from its source text is screened too: a
    spelling escape, a line continuation, or adjacent literals.
  - If you rely on the screen, upgrade. A packet that 0.10.0 passed can be refused now, with
    `forbidden_token_present`.
- **`plan`, `review` and `propose` had no figure screen.** Only the gate did, so a range that
  `doctor` called ready could carry listed figures on the configuration route. See Added.
- **A private name hidden behind a dot was reviewable.** `.secrets/`, `.data/`, `.credentials.json`
  and other hidden spellings of the private names were not refused, so a file under one could be
  sent for review once its directory was allowed. A hidden spelling is now the same name, at any
  depth and on every route.
- **Credential stores are private by name.** Files where tools keep a login are refused wherever
  they sit: `.netrc`, `.pypirc`, `.git-credentials`, `.docker/config.json`, `.kube/`, `.gnupg/`,
  `.config/gcloud/`, `.config/gh/` and the others listed in `docs/configuration.md`. The content
  screen does not recognise every one of them, such as the encoded login in a Docker `auths` entry.

### Added
- **Confidential figures on the configuration route.** `forbidden_token_file` and
  `forbidden_token_hashes` are now configuration settings too, with the gate's rules:
  - `plan` screens the instructions, every changed file and related context, and names the file
    that holds a figure in local output only;
  - `review` and `propose` load the list again, screen the packet again before sending and
    screen what the model returns. They take `--repo` for the check that the list sits outside
    the repository;
  - `doctor --base --head` lists each file that holds a figure, and reports `figure_screen`
    (`configured`, `listed`) so a ready report says whether any figure screen ran;
  - a request prepared without the screen is refused with `forbidden_token_guard_required`.

- **Figure lists from files you already hold, and matching by digits.** For a configuration and
  for a gate policy alike:
  - `forbidden_token_sources` names up to 16 delimited files, such as custody exports. Every cell
    that holds exactly one number of enough significant digits is listed, in any notation. Dates
    and cells with other text are not;
  - `forbidden_token_match: "digits"` also refuses the same significant digits at any scale and a
    two-place rounding in either direction, as common figure guards do. It leaves out digits
    inside a hexadecimal word such as a commit id. `forbidden_token_min_digits` (5 unless set)
    is the fewest significant digits a figure may have;
  - `doctor --base --head` reports the match rule and how many figures and digit forms are listed.

  Unset, nothing changes. New codes: `forbidden_token_source_invalid` and
  `forbidden_token_match_invalid`.

### Changed
- **Adding these settings does not change the configuration hash.** A setting marked this way is
  left out of the hash while it has its default, so saved check records, workflow plans and
  readiness evidence from 0.10.0 still count after the upgrade.
- **A gate can refuse what it passed before, when the policy lists figures:**
  - the notations above are now read as the listed figure;
  - a `.py` file that tokenizes but does not parse is refused with
    `forbidden_token_python_unreadable` when a string in it has a spelling escape, a line
    continuation or an adjacent literal;
  - a listed whole number no longer refuses a decimal that merely starts with it. `73026.04`
    passes when `73026` is listed, in every surrounding; 0.10.0 refused it in some.
- **Every route refuses more names as private.** A range that changes a hidden spelling of a
  private name, or a credential store, is refused with `private_path`, `gate_private_path` or
  `private_profile_path`, or withheld under `private_paths: skip-and-report`. On nine real
  repositories no tracked file and none of 225 recent changes is affected.

Nothing else about what a gate accepts, authorizes or spends has changed.

### Fixed
- **On macOS a check could fail with `PermissionError` when its command exited as the runner stopped
  reading its output.** macOS refuses to signal a process group that holds only a zombie, and the
  runner raised that refusal when it came a moment before the exit was reported. The signal is now
  tried again until the group is proved to hold only a zombie. A group with a live member still
  raises.
- **`init --detect` left hidden directories out of `allow_paths`.** A change to `.github/workflows/`,
  to a tool's settings directory or to a root file such as `.pre-commit-config.yaml` then left every
  range that touched it incomplete, or refused by a gate. On nine real repositories that was the most
  common blocker: it left something out of 56 of 225 changes, and in 43 of them nothing else. The proposal now lists hidden directories and root dotfiles that
  hold reviewable text. Private ones are never proposed, read or sized, at any depth: `.env` files,
  hidden spellings such as `.secrets/`, and credential stores such as `.docker/config.json`. A
  fixture root the gate would refuse, such as `tests/.data/`, is no longer drafted either.
- **`init --detect` drafted a gate policy that the gate refused.** The draft listed private files
  found inside reviewed directories under `deny_paths`, and the policy check refused any policy whose
  `deny_paths` named a private path such as `.env.example`, `holdings/` or `USER.md`. Every range was
  then blocked with `private_path` or `private_profile_path` before a file was read. On nine real
  repositories this blocked all 25 changes checked in four of them. Now:
  - a `deny_paths` entry may name a private path. It reads and sends nothing, so only its form is
    checked: a literal relative path with no wildcard. `allow_paths` entries still meet the path policy;
  - the draft's `deny_paths` is empty. Private files are refused or withheld by name already, and a
    deny entry would refuse the range even under `skip-and-report`. The proposal counts them under
    `private_paths` and warns with the new `private_paths_inside_scope`, beside
    `private_paths_outside_scope`.

  For a gate: a policy that names a private path under `deny_paths` now loads; it was refused whole.
  A file under such an entry still refuses the run with `gate_denied_path`.

## 0.10.0 - 2026-11-10

### Changed
- **`init --detect` proposes something a repository can use as it stands.** Run on a first adopter's
  repository, the 0.9.0 proposal left out a root roadmap file that every pull request edits, sized
  its limits for one file instead of a real change, kept the default profile and drafted a gate policy
  with 14 required fields absent. Now:
  - `allow_paths` also lists root text files and other directories of reviewable text;
  - without `--purpose` or `--profile`, the profile follows the README and agent instruction files when
    they clearly point to one purpose. Otherwise the default is kept and `purpose_not_stated` warns;
  - `max_packet_bytes` and `max_request_bytes` also fit the largest of the last 40 first-parent
    changes, sized from Git's object headers without reading a file. `recent_change_over_ceiling`
    warns when one can't fit;
  - the gate policy draft is a whole version-2 policy. With `--provider`, `--model`, `--api-key-env`
    and both prices it needs nothing more, and its `max_run_usd` covers one request at the proposed
    limit. Otherwise `gate_policy_missing` lists what is left to choose, and nothing is invented.

  For scripts that read the proposal: `gate_policy_draft` gains `schema_version` and more
  `model_review` fields, `gate_policy_missing` is new, and a stated `--profile` is now recorded in the
  evidence as `stated`. Detection also runs `git rev-list` and `git diff --raw`, both read-only.
- **Larger ranges fit.** `max_packet_bytes`, and a gate policy's `max_request_bytes`, may now be set up
  to 8,000,000 bytes; the ceiling was 2,000,000. A packet holds the earlier and later text of every
  changed file, so a range that touches large files could exceed the old ceiling in any setup.
  - The defaults (120,000 and whatever a policy states) are unchanged, and so is every other limit,
    including `max_file_bytes` at 2,000,000.
  - `review`, `propose`, `workflow` and `verify-gate` read a packet file up to the new ceiling.
  - A gate whose policy keeps `max_request_bytes` at or under 2,000,000 behaves as before. One that
    states more is bounded by that figure.
  - `init --detect` sizes its proposal against the new ceiling.
  - The configuration guide lists what to check before raising either limit: the model's context
    window, `timeout_seconds` and `max_run_usd`.

  This changes what a gate accepts only for a reviewed policy that states a `max_request_bytes` above
  2,000,000, which no earlier version accepted.
- **A gate with `private_paths: skip-and-report` withholds a private path wherever it sits.** A
  private path outside `allow_paths` used to refuse the run with `gate_path_not_allowed`, although
  `plan` and `review` withhold it. It is now withheld unread and counted, like one inside
  `allow_paths`:
  - `allow_paths` only admits files for review, so a file that is never read needs no entry there;
  - a path under `deny_paths` still refuses, and so does any other changed file outside `allow_paths`;
  - the default, `refuse`, is unchanged;
  - `doctor --policy` and `doctor --policy-file` list such a path as `withheld`.

  This changes what a gate accepts. A policy that already sets `skip-and-report` now reviews a range
  it used to refuse, with coverage marked incomplete.

### Fixed
- **Dependabot can read the pinned development environment.** `requirements.txt` pointed at
  `requirements-dev.lock` with `-r`, and Dependabot follows only includes that end in `.txt` or
  `.in`. Its dependency graph job and its weekly pip update job therefore failed on every run.
  `requirements.txt` is now a derived copy of the lock with the same pins and hashes, written by
  `scripts/dependabot_requirements.py` and checked by a test. CI and installs still use
  `requirements-dev.lock`. This changes the repository and the source distribution, not the
  installed package.

### Upgrading

No evidence-store migration is needed, and gate reports keep schema version 2. Upgrades never edit
project configuration or evidence. The configuration hash is the same as in 0.9.0 and 0.8.0, so
reviews, saved check records and workflow plans recorded by either still count. A gate whose policy
states a `max_request_bytes` of 2,000,000 or less derives the same configuration as before. If you
are coming from 0.7.1 or earlier, the 0.8.0 notes below still apply.

Behaviour that scripts may depend on:

- **A gate with `skip-and-report` and a private path outside `allow_paths`.** The run used to end
  `BLOCKED` with `gate_path_not_allowed`. It now reviews the rest, withholds that path and reports
  `coverage: {complete: false, withheld: N}`. `doctor --policy` lists the path as `withheld`, and no
  longer reports `gate_ignored_path` for a withheld path that an ignore rule covers. To keep the
  refusal, leave `private_paths` at `refuse` or list the directory under `deny_paths`.
- **Limits.** `invalid_limit` for `max_packet_bytes` now states a maximum of 8,000,000, and a gate
  policy's `max_request_bytes` accepts up to 8,000,000. Every other limit keeps its maximum.
- **`init --detect` output.**
  - `gate_policy_draft` now has `schema_version: 2`. Its `model_review` adds `enabled`, `max_files`,
    `max_output_tokens`, `timeout_seconds` and `blocking_severities`, and with the provider options
    also the provider fields, both prices, `max_run_usd` and `daily_budget_usd`.
  - `gate_policy_missing` is new.
  - `allow_paths` can list more entries, and `max_packet_bytes` and `max_request_bytes` can be larger.
  - `profile` can differ from the default without `--purpose`. Pass `--purpose` or `--profile` to
    fix it. A configuration written with a different profile has a different configuration hash, as
    with any changed setting.
  - Evidence gains `max_packet_bytes`, `max_files` and `max_run_usd`, and an entry can carry
    `purpose`, `words`, `commit` or `changes_measured`.
  - New warning codes: `purpose_not_stated` and `recent_change_over_ceiling`. `gate_policy_invalid`
    can appear as a warning when a whole draft fails the gate's schema.
- **Hint text** changed for `packet_limit_exceeded`, `patch_limit_exceeded`,
  `gate_request_bytes_exceeded`, `file_limit_above_request_limit`, `request_cap_cannot_fit_file`,
  `invalid_limit` and `private_paths_outside_scope`. Their codes did not.
- **Going back to 0.9.0.** It refuses a configuration whose `max_packet_bytes` is above 2,000,000
  (`invalid_limit`) and a gate policy whose `max_request_bytes` is above 2,000,000
  (`gate_policy_invalid`), and it can't read a packet file over 2,000,000 bytes
  (`input_limit_exceeded`). Lower those limits before downgrading.

Install the release requirements with
`python -m pip install --require-hashes --only-binary=:all: -r finledgerpoli-0.10.0-requirements.txt`.

## 0.9.0 - 2026-11-10

### Added
- **`doctor --policy-file` for a past range.** The gate preflight can read a policy file on this
  machine instead of one committed at `--base`, so a policy can be tried on merged ranges whose
  base predates it. It runs the same checks and reports `policy.source: "working-tree"` with a
  `policy_from_working_tree` warning. It authorizes nothing: a `ready` range gets no `gate run`
  command, and `gate run` still reads only the pinned policy at base. The base route's report
  now carries `policy.source: "base"`.
- **`doctor --repo --base --head` for the configuration route.** Without `--policy` or
  `--policy-file`, the range preflight now checks `plan` and `review` for `--config` (or the
  defaults) and reports every blocker in one run, instead of refusing with
  `doctor_policy_required`. That covers refused, withheld and omitted paths (named in local
  output only), file and packet limits, `scope_incomplete`, settings with no effect, the network
  setting, whether the key variable is set, prices and the reserved spend. Once nothing else
  blocks it runs the real packet builder, so `ready` means `plan` builds the packet. It reads no
  key value, opens no ledger, makes no network call and writes nothing.
- **`doctor` reports evidence recorded under another configuration.** With an audit ledger in
  the state directory it adds `evidence` (saved check records and workflow plans, and how many were
  recorded under another configuration hash) and warns `evidence_configuration_changed` with
  what to run again. The hash still covers every setting with its default, so a default that
  changes between releases is caught too.
- **Mix-ups between file kinds are named.** A finassist.json configuration passed as a gate policy
  now blocks with `gate_policy_is_configuration` instead of a list of schema errors. `--config`
  refuses a gate policy with `config_is_gate_policy` and a CI policy with `config_is_ci_policy`.
- **`audit close-run` for an unfinished command (#69).** A command that was killed, or whose completion
  couldn't be recorded, used to block readiness until the state directory was replaced.
  `finassist audit close-run --run RUN_ID --command NAME` records its outcome as unknown:
  - only a run listed in `incomplete_runs` qualifies, and `--command` must match its recorded command;
  - it never claims success, deletes nothing and leaves open spend for `reconcile-budget`;
  - a late completion from that run is refused, so the unknown outcome can't be replaced;
  - `audit` lists it under `reconciled_runs`.
- **`workflow abandon` for a damaged run (#69).** A run whose own files were missing or changed refused
  every command, and its plan couldn't start a new run.
  `finassist workflow abandon --run-id RUN_ID --approve-plan HASH` closes it:
  - only an unfinished run that fails with `workflow_artifact_missing_or_changed` qualifies;
  - the plan hash comes from the audit ledger, and an interrupted step needs `--confirm-cleanup`;
  - nothing is deleted, its status becomes `abandoned`, and none of its check results count as evidence.
- **`verify-gate` warns about recent recoveries.** A closed run or an abandoned workflow within
  `readiness_max_age_seconds` adds a `warnings` entry, `reconciled_operation`, with the counts. It never
  blocks.

### Changed
- **`plan` names what it refuses.** It now checks every changed name before reading any file,
  and one error reports them all:
  - the first refusal's `code`, plus `refused_count`;
  - under `local`, each refused path grouped by code, up to 20 names per code;
  - for a refusal while reading a file, such as `file_limit_exceeded`, that file under `local.path`.

  Names appear only on this machine's stderr, screened like the names `doctor --policy` shows. The
  error's other fields, packets, reports and audit records still never hold a path. `gate run`
  doesn't print them, since CI logs are often public; `doctor --policy` lists them for a gate range.
- **`plan` reports settings with no effect.** Its summary, and the `local` part of a refusal, now
  carry the `config_warnings` that `doctor` reports. That covers a `finassist.json` not passed with
  `--config`, a `text_suffixes` entry the deny list always refuses, and a paid provider with zero
  prices.
- **`init` reports settings with no effect.** When it writes a configuration that keeps one, for
  example a `text_suffixes` entry copied from `--config`, its output adds `config_warnings`;
  `init --detect` adds them to the proposal.
- **`packet_limit_exceeded` from `plan`** now adds the `limit` and the packet's `bytes`.
- **Hints for refused data and private paths** now mention `private_paths: skip-and-report`, which
  withholds them unread and reviews the rest.

### Fixed
- The 0.8.0 install line now uses `--only-binary=:all:`, like the README and the upgrading guide.

### Upgrading

No evidence-store migration is needed, and gate reports keep schema version 2. Upgrades never edit
project configuration or evidence. The configuration hash is the same as in 0.8.0, so reviews,
saved check records and workflow plans recorded by 0.8.0 still count. If you are coming from 0.7.1
or earlier, the 0.8.0 notes below still apply, and `finassist doctor` now names what to run again
(`evidence_configuration_changed`).

Behaviour that scripts may depend on:

- **`doctor` with a range but no policy.** `doctor --repo R --base B --head H` used to refuse with
  `doctor_policy_required`. It now runs the configuration preflight and exits 0 (ready) or 1
  (blocked). With only part of a range it refuses with `doctor_policy_range_required`.
- **`doctor` reads the audit ledger.** Without a range, it now opens `audit.sqlite` in the state
  directory read-only, if one exists, to report `evidence`. It still writes nothing.
- **`plan` refusals.** A refusal can now carry `refused_count` and a `local` object. Scripts should
  key on `code` and ignore fields they don't know. Every changed name is checked before any file is
  read, so a range with both a refused name and a file that can't be read (too large, for example)
  now reports the name's code.
- **New fields in existing output.** Each appears only when it applies, except `policy.source`:
  - `config_warnings` in `plan` and `init` output;
  - `policy.source` in every gate preflight report;
  - `reconciled_runs`, `abandoned_workflows` and `closed_run` in `audit` output;
  - `warnings` in `verify-gate` output;
  - the workflow status `abandoned`.
- **Changed codes.**
  - A gate policy or CI policy passed to `--config`: `unknown_config_option` is now
    `config_is_gate_policy` or `config_is_ci_policy`.
  - A finassist.json configuration passed to `doctor --policy`: `gate_model_opt_in_required` or
    `gate_policy_invalid` is now `gate_policy_is_configuration`. `gate run` is unchanged.
- **State directories that use the new recovery events need this release or later.** After
  `audit close-run`, 0.8.0 still lists the run as incomplete. After `workflow abandon`, 0.8.0's workflow
  commands and readiness refuse the ledger with `workflow_state_invalid`. Don't downgrade a state
  directory once either command has been used.

Install the release requirements with
`python -m pip install --require-hashes --only-binary=:all: -r finledgerpoli-0.9.0-requirements.txt`.

## 0.8.0 - 2026-11-09

### Added
- **`doctor --policy` preflight (#64).** `finassist doctor --policy P --repo R --base B --head H` reports every gate blocker for one range in one run, each with a hint. That covers:
  - each changed path and why it is refused, named only in local output;
  - every policy schema error with its allowed values;
  - the request size;
  - the reserved spend;
  - the policy's sha256;
  - whether the key variable is set.

  It makes no network call, reads no key value, opens no ledger and spends nothing. It exits 0 when ready and 1 when blocked.
- **A hint for every error code (#64).** Each error record on stderr now carries a `hint`: fixed, packaged text that says what to do. It never contains anything from the run.
  - `finassist explain CODE` explains a code offline: what happened, how to fix it, related codes and the guide to read. It also accepts a pasted error record.
  - `finassist explain --list` lists every code. A test fails when a code the package raises or reports has no hint.
  - A new [troubleshooting guide](docs/troubleshooting.md) (`finassist guide troubleshooting`) covers the codes most often seen on a first run.
- **`init --detect` (#64).** It proposes `allow_paths`, `generated_paths`, `protected_paths`, file limits, a gate policy draft and test commands from the committed layout. Each proposal shows the file and rule that suggested it. It runs nothing from the repository, reads only the committed revision, and writes only with `--write`.
- **`init --purpose` (#64)** chooses the review profile by what the code does: quant, accounting, research or general.
- **`private_paths: skip-and-report` (#64).** It is opt-in; the default is still `refuse`.
  - A private path in the range is withheld by its name before anything is read, instead of refusing the whole review.
  - Packets, requests, reports and audit records carry only the withheld count. `plan` and `doctor --policy` name the paths in local output only.
  - Every coverage check stays incomplete.
  - It works in configuration and in a gate policy's `model_review`, and the gate report adds `coverage`.
- **Related-code context (#64), opt-in.** With `related_context: "related"`, in configuration or a gate policy's `model_review`, the packet gains a `related` block of signature-only skeletons of unchanged Python code: the functions a change calls, the functions and tests that call it, and the classes it extends.
  - It uses the standard library's `ast` only, in a fixed order, and resolves only exact imported names.
  - Every candidate passes the same path, private-name and content screening as a changed file before it is read. A private name is never read, searched or listed.
  - In a gate, a candidate also meets the policy's `deny_paths`, ignore rules and forbidden figures, and the final screen before sending covers every snippet line.
  - The block has its own byte budget (`related_max_bytes`, default 24,000) and is bound by the packet hash.
  - The default stays `none`.
- **Setup skill and example policies (#64).**
  - `finassist export-kit` now includes a `finassist-setup` skill. It runs `init --detect`, shows every proposed field with its evidence, writes only what the person confirms, then preflights a range with `doctor --policy` until it is ready.
  - Two complete example gate policies with synthetic values: `examples/policies/quant-engine.json` withholds private data (`skip-and-report`), and `examples/policies/rebalancer.json` refuses it (`refuse`).
  - Tests run each example on a synthetic repository of its shape, and check that every command in the skill parses.
  - `init --detect` now warns with `private_paths_outside_scope` when private files lie outside the proposed `allow_paths`, because a gate refuses any range that changes them.

### Changed
- **Error details (#64).** Some refusals now add bounded fields beside `code`:
  - limit errors give the option and its allowed range;
  - `file_limit_exceeded` gives the limit and the file's size;
  - `provider_prices_required` lists the price fields that are still zero;
  - `network_not_approved` says whether the configuration, the `--allow-network` flag, or both are missing.

  These fields never include values, paths or file contents.
- **`doctor` (#64).** It now reports `config_source` (`file` or `defaults`) and `config_warnings`. The warnings cover a `finassist.json` that was not passed with `--config`, a `text_suffixes` entry the deny list always refuses, and a paid provider with zero prices.
- **Names that could display as another name** are redacted in `doctor --policy` and `init --detect` output. That covers names with a control or format character, such as a right-to-left override.
- **Literal error codes.** Every code now appears literally in the source, so it can be found with a text search. The codes themselves are unchanged.

### Security
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

### Fixed
- **`score`** reported a traceback when a labels file's `outcomes` was a list instead of an object. It now refuses with `invalid_adjudication` (#69).
- **Supervised runs.** A recipe could start briefly on a platform where its exit can't be observed without reaping it. The platform is now checked before launch, with `non_reaping_wait_required` (#69).
- **`plan`** built packets for ranges of more than 2,000 changed files, which every later command refused. It now refuses them with `packet_file_count_limit` before reading any file (#69).
- **Workflow run files.** A damaged run file was reported as generic `invalid_input`. It is now `workflow_artifact_missing_or_changed`, like any other changed artifact (#69).
- **`min_version` on a development build.** A development, pre-release or local build refused every configuration with a floor as `invalid_min_version`, blaming a valid file. The build is now compared by its release, and a pre-release or development build counts as earlier than its release (#69).
- **GitHub Action output errors.** An invalid report path or report was always shown as `ci_action_output_unavailable`. It now shows `ci_output_path_invalid` or `ci_report_invalid` (#69).
- **Workflow bundles.** A duplicate key or NaN in a bundle reported pack codes. It now reports `workflow_bundle_invalid` (#69).

### Upgrading

No evidence-store migration is needed, and gate reports keep schema version 2.
Upgrades never edit project configuration or evidence.

**Run reviews, checks and workflow plans again after upgrading.** This release adds
three configuration fields: `private_paths`, `related_context` and
`related_max_bytes`. The configuration hash covers every field with its default, so
an unchanged `finassist.json` hashes differently under 0.8.0, and evidence recorded
by 0.7.1 no longer matches it:

- Readiness reports `review_configuration_changed` and `check_configuration_changed`
  until the review and each required check have run again.
- A workflow plan bound by 0.7.1 reports `workflow_configuration_changed`, and a
  saved bundle resolution refuses with `workflow_resolution_inputs_changed`. Bind
  them again.
- A workflow run started by 0.7.1 can't be resumed, so finish it before upgrading.
  After upgrading, `workflow cancel` closes a pending or failed run. An interrupted
  run (`running` or `unknown`) is refused with `workflow_cancel_not_allowed` until it
  is reconciled: once you have confirmed that its processes have stopped and cleanup
  is complete, `workflow reconcile --confirm-cleanup` records the attempt as failed,
  and the run can then be cancelled. Nothing is cleaned up or retried for you, and
  the attempt's saved result can't be adopted after upgrading (`workflow_result_invalid`).
  Then start a new run from a new plan.

**Configurations and gate policies that use the new fields need 0.8.0.** 0.7.1
refuses such a configuration with `unknown_config_option`. Add
`"min_version": "0.8.0"` so an older reader refuses with `minimum_version_required`
and says to upgrade instead. A 0.7.1 gate refuses a policy whose `model_review` uses
them with `gate_policy_invalid`, so upgrade the gate before committing that policy
on the base branch.

**Gate reports.** When `skip-and-report` withholds paths, the report adds
`coverage: {complete: false, withheld}` with the count. A range whose every changed
path is withheld refuses with `review_scope_entirely_withheld`.

- **`init` with a paid provider** now needs `--input-usd-per-million` and `--output-usd-per-million`. Without them it refuses with `provider_prices_required` instead of writing a configuration every review would refuse.
- **Scripts reading stderr errors.** They should key on `code`; refusal objects may now carry extra fields, including `hint`. Hint wording can change between releases; codes don't.
- **Changed codes.** Scripts that matched these should update:
  - a damaged workflow run file: `invalid_input` is now `workflow_artifact_missing_or_changed`;
  - the GitHub Action's output errors: `ci_action_output_unavailable` is now
    `ci_output_path_invalid` or `ci_report_invalid`;
  - a workflow bundle with a duplicate key or NaN: pack codes are now `workflow_bundle_invalid`;
  - a development or pre-release build with a `min_version` floor: `invalid_min_version`
    is now `minimum_version_required` when the build is below the floor, and accepted
    when it meets it.

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

Install the release requirements with
`python -m pip install --require-hashes --only-binary=:all: -r finledgerpoli-0.8.0-requirements.txt`.

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
