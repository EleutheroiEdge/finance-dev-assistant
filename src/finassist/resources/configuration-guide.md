# Configuration reference

Configure finledgerpoli source policy, providers, budgets and review requirements in one validated JSON file. Its command is `finassist`.

The CLI and library use the same `Config.validate()` rules. Unknown fields fail
with `unknown_config_option`; no provider is selected from an existing key.
[Complete example](../examples/fork-config.json) lists every option. It stays offline.

Update notices use a separate user-level `settings.json` with `update_check`
set to `off` or `notify`; the default is off. Do not put this setting in project JSON.
`FINASSIST_NO_UPDATE_CHECK` disables checks, including when empty. See
[Upgrading](upgrading.md) for platform paths, daily caching, explicit installer
commands and the `doctor --check-updates` network gate.

| Option | Meaning |
|---|---|
| `schema_version` | Configuration format version; use 1. |
| `min_version` | Optional stable X.Y.Z reader floor, checked before other options; empty by default. Historical releases without this feature report unknown_config_option for it. |
| `provider` | offline, openai, anthropic, google, compatible or ollama. No automatic fallback. |
| `model` | Exact user-selected model identifier; empty for offline. |
| `endpoint` | Explicit provider API URL, or the built-in protocol default. |
| `api_key_env` | Environment variable NAME only. Never a key value. |
| `auth_header` | Authorization, api-key or x-api-key for the selected endpoint. |
| `profile` | Selected name from the resolved profiles registry. |
| `profiles` | Registry of names to nonempty checklist arrays. Replaces built-ins when supplied; general is required. |
| `profile_files` | JSON registry files, strict relative POSIX .json paths inside this config directory. Definitions overlay profiles; duplicate paths, names and empty files fail. |
| `denied_parts` | Lowercase private path component names (matched case-insensitively). Remove portfolios only for approved source code; .git and .finassist remain required. |
| `text_suffixes` | Lowercase source suffixes including the dot. Add .tf/.cs explicitly. Binary/credential file restrictions remain. |
| `github_host` | GitHub DNS hostname, without scheme, path or port. Defaults to github.com; Enterprise uses existing gh auth. |
| `allow_network` | Enable potential network use. Each command still needs its own explicit network approval. |
| `allow_partial_review` | Permit model calls with explicitly accounted-for omissions. Readiness still requires complete coverage. |
| `related_context` | `none` (default): the packet holds only the changed files. `related`: it also holds signature-only skeletons of unchanged Python code the change calls, is called by or extends. See [related-code context](#related-code-context). |
| `related_max_bytes` | Byte cap for the related-code block, 1 to 400,000; default 24,000. |
| `private_paths` | `refuse` (default): a private path in the range, such as a data file or a path under a private directory, refuses the whole review. `skip-and-report`: such a path is never read or sent; the packet carries only how many were withheld, and names appear only in local output. Coverage is then incomplete. See [skipping private paths](#skipping-private-paths). |
| `allowed_hosts` | Additional approved MODEL endpoint hostnames; distinct from github_host. |
| `generated_paths` | Exact relative files or directory prefixes excluded from review and snapshot source. Defaults to src/finassist/resources/dashboard/. No globs; rebuild/integrity CI must verify these artifacts. |
| `allow_paths` | Exact source paths or prefixes ending in /. Denied components still apply. |
| `protected_paths` | Proposal-protected paths or directories. Source may still be inspected if allowed. |
| `protected_branches` | Glob patterns where local patch application is prohibited. |
| `extra_sensitive_patterns` | Additional case-insensitive regular expressions. Invalid patterns fail; matches block content. |
| `max_file_bytes` | Maximum bytes per source file version. |
| `max_packet_bytes` | Maximum serialized outgoing request bytes. |
| `max_output_tokens` | Requested output token ceiling. Anomalous reported usage stays unreconciled. |
| `timeout_seconds` | Bounded provider and recipe timeout; remote cancellation is separate. |
| `max_run_usd` | Local per-call spend admission limit in USD; not a provider-enforced cap. |
| `monthly_budget_usd` | Local UTC booking-month admission budget (default USD 100); includes all unresolved reservations from earlier periods. Not a provider billing cap. |
| `daily_budget_usd` | Local UTC daily admission budget, including unresolved reservations from prior days. |
| `input_usd_per_million` | Operator-supplied input token price in USD per million. |
| `output_usd_per_million` | Operator-supplied output token price in USD per million. |
| `recipes` | Named arrays of literal executable/argument strings. Never shell command strings. |
| `runner_image` | Prebuilt digest-pinned OCI image used for isolated recipes. |
| `required_recipes` | Recipe names whose fresh passing check records are required for human review. |
| `blocking_severities` | Finding severities that block readiness: critical/high/medium/low/info. |
| `readiness_max_age_seconds` | Maximum age of audited review and check evidence. |
| `allow_local_readiness` | Explicit trusted-code opt-in for local recipe evidence; false by default. |

Saved records bind actions to source and configuration hashes. Readiness means satisfying configured prerequisites for human review.

## Start from your repository's layout

`finassist init --detect` reads the files committed at `HEAD` (or `--revision`) and prints a
proposed configuration, with the file and rule behind each setting. It writes nothing unless
you add `--write`, and it never overwrites an existing file.

```sh
finassist init --detect --purpose quant
finassist init --detect --purpose quant --write --output finassist.json
```

- **What it proposes:**
  - `allow_paths`: source directories, root source files, tests, docs and scripts, then any other
    directory of reviewable text and root text files such as a roadmap, so a change to one doesn't
    leave a range incomplete. Hidden directories and root dotfiles count too, such as `.github/` and
    `.pre-commit-config.yaml`; a private name, or a hidden name that is private without its dot, never does;
  - `generated_paths`: lock files, hash-named build assets, `dist/`, and files `.gitattributes` marks `linguist-generated` or `linguist-vendored`;
  - `protected_paths`;
  - `profile`: from `--purpose` or `--profile`. Without either, it follows the README and agent
    instruction files when at least three words for one purpose appear there and that purpose leads
    the next by two; the evidence lists the words. Otherwise the default is kept and
    `purpose_not_stated` warns;
  - `max_file_bytes`: fitted to the largest reviewed source file;
  - `max_packet_bytes`: enough for one file's change and for the largest recent change.

  Its gate policy draft is a whole version-2 policy, apart from the choices that are yours:
  - `max_request_bytes`, `max_files`, `max_output_tokens`, `timeout_seconds` and `blocking_severities`;
  - the provider, model, endpoint, key variable name, prices and budgets, when you pass `--provider`,
    `--model`, `--api-key-env` and both prices. `max_run_usd` then covers one request at the proposed
    limit. Without them `gate_policy_missing` lists those fields, and nothing is invented for them;
  - `fixture_roots` for CSV or TSV files under a tests directory, which must be synthetic;
  - an empty `deny_paths`. Private files are refused or withheld by name already (the shared path policy and the
    gate's private names: data, private, client and similar), so none is listed. The proposal counts them under
    `private_paths` and warns with `private_paths_inside_scope` or `private_paths_outside_scope`. Add your own
    entries for paths that must always refuse; an entry may name a private path.

  Packet and request limits are measured, not estimated:
  - a changed file travels with its earlier version;
  - the packet escapes its text as JSON once, and the provider request escapes the packet again, so tabs, quotes and non-ASCII text grow most;
  - the proposal measures the largest source files that way and adds 64 KiB for instructions;
  - it then sizes the last 40 first-parent changes from Git's object headers, without reading a file
    and never sizing a private name, and scales them by the escaping it measured. The limits fit the
    largest, and `recent_change_over_ceiling` warns when that needs more than 8,000,000 bytes;
  - when even 8,000,000 bytes can't fit one file's change, it warns with `request_cap_cannot_fit_file`.
- **Proposals stay narrow:**
  - a file name that only looks generated, such as `assets/name-<hash>.js`, must have a digit in its hash, and never widens a generated prefix beyond its own `assets` or `dist` directory;
  - only each runner's own test command is proposed, so `npm publish test` or `make deploy test` never is;
  - a file the path policy treats as private is never read or sized, even under `.github/workflows/`;
  - a name that would be shown as `[redacted]` is left out of every proposed value and counted in `unsafe_names_skipped`.
- **Test commands** come from pytest configuration, tox, nox sessions, a Makefile `test` target, `package.json`, CI `run:` steps and shell blocks in AGENTS.md or CLAUDE.md. Each has a confidence and names the file and line it came from. They are proposed, never run.
- **What it never does:**
  - run anything from the repository (no make, nox, tox, npm, setup.py or workflow step);
  - read the working tree, untracked files or `.env`;
  - use the network;
  - treat text in agent files as instructions.
- **`--purpose`** chooses the review profile: `quant` (quant-review), `accounting` (finance-saas), `research` (investment-research) or `general`. It is never guessed from prose.
- **Names** appear only in this local output. A name that fails screening, or that contains a control or format character such as a right-to-left override, is shown as `[redacted]`.
- **Limits:**
  - YAML is scanned line by line, not parsed.
  - Reading `.gitattributes` from a revision needs Git 2.40 or later.
  - A proposal is a starting point to check, not a review of the repository.

A paid provider needs both prices from your provider's price list:
`finassist init --provider PROVIDER --model MODEL --input-usd-per-million IN --output-usd-per-million OUT`.
Without them, `init` refuses with `provider_prices_required` and writes nothing. `--api-key-env NAME`
names the key variable, never the key.

## Path and file policy

Conservative denied path components and source suffixes are supplied by default. A path
under `src/portfolios/` needs both an allowed source prefix and explicit removal
of `portfolios` from `denied_parts`. Paths stay relative, reject traversal and
links, and are rechecked throughout planning, verification, export, evaluation,
proposals and rollback. Packets capture `allow_paths` and the selected profile;
active review/readiness requires an exact match and re-screens custom content
patterns. Rebuild older outgoing requests lacking scope-policy evidence before active use.
The approved path policy is saved in patch backups; CLI rollback also enforces
the active configuration before writing any file.
Generated exclusions are captured in outgoing request policy, are accounted for explicitly,
and do not count as incomplete review coverage. Other omissions still do. Generated
bytes remain subject to publication scans and build-integrity CI. `.gitattributes`
is reviewable and protected by default.
Runtime/Git internals, environment files, private profile filenames, credential
formats and binary restrictions remain intrinsic protections. There is no bypass switch.

## Related-code context

The packet always holds the whole merge-base and head copies of each changed file. With
`related_context` set to `related`, it also gets a `related` block: short, read-only skeletons of
unchanged Python code in other files, so the reviewer can see what a change calls and what calls it.
The same field works in a gate policy's `model_review` object.

- **What is added,** in this fixed order:
  1. `callee`: a function called on a changed line;
  2. `caller`: a function that calls a changed or removed function;
  3. `test`: the same, in a test file;
  4. `base`: a class that a changed class extends.
- **Skeletons, not bodies.** A function shows its decorators, its `def` line and the first line of
  its docstring. A class also shows its methods' signatures. A caller also shows its call lines.
  Each snippet gives its path, line numbers, relation, symbol, the changed line or definition that
  links it, and the sha256 of the file it came from.
- **Only names that resolve exactly.** A name resolves through the file's own module-level
  `import` and `from ... import` statements: a plain imported name, or `module.attribute`. A name
  bound where the call is, such as a parameter, a local assignment or an import inside the
  function, is left out, and so is a name the file defines itself. Anything else, such as a method
  called on an object, is left out rather than guessed. Python only, for now.
- **The same screening as a changed file.** A candidate must be tracked at head, inside
  `allow_paths`, not generated, and pass every path and private-name rule before it is read. A
  private name is never read, searched or listed. A file that fails content screening or doesn't
  parse is listed by name and reason code under `skipped`, with nothing from its content.
- **In a gate, the policy's rules too.** A candidate must also pass the policy's `deny_paths` and
  the current and base ignore rules before it is searched or read. When the policy lists forbidden
  figures, a candidate's whole file is screened for them, as a changed file is. A file holding one is
  listed with the reason `forbidden_token_present`, and the final screen before sending covers every
  snippet line.
- **Its own budget.** The block takes at most `related_max_bytes`, and at most the changed files'
  own size or 16 KB, whichever is larger. It never takes the room the changed files need. Snippets
  are added in rank order until the budget is spent. The rest are listed by name with the reason
  `related_budget`. Each changed function shows at most 3 callers and 3 tests; the others are
  listed with the reason `related_target_limit`. At most 500 files are read to find callers; the
  others are listed with the reason `related_search_limit`.
- **Bound like the rest of the packet.** The approved packet hash covers the block, and `review`
  checks it again before sending. The model is told the snippets are reference only, and its
  findings must still cite the changed files.

The default stays `none` until phase 4 of the [roadmap](https://github.com/EleutheroiEdge/finance-dev-assistant/issues/64)
measures whether the block helps.

## Checking a range first

Before the first `plan` or `review` of a range, run the configuration preflight:

```sh
finassist --config finassist.json doctor --repo . --base BASE --head HEAD
```

It reports every blocker `plan` and `review` would hit for that range in one run, each with a
`hint`, and exits 0 when the range is ready and 1 when it is blocked:
- **Each changed path** as `included`, `withheld`, `omitted` (with its reason) or `refused`
  (with the code and any limit or size). Refused paths, and omitted ones that make `review`
  refuse a partial range (`scope_incomplete`), are grouped by code with a `count` and up to
  20 example `paths`.
- **Settings with no effect,** the same `config_warnings` that `doctor` reports.
- **The packet's size** against `max_packet_bytes`, from the real packet builder once nothing
  else blocks.
- **For a model provider:** the network setting, whether the key variable is set (never its
  value), the prices, and the request's reserved spend against `max_run_usd`,
  `daily_budget_usd` and `monthly_budget_usd`. Spend already recorded is not read.

It makes no network call, reads no key value, opens no ledger and writes nothing. Path names
appear only in its local output, as `[redacted]` when a name fails screening. A `ready`
report lists the `plan` and `review` commands to run next. Without `--config` it checks the
defaults. For a gate range, use `doctor --policy` instead (see the pre-merge gate guide).

## Skipping private paths

With `private_paths` set to `refuse` (the default), a private path anywhere in the range refuses
the whole review:
- **`plan` and `review`** refuse a data, binary or credential file (by suffix), a path under a
  denied directory (`denied_parts`, such as `credentials/` or `.env`) and a reserved profile name.
- **A gate** also refuses the gate's private directories and names, such as `data/`, `private/`,
  `client/`, `household/` or `client.json`.

`plan` checks every changed name before it reads any file, and its error lists each refused
path under `local`, grouped by code. Those names appear only on this machine's stderr, as
`[redacted]` when a name fails screening; the error's other fields, the audit record and any
report never hold them.

Set `private_paths` to `skip-and-report` to review the rest of the range instead. The same field
works in a gate policy's `model_review` object. What happens then:

- **A path is withheld when its name alone makes it private,** by the gate's rules (both lists
  above), in `plan`, `review` and the gate alike. Its contents are never read, hashed, sized or sent.
- **Only a count leaves your machine.** The packet, request, report and audit record carry how many
  paths were withheld, never their names, extensions, directories or sizes. `plan` names them in its
  local summary (`withheld_paths`), and `doctor --policy` lists them as `withheld`. A name that could
  display as a different one, or that matches a configured sensitive pattern, is shown as `[redacted]`.
- **Some refusals still come first.** A private path under a gate policy's `deny_paths` still
  refuses the gate; one outside `allow_paths` is withheld, as in `plan` and `review`. A name that
  matches `extra_sensitive_patterns`, or that itself looks like a credential, still refuses everywhere.
- **Coverage is incomplete wherever it is checked:**
  - a review is `partial-review`;
  - readiness, workflow plans and the CI check gate still refuse it with their coverage codes;
  - a gate report carries `coverage: {complete: false, withheld: N}`, its Actions summary says
    coverage is incomplete, and its `withheld-count` and `coverage-complete` outputs carry the same.

  A gate PASS then means the reviewed files passed, not that every changed file was reviewed.
- **A range in which every changed file is private** refuses with `review_scope_entirely_withheld`.

`refuse` is the mode that requires complete coverage; there is no separate switch. Text inside a
reviewed file that mentions a private file is outside this guarantee; it is screened like any other
source.

## Confidential figures

`plan`, `review`, `propose` and `doctor` refuse a range that holds a listed confidential figure
when the configuration names a list:

- **`forbidden_token_file`:** an absolute path to a private file outside the repository and its
  worktrees, with one figure per line.
- **`forbidden_token_hashes`:** up to 1,024 SHA256 hashes of canonical figures. A hash of a
  short number can be guessed, so keep the hashes private too.

With neither set, which is the default, no figure screen runs, and `doctor --base --head` says
so under `figure_screen`. With a list set:

- **`plan`** screens the instructions, both versions of every changed file and any related
  context. It names the file that holds a figure in its local output only, and never prints
  the figure.
- **`review` and `propose`** load the list again and screen the packet again before anything
  is sent, then screen what the model returns. Pass `--repo` when you run them from outside
  the repository: the list must not sit inside it.
- **`doctor --base --head`** lists each file that holds a figure with the code
  `forbidden_token_present`, and reports how many entries the list holds.

A request prepared without the screen is refused with `forbidden_token_guard_required`, so a
configured list can never be skipped. The matching rules are the gate's; see "Confidential
numeric tokens" in the pre-merge gate guide. While both settings are empty they leave the
configuration hash unchanged, so adding them does not make saved check records stale.

## Custom profiles

`profile_files` contains UTF-8 JSON objects mapping profile names to checklist
arrays. See [engineering profile](../examples/profiles/engineering.json). Files
are data, never Python/plugins or executable templates. File paths resolve from
the config file directory, not the shell working directory. Missing, malformed,
linked or oversized files fail before model work. Names are lowercase slugs;
checklists have 1–64 nonempty entries of at most 2,000 characters. At most 16
files of 128,000 bytes each are loaded. References must pass the configured denied
path policy and cannot contain absolute paths, home expansion, traversal or links.
Directories and FIFOs are rejected before opening. Duplicate JSON keys and names
across files fail.

The loaded registry is captured once per `load_config` call. Its content and
file references enter the configuration digest. Changing a checklist invalidates
old review/readiness evidence on reload. Saving preserves references and only the
original inline definitions, so deleting a file definition removes it on reload.
A save checks the destination's referenced files against the captured snapshot.
The dashboard and CLI share the same persistence representation.
`init --output` materializes resolved definitions and clears file references, making
copies portable across directories. Library callers supply `profiles` directly or
use `load_config` for files; a raw `Config(profile_files=...)` fails explicitly with
`profile_files_require_load_config` instead of silently ignoring references.
The fixed authority instructions remain outside all custom checklist content.

## GitHub Enterprise

Set `github_host` to a lowercase DNS name such as `git.example.com`. The same
fixed metadata GETs pass it as a literal `gh api --hostname` argument. The GitHub
CLI selects the Enterprise API prefix and consumes its existing authentication;
the assistant does not log in, extract a token, change TLS verification or follow
model-selected URLs. Reports include the host so public and Enterprise snapshots
cannot be confused. IP literals and single-label hosts are rejected. Public
`GH_TOKEN`/`GITHUB_TOKEN` values are used only for github.com. Other hosts use
existing per-host CLI authentication or explicitly supplied Enterprise token
variables; for .ghe.com the selected Enterprise credential is mapped to gh's cloud
variable, without forwarding the public token. `allow_network` and `--allow-network` are still both required.
See the [GitHub CLI API reference](https://cli.github.com/manual/gh_api).

## Validation errors

`invalid_denied_parts`, `required_denied_parts_missing`, `invalid_text_suffixes`,
`invalid_github_host`, `invalid_profiles`, `invalid_profile_name`,
`invalid_profile_checklist`, `unknown_profile` and `invalid_profile_files` identify
policy configuration problems. `profile_file_unavailable`, `profile_file_invalid`,
`profile_file_too_large` and `duplicate_or_invalid_profile_file` identify file
loading problems. Errors never print file contents, credentials or private paths.
Only the local `doctor --policy` preflight names changed paths, and never their contents.
An allowed/protected prefix must also satisfy the configured path policy.
Configuration files are bounded to 2 MB. Budget values must be finite and nonnegative;
limits must be integers from 1 to 2,000,000. A limit error names the option and its
allowed range, for example `{"code":"invalid_limit","option":"max_file_bytes","minimum":1,"maximum":2000000}`.

`max_packet_bytes`, and a gate policy's `max_request_bytes`, may go up to 8,000,000 for a range too
large for anything smaller. A packet holds the earlier and later text of every changed file, so a
range that touches large files is much larger than its diff. Before raising either limit, check
what the preflight can't:
- **The model's context window.** Source code runs at roughly three to four bytes per token.
- **`timeout_seconds`.** A large request takes longer to answer.
- **`max_run_usd`.** The spend reserve counts about one token per byte of request.
Unknown configuration keys are rejected.

`finassist doctor` reports defaults unless you pass `--config`, and says so in
`config_source`. Its `config_warnings` list settings that have no effect:
- **`config_file_not_loaded`:** a `finassist.json` is present but was not passed with `--config`.
- **`text_suffix_always_denied`:** a `text_suffixes` entry, such as `.csv`, that the
  built-in deny list always refuses. Admit synthetic fixtures with `fixture_roots` in a
  gate policy instead.
- **`provider_prices_missing`:** a paid provider whose prices are zero. Reviews are
  refused until both are set.

## Editor schema

The [published JSON Schema](../schemas/finassist.schema.json) is generated from
`Config` fields, type annotations, defaults and field constraint metadata. Regenerate
it with `python scripts/generate_config_schema.py`; CI tests compare both public
and packaged copies and validate the examples. `$schema` in config is an optional
editor hint, ignored after parsing and never fetched by the CLI. Editors may fetch
schemas under their own settings. The schema checks structure and documented basic
limits; runtime validation additionally checks private paths/content, endpoint
approval, profile files and cross-field policy. Schema validation alone is not
approval to send source or run a recipe. Forks can use a local schema copy and
change its `$id` when publishing their own version.

## Limits

Configuration selects policy; it does not authorize a network request, recipe execution or patch application. Runtime checks remain authoritative after editor validation. Screening cannot prove confidentiality, generated exclusions require independent source/build verification, and local budget admission cannot enforce provider billing. See the [threat model](threat-model.md).
