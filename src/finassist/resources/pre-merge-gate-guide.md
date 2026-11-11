# Using finledgerpoli as a pre-merge gate

An external gate can run one unattended model-review component through the same
core locally or in GitHub Actions. This requires an explicitly reviewed version-2
model policy. The default configuration remains offline. Version-1 check policies
retain their existing behavior, including blocking required model review.

This component reviews committed source and executes no candidate code, checks,
patches, merges or financial operations. Pair it with your deterministic checks
and your project's approval process. PASS means this component completed under
its policy; it does not mean financial correctness or permission to merge.

For automation, `gate run` is the one command to call. It plans, screens, sizes the request,
reserves the budget, calls the model and writes the report in one step. `plan` and `review` are
the manual flow, for a person who inspects and approves each request. Before the first run,
check the range with [`doctor --policy`](#checking-readiness-first); see also [your first run](first-run.md).

## Reviewed policy and exact request

Start with [the generic example](../examples/model-gate/policy.json). Replace the
provider, model, exact endpoint/allowed host, variable name, prices and limits
with reviewed values. Its example model name is a placeholder, not a live-tested
model or pricing recommendation. Empty `blocking_severities` means advisory
findings; list severities explicitly to make those findings fail the component.
The existing OpenAI, Anthropic, Google, compatible and Ollama protocol adapters
are available; protocol compatibility depends on the selected provider/model.

Commit the policy through your normal protected-base review process first.
Pin the SHA-256 of its **exact raw bytes**, including whitespace and newline.
The policy is always read from `--base`; a PR-head policy edit cannot authorize
itself. Policy edits and ignore-rule edits block this component pending separate
review. Policy paths and source allow/deny rules are exact file paths or literal
directory prefixes ending in `/`, with no glob syntax.

The policy explicitly binds provider, model, endpoint/host, `api_key_env` (NAME
only), allow/deny scope, file count, file bytes, serialized outgoing JSON body
bytes (including protocol envelope/schema), profile, output-token/time bounds,
prices, per-run/daily caps and blocking severities. Header credentials and
transport/TLS framing are outside `max_request_bytes`; it limits the JSON body.
Screening cannot be disabled. Data, environment, credential, household/client
configuration, private formats and Git-ignored source are refused. Both source
versions are screened. Forced tracked files are still checked against ignore
rules from the current checkout, immutable base and merge base. Pattern-based
screening cannot prove confidentiality; the policy owner must review the scope.

Only after the rules and reservation budget checks pass does the audit record
`request_approved`, with `approved_by: policy`, `policy_sha256` and
`request_sha256`. The request hash binds POST, exact destination, header names,
fixed protocol headers and the hash of the exact serialized body, including the
system instructions, schema, model, source and profile. Authentication values
are excluded from this public identity; the named process variable is their
authority. The provider rechecks the request hash immediately before dispatch.
There is no approve-packet bypass or automatic provider fallback.

## Project-owned review profiles

The v2 `model_review` object keeps the required `profile` name. With no custom
text it selects a shipped built-in checklist (`general`, `finance-saas`,
`investment-research` or `quant-review`). To own the checklist, use either
`profile_text` or the pair `profile_path` / `profile_sha256` in that same object.
Do not supply both forms. Other required policy fields remain unchanged.

For example, add these fields to your reviewed `model_review` object:

```json
{
  "profile": "project-review",
  "profile_text": [
    "Trace cent rounding through preview, booking and final balances.",
    "Use the project's approved objective and constraints; flag missing canon."
  ]
}
```

Alternatively, set `profile` to `project-review`, `profile_path` to a committed
file such as `docs/review-checklist.txt`, and `profile_sha256` to the lowercase
SHA-256 of that file's **exact raw bytes**. The file is UTF-8 plain text: each
nonblank line is one instruction; blank lines are omitted. It is read from the
same base commit as the policy, never from the worktree or PR head. Update and
review the file and its policy pin together on the protected base first, then
refresh the caller's policy-byte pin. Editing, deleting or renaming that profile
in the PR blocks with `gate_profile_change_requires_review`, even when it is
outside the source `allow_paths`. A missing file or mismatching pin also blocks.

Compute file pins from the committed blob, including its original line endings:

```sh
git cat-file blob BASE:docs/review-checklist.txt | sha256sum
# macOS alternative:
git cat-file blob BASE:docs/review-checklist.txt | shasum -a 256
```

Copy only the 64 hexadecimal digest characters into `profile_sha256`. These
stdin commands also print a filename field (`-`, shown as a trailing ` -` after
the digest/spacing); that suffix is not part of the hash. Hash exact Git blob
bytes, not a working-tree copy with potentially different line endings.

Replace `BASE` with the reviewed full commit SHA. Do not hash a CRLF-converted
working copy. The policy pin similarly binds its exact committed blob bytes.

Both forms accept 1–64 nonblank instruction lines, at most 2,000 characters per
line. Each inline string must be exactly one line, including no trailing newline
or Unicode line separator. Instruction lines reject Unicode control/format
characters (`Cc`, `Cf`, `Zl`, `Zp`), including BOM and zero-width-only content;
ordinary visible Unicode text is preserved. A leading UTF-8 BOM or a tab-indented
line refuses the entire profile file with `gate_profile_line_invalid`; neither
is silently stripped. Only LF/CRLF delimit physical profile lines before validation.
A profile file is capped at 128,000 bytes, and inline
text counts toward the policy blob's existing 128,000-byte cap. Files must pass
the mandatory text-path, UTF-8, Git-object and sensitive-content checks. Links,
private/client/data paths, explicit policy `deny_paths`, and ignored files are
refused, including immutable
base/merge-base ignore rules removed from a dirty checkout. Custom text is
included in the existing serialized request-size limit and exact request hash.
Instructions never load code, read a local `profile_files` path or bypass screening.

The custom text defines the named checklist (it may replace a built-in name).
The fixed evidence-first reviewer preamble remains; the built-in `general`
checklist is also prepended unless the selected name is `general`. To own all
checklist lines, select `general` with your custom text. Neither form confers
merge, execution or financial authority: the gate report schema fixes
`merge_authority` to `false`. Profile text has **policy-author trust**: a hostile
checklist can suppress useful findings despite the fixed preamble, but cannot
grant execution or merge authority. Protect the profile and policy with
`CODEOWNERS` and require trusted review of changes. Human-maintained checklists
still need review for confidential content, correctness and consistency with project canon;
pattern screening cannot establish those properties.

Secret and confidential-figure screening is a backstop, not the control that keeps
data private. The primary controls are the path allowlist, keeping secrets in
gitignored files or a secret manager, and a policy that keeps client data out of
reviewed source. A pass means only that no rule matched.

In parseable `.py`/`.pyi` source, credential screening reads code with Python's own
parser. A credential-named target given a literal value is refused: an assignment,
typed assignment, walrus target, keyword argument, function default, dictionary
key, attribute or subscript, including a literal fallback in `os.getenv(NAME, ...)`
or `os.environ.get(NAME, ...)` and a literal `default=` argument. Credential names
use the label vocabulary below: a name matches when it ends with a credential word,
at any length and whatever characters come first. A string or numeric value must
have at least 12 characters, counted in its source spelling; account and routing
numbers need at least six digits, and integers count by magnitude. Type
annotations are never inspected, so a `signing_key` field annotated
`Ed25519PrivateKey | None` passes. Unquoted names and call results are not literals and pass. Comments,
docstrings and other string text are screened with the text rules, and known
secret formats are screened across the whole file. Python that does not tokenize
and parse keeps the strict text rules.

Other files (YAML, JSON, Markdown, TypeScript, Kotlin and so on) use the text
rules. Credential-bearing key labels (`secret_key`, `aws_secret_access_key`,
`access_key` and labels containing private, signing, encryption, client, master,
auth or api), and password, secret, API-key and access/GitHub-token labels, are
screened when their values meet the length/shape threshold. Bare `key` and
database/cache/idempotency key labels are not treated as credentials. The
credential-key text rule excludes unquoted calls, dotted identifier references and
digit-free uppercase-leading whole identifiers. The whole-identifier exclusion ends
at whitespace, end of input or annotation punctuation such as `[`, `]`, `)`, `,` or
`;`; `/`, `+`, `=`, `-`, `:` and `@` continue a candidate literal. Uppercase-leading
unquoted literals containing digits are screened. Custom patterns apply to every
file, and known formats and custom patterns also read the complete serialized packet
the model receives. Original source/request bytes are kept. Review output may quote exact credential-label
matches from screened annotations in that request. The view preserves the label
and masks the complete recorded annotation, including unions, so a value appended
after `=` still undergoes assignment screening. Shorter `label: Type` quotes pass;
unrecorded union/subscript continuations are refused conservatively. Patches screen complete post-images with their paths before target writes;
active-policy rollback screens both versions with their paths.

Known limits of the text rules, which are no longer extended:

- A typed assignment in non-Python text, such as `password: str = "..."` in a
  Markdown code block, is not detected.
- A credential-named label followed by a digit-bearing type name, such as
  `signing_key` annotated `Ed25519PrivateKey`, is refused in Markdown, YAML,
  TypeScript or Kotlin.
- Digit-free all-caps unquoted values resemble constants and are not detected.
- Labels outside the vocabulary (for example `auth_token` or `pwd`) and values
  shorter than the threshold are not detected.
- Values split across lines, encoded or built at runtime are not detected.

Known limits of the Python check: values computed at runtime (concatenation,
variables and calls other than the two fallback forms above) are not literals and
pass, and a credential written as a type annotation is not inspected.

Quote literal credential values to make their intent explicit, and inspect
outgoing requests yourself.
Profile selection and authorization contracts remain unchanged; common text
screening also applies to version-1 checks and manual review.

For a history suite selecting a separate policy repository or commit, the profile
comes from that policy selection and its immutable ignore rules also apply.
A source file at the same relative path in a different repository remains source
data; it cannot replace the policy profile. Same-repository profile changes stay
guarded. The ordinary CLI/CI gate still has no separate-policy override.

## Policy-owned synthetic text fixtures

Text-fixture exceptions are off by default and belong only to a reviewed,
base-pinned policy. In a v2 policy, add `fixture_roots` and optionally
`fixture_max_file_bytes` to `model_review`. A v1 checks policy uses the same fields
at its top level, beside `config`; ordinary local configuration cannot grant this
capability. For example:

```json
{
  "fixture_roots": ["packages/engine/tests/fixtures/prices.csv", "synthetic-firm/"],
  "fixture_max_file_bytes": 48000
}
```

Each root is an exact repository-relative file or a literal directory prefix
ending in `/`. Globs, absolute paths and `..` are refused. Policy load checks
the root's own Git entry (when present) and refuses links/special objects there;
it does not walk each parent Git entry. A nested structural root below a linked
parent can therefore pass this declaration check. All content reads use Git
objects and never follow working-tree links; this is not permission to traverse
a host symlink or to include its target. The match is literal:
`tests/fixtures/public/` does not cover
`tests/fixtures/public-extra/`, and an exact CSV does not admit its siblings.
Only `.csv`, `.tsv`, `.yaml` and `.yml` qualify for the text-fixture exception.
Other denied formats remain denied. Ordinary source `allow_paths`, v2
`deny_paths`, coverage accounting and request/packet byte caps still apply.

A root qualifies when one complete component is exactly `tests` or `fixtures`
(nested roots such as `packages/x/tests/fixtures/` qualify; `tests-old/` does not).
Case aliases are refused: `Tests/fixtures/` and `src/App.Tests/Fixtures/` are
invalid roots even with a valid marker. Use the exact lowercase components.
Otherwise place `.finledgerpoli-synthetic` in the listed directory, or beside an
exact listed file, with its first line exactly:

```text
synthetic: true
```

Commit and review this UTF-8 marker on the pinned base before enabling the root.
The marker is read only from that Git commit, capped at 4,096 bytes and screened;
a marker in the working tree or PR head cannot qualify a root. Refusals retain
the underlying safety code:

| Marker failure | Reason |
| --- | --- |
| Missing, invalid UTF-8 or nonexact first LF-delimited line | `fixture_root_unqualified` |
| Link, tree or other nonregular Git object | `linked_or_special_git_object` |
| More than 4,096 bytes | `file_limit_exceeded` |
| NUL byte | `binary_input` |
| Sensitive-content pattern | `sensitive_content` |

Every refusal stops before provider dispatch. Candidate marker content edits,
deletions, mode changes and symlink replacements require separate policy review.
A candidate forked before the current base marker existed is also stale and must
be integrated/reviewed against that base; it cannot inherit marker authority
while omitting the marker from its own tree. As with other guarded changes, the
model gate reports `gate_fixture_marker_change_requires_review`, while the
checks gate reports `ci_guarded_change_requires_review`. Marker bytes are never
provider context or recipe inputs. History evaluations use the selected policy repository
and commit for this qualification, as for their policy-owned review profiles.

Every `data` component remains refused, case-insensitively, with
`fixture_root_contains_data`, even inside a listed root. Private, client,
household, holdings and credential locations, ignored paths, non-UTF-8 or NUL
content, secret patterns and special Git objects remain refused. Both changed
versions are screened; deterministic recipes use screened committed snapshots.
The allowance is the policy author's attestation that the data are synthetic.
Neither the path nor the marker proves confidentiality: review their contents
and guard the policy and marker with trusted review/CODEOWNERS.

`fixture_max_file_bytes` defaults to 48,000 and has a hard ceiling of 2,000,000.
It applies per version of a listed text fixture, independently of the policy's
ordinary `max_file_bytes` (also capped at 2,000,000). For example, a reviewed
`max_file_bytes` of 200,000 can admit a large source module while fixtures retain
the 48,000-byte default. Byte limits are enforced during construction, packet
revalidation, model dispatch and recipe staging. Raising either limit does not
raise the total request/packet caps or change offline/approval/budget defaults.

## Checking readiness first

Before the first `gate run` on a range, run the preflight:

```sh
finassist doctor --policy gate-policy.json --repo . --base BASE --head HEAD
```

It reports every blocker the gate would hit for that range in one run, each with a
`hint`, and exits 0 when the range is ready and 1 when it is blocked. It also lists:
- **Each changed path** as `included`, `refused` (with the code and any limit or size)
  or `unchecked`. A path is `unchecked` when a screening step can't run, for example an
  unreadable token file, too many files, an ignored profile or fixture marker, or a
  change in the range to the policy, its profile, a fixture marker or a `.gitignore`
  file. These stop the gate before it reads content, so the preflight reads none
  either. An ignored changed file is refused and named. At most
  2,000 paths are listed. Path refusals are grouped by code, each with a `count` and
  up to 20 example `paths`. A changed name that isn't UTF-8 is counted, never shown.
- **Every policy schema error,** with its field and allowed values. Current values are never echoed.
- **The size of the exact request body** against `max_request_bytes`.
- **The reserved spend estimate** against `max_run_usd` and `daily_budget_usd`.
  Spend already recorded in a state directory is not read.
- **The policy's sha256 at base,** to pass as `--policy-sha256`. The full commit hashes
  `gate run` needs are given too.
- **Whether the key variable is set.** The preflight checks that it is set, never its value.
- **Settings that have no effect,** such as a prefix that matches no file.

The preflight makes no network call, reads no key value, opens no ledger and spends
nothing. Path names appear only in its local output, and a name that fails
screening is shown as `[redacted]`. They never enter a packet, gate report or audit
row.

The pin decides what the policy may make it read:
- **A supplied `--policy-sha256` that is invalid or does not match.** Only checks on
  the policy bytes run. Nothing the policy selects is read.
- **No pin.** The policy's sha256 is shown, but a `forbidden_token_file` outside the
  repository is not opened until you confirm the policy with `--policy-sha256`.
- **A policy that fails screening, path rules, fixture rules or its profile.** Its
  blockers are reported, and nothing else it selects is read.

Once its own checks pass, it runs the gate's policy loader and source builder
too, so `ready` means `gate run` will accept the range up to the provider call. The
provider's answer, the key's value and prior spend are not checked.

### A past range, before the policy was committed

The gate reads its policy only at `--base`, so a range whose base predates the policy
can't be preflighted with `--policy`. To try a policy on such a range, give the
preflight a file on this machine instead:

```sh
finassist doctor --policy-file gate-policy.json --repo . --base BASE --head HEAD
```

It runs the same checks, with three differences:
- **It authorizes nothing.** The report shows `policy.source: "working-tree"` and a
  `policy_from_working_tree` warning, and a `ready` range gets no `gate run` command.
  `gate run` has no `--policy-file`; it still reads only the pinned policy at base.
- **The pin is optional.** `--policy-sha256` is checked against the file's bytes when you
  pass it, and a `forbidden_token_file` is opened only once you do, as with `--policy`.
- **What the policy selects is still read at base:** its profile file, fixture markers
  and ignore rules, as the gate would read them for that range.

Pass `--policy` or `--policy-file`, not both. If either names a finassist.json
configuration, the preflight says so with `gate_policy_is_configuration`; `--config`
likewise refuses a gate policy (`config_is_gate_policy`) or a CI policy
(`config_is_ci_policy`).

## Calling it locally

Use trusted installed package code, outside candidate-controlled imports:

```sh
python -I -m finassist gate run --policy gate-policy.json \
  --policy-sha256 REVIEWED_RAW_BYTE_SHA256 --repo . \
  --base FULL_BASE_SHA --head FULL_HEAD_SHA \
  --state-dir PRIVATE_RETAINED_STATE --output NEW_PRIVATE_REPORT.json
```

Only the process environment supplies the key. No dotenv file is loaded and no
key goes in command arguments. A [generic caller](../examples/model-gate/caller.py)
shows how a parent process maps a named private variable into a minimal child
environment. Set that variable through your existing secret facility; do not
put its value in source, shell history or logs. Never execute the caller from
untrusted candidate code with a key present. The direct CLI also checks trusted
Actions event metadata when `GITHUB_ACTIONS=true`; do not strip it to avoid a
fork check. Use the Action adapter in Actions.

The state directory is mandatory and private. Retain the **same ledger** across
calls that share a daily budget; serialize access or share the SQLite database
on a filesystem that supports its locking. Caps are per ledger and UTC day,
based on configured prices and reported usage. This v2 model policy exposes
run and daily limits, with no operator-selected monthly cap; manual review's
`monthly_budget_usd` setting is not configurable through this policy version. A
fresh hosted runner with fresh
state does not enforce a project-wide daily cap. Caller retention, access
control, reliable filesystem locks and accurate prices remain prerequisites.
There is no new hosted state service or provider-enforced billing guarantee.

Missing usage, timeout and uncertain calls remain reserved, block readiness and
block the next policy-approved call, including across day/month changes. No
automatic retry occurs. Use the existing audit/reconcile-budget commands against
this same state only after verifying actual billing; never delete/reset a
ledger to retry. A conservative request-byte estimate plus envelope allowance
is reserved before HTTP; provider accounting may exceed that estimate. An
over-bound usage report blocks completion and retains the reservation.

## GitHub Actions

Pin trusted finledgerpoli action source to a reviewed full commit SHA. Check out
the target PR without persisting credentials; do not install its package on the
runner. In your existing `pull_request` workflow, map your existing Actions
secret into the exact variable named by the policy and invoke `actions/gate`
with `mode: model-review`, `policy-path`, `policy-sha256`, `repository-path` and
`state-directory`. The same core evaluates the request and report as the CLI.

Guard the key-bearing step with a same-repository PR condition, such as
`github.event.pull_request.head.repo.full_name == github.repository`, and map
`REVIEW_PROVIDER_KEY` to your secret through the step's `env`. Never grant a
fork that key. The adapter independently rejects fork events before reading
the named key. It accepts only the narrow `pull_request` context, never
`pull_request_target`; do not run candidate scripts, local actions or install
hooks in a key-bearing job. Workflow isolation and trusted caller wiring remain
part of the boundary, not something this source-review tool can enforce.

Supply a caller-managed private retained state directory explicitly, using an
**absolute path outside both RUNNER_TEMP and GITHUB_WORKSPACE**. The adapter
refuses relative paths that would resolve inside its disposable bootstrap
directory, temporary state paths and candidate-controlled checkout state. With
ephemeral hosted runners, arrange trusted retention and serialization yourself
before enabling paid unattended review. Do not restore budget/audit state from
untrusted PR-controlled caches. No persistence backend, secret or workflow is
created by this feature. Default `mode: checks-only` preserves the v1 adapter.

## Withheld private paths

A policy can set `"private_paths": "skip-and-report"` in `model_review`. Private paths in
the range are then withheld unread instead of refusing the run, and the report adds
`coverage: {complete: false, withheld: N}`. The default, `refuse`, keeps the run blocked.
- **A private name comes first:** a private file with a suffix no review reads, such as a `.jsonl`
  file under `data/`, is withheld like any other private path. Before, it refused the run.
- **Where the path sits:** a private path is withheld whether or not `allow_paths` covers it,
  since `allow_paths` only admits files for review. One under `deny_paths` still refuses the run,
  and so does any other changed file outside `allow_paths`.
- **A PASS covers only what was reviewed:** the Actions summary says coverage is incomplete, and
  the action's `withheld-count` and `coverage-complete` outputs carry the count. Readiness and the CI
  check gate still refuse incomplete coverage.
- **The preflight** lists withheld paths as `withheld`, warns with `private_paths_withheld`, and
  doesn't treat them as blockers.

See [skipping private paths](configuration.md#skipping-private-paths).

## Files that cannot be reviewed

A policy can also set `"unreviewable_paths": "skip-and-report"` in `model_review`. A changed file
with an unsupported suffix, over `max_file_bytes`, not UTF-8 text or outside `allow_paths` is then
left out instead of refusing the run. The default, `refuse`, keeps the run blocked.
- **The reviewer is told:** the request names each file left out with its reason. A private path is
  never named; it is refused, or withheld under `private_paths: skip-and-report`.
- **The count is one number:** `coverage.withheld` counts every changed file that was not reviewed,
  private or left out, and the Actions summary and the `withheld-count` output carry it.
- **What still refuses:** `deny_paths`; a change to the policy, the profile, a fixture marker or a
  `.gitignore`; credential content; a listed figure; and a range with nothing left to review.
- **The preflight** lists each file left out as `omitted` with its reason, warns with
  `unreviewable_paths_left_out`, and doesn't treat them as blockers.

See [leaving out files that cannot be reviewed](configuration.md#leaving-out-files-that-cannot-be-reviewed).

## Placeholder credentials in test files

A policy can list test files whose credential-named values are made up, in
`"placeholder_credential_paths"` under `model_review`: directory prefixes ending in `/`,
exact paths, or patterns with `*`. The credential label rule is then not applied to those
files, so a fixture with a made-up login no longer blocks the run. Known formats, account
numbers, listed figures and `extra_sensitive_patterns` still refuse there, and the files
are sent as they are. The preflight lists each such file with
`credential_labels: not_screened` and warns with `credential_labels_not_screened`.

See [placeholder credentials in test files](configuration.md#placeholder-credentials-in-test-files).

## Example policies

Two complete version-2 policies with synthetic values show common shapes. Both are in
`finassist export-kit` under `examples/policies/`.

| Example | Shape | Private paths |
| --- | --- | --- |
| [quant-engine.json](../examples/policies/quant-engine.json) | A Python pricing and risk engine with synthetic price fixtures and a `data/` directory | `skip-and-report`: files under `data/` are withheld unread, and coverage is reported incomplete |
| [rebalancer.json](../examples/policies/rebalancer.json) | A Python engine with a TypeScript web app | `refuse`, the default: any private file in a range refuses it |

`allow_paths` must cover every directory a pull request may change, because the gate refuses
a range that changes a file outside it or under `deny_paths`. That is why both examples
include `docs/`, and why the quant example includes `data/`. Replace the provider, model,
prices and budgets with your own before you commit a policy, then preflight it with
`doctor --policy`. The `finassist-setup` skill in `finassist export-kit` walks an agent
through these choices with the person.

## Verdict contract

The [version-2 report schema](../schemas/model-gate-report.schema.json) defines:

| Verdict | Exit | Meaning |
| --- | --- | --- |
| PASS | 0 | Complete validated model response, known usage, no configured blocking severity |
| FAIL | 1 | Validated advisory findings include a configured blocking severity |
| BLOCKED | 2 | Policy, screening, context, budget, transport, usage, evidence or audit incomplete/refused |

Reports bind base/head, policy/request/report hashes, reasons, token usage and
reserved/actual estimated spend. Unknown fields are `null`, never fabricated
zeros. Structured findings contain severity, file, line, bounded screened claim
and `source-reference-validated-not-reproduced`. Citations identify supplied
source; they do not prove the claim. Full provider response, proposed
reproductions and source blobs are omitted. The summary is fixed text; Actions
summaries/stdout/outputs contain only verdict, fixed reason codes and report
identity, never claims, source or provider text. Private report findings remain
untrusted model content; do not execute them or render them as workflow commands.
Output paths must be new. Invalid CLI syntax or unwritable/existing outputs also
exit 2; these failures may prevent creation of a report file.

Tests use synthetic source and fake transports. No live provider validation,
financial approval, production secret setup or merge authorization is implied.

Profile instructions accept visible Unicode letters, marks, numbers, punctuation
and symbols plus ASCII space. Invisible fillers (including U+13441, U+13442,
U+16FE4 and U+1BC9D), variation selectors, private-use, unassigned and surrogate
characters are refused. Emoji sequences containing VS16, such as the common
VS16 keycap spelling, or a zero-width joiner are refused. Plain visible emoji,
combining accents and keycaps without a variation selector remain permitted.
File instructions use LF or CRLF physical lines; other separators are refused
rather than creating instructions.
Synthetic markers require exactly `synthetic: true` before the first LF (or EOF).
Source paths, fixture roots and fixture paths refuse control and format characters,
line/paragraph separators and pinned Unicode 18 default-ignorable characters,
including embedded zero-width spaces.
Reserved directory and private-filename comparisons use compatibility normalization,
case folding, trailing-dot/space removal and a pinned ASCII-target Unicode 18
confusable table. Thus Cyrillic-letter spellings of `data` or `client`, `holdings.`,
`secrets .`, `client.json.` and `auth.json.` do not bypass their privacy checks.
These comparisons can conservatively refuse visible lookalikes; they do not detect
every possible visual spoof or prove that other paths contain public data. The
actual Git names and request hashes are preserved. Enabling fixtures does not add
fixture-only private-path restrictions
to ordinary files in a v1 checks snapshot; all original screening still applies.


## Finding identities and human trace tables

New model gate reports use `schema_version: 2` with a required `id` on each
finding. Both `gate run` and the Action use the same report core. An ID is
`f-` followed by SHA256 of canonical JSON containing `request_sha256`, the
zero-based `index` and the public `finding` projection (severity, file, line,
claim and evidence_status, excluding id). This preserves the history ID format
while binding new IDs to the exact request. Identical requests and ordered
findings have identical IDs; reordered, changed or duplicate findings have
position-specific IDs. A model may produce different findings on a rerun.

New history evaluations copy the gate IDs. Archived history evaluations and
labels remain valid as stored; they are not rewritten. The validator also reads
strict legacy v1 gate reports, which have no id. The trace command derives new
request-bound IDs for those reports and marks this conversion in its output.
Older readers that only support v1 need updating before consuming v2 reports.
The strict legacy schema is published as `schemas/model-gate-report-v1.schema.json`
and included at that path in `finassist export-kit`.
Report hashes remain hashes of the exact complete report, including new IDs.

Use a private local JSON mapping from full finding ID to outcome and note:

```json
{
  "f-REPLACE_WITH_THE_FULL_FINDING_SHA256": {
    "outcome": "Confirmed",
    "note": "Reproduced with the reviewed synthetic check."
  }
}
```

Allowed outcomes are `Confirmed`, `Partly right` and `Refuted`. Notes are limited
to 2,000 characters. Omit a mapping entry to leave a finding `Unresolved`.
Unknown IDs, invalid outcomes, extra fields and duplicate JSON keys are refused;
a mapping for another request cannot silently adjudicate this report. Input
files are bounded to 1 MB. Hashes bind bytes, not reviewer identity or truth.

```sh
finassist report trace --report .finassist/model-gate.json \
  --adjudications .finassist/adjudications.json --output .finassist/trace.md
finassist score --report .finassist/model-gate.json \
  --adjudications .finassist/adjudications.json --output .finassist/dispositions.json
```

Both commands are offline; `--adjudications` is optional. The Markdown table has
columns `#`, `Reviewer claim`, `Trace` and `Result`, including the full finding
ID and file:line. Model text and notes are escaped as plain table text and line
breaks are flattened. Mentions, `#<n>` references and case-insensitive `GH-<n>`
references are separated with generated zero-width entities to prevent rendered
autolinks. Invisible control characters are refused. Output paths
must be new. No PR comment is posted and no source is executed. The Action still
publishes metadata-only summaries; claims and notes remain in private artifacts.
Inspect content for confidentiality before choosing to share a generated trace;
escaping markup does not remove private information from human notes.

`score --report` returns disposition counts and a completeness flag, never
precision or recall. Missing judgments remain unresolved; a blocked review is
never complete even if it returned no findings. Human dispositions do not change
the original gate verdict or grant merge/deployment authority. Existing
`score --evaluation --labels` contracts are unchanged; evaluation/compare flags
cannot be mixed with report/adjudication mode. Supplying `--adjudications` with
`--evaluation --labels` returns `score_input_mode_conflict` before reading inputs.

## Confidential numeric tokens (policy-approved model gate)

`plan`, `review` and `propose` run the same screen when the configuration sets
`forbidden_token_file` or `forbidden_token_hashes`; see "Confidential figures" in the
configuration guide. This section describes the gate, and the matching rules both share.

The optional base-policy `model_review.forbidden_token_file` names an absolute,
operator-controlled file outside both the source and policy repositories and
Git administrative directories. The strict UTF-8 file contains one numeric
literal per line (LF or CRLF, optional final newline). Empty files/lines,
malformed numbers, a BOM, links, multiply linked files, special files, unavailable
files and repository-contained paths refuse the request. Limits are 128 KiB,
1,024 lines and 256 characters per literal. Keep this file private; do not
commit it, upload it as an Action artifact or place it in a packet.

Alternatively, `model_review.forbidden_token_hashes` accepts 1–1,024 unique,
lowercase SHA256 hashes of canonical numeric strings encoded as UTF-8. If both
options are declared, their deny sets are combined. Neither option changes
network authorization, provider selection, approval or budget requirements.
Hashes of low-entropy numbers can be guessed; they are not encryption.

For example, the synthetic `6729102.50`, `$6,729,102.500` and `6_729_102.50` normalize to
`6729102.5`, whose SHA256 is
`5717d161608c9711d081c00901d8091210e5c7f00a77f0493cb873a8ba0f82b7`.
A list entry is normalized as a decimal string, without floating-point rounding. An entry
may use Unicode decimal digits; an optional `$`, `€`, `£` or `¥` prefix; a sign or
accounting parentheses; a dot decimal; groups of three digits with one consistent
separator (comma, ASCII space, NBSP or narrow NBSP); underscores between any two digits,
including `6729_102.50`, `67_29_102.50` and `6_7_2_9_1_0_2.50`; and a decimal exponent up
to absolute value 128. At most 128 digits are accepted. Leading integer zeros and trailing
fractional zeros are removed; integer trailing zeros are preserved.

In screened text, the screen reads runs of digits and the single characters between them,
and compares every number they can form with the list:

- **A whole part** is one run of digits, runs joined by underscores, or groups of three
  joined by one separator: a comma, a point, an apostrophe, or a space (ASCII, no-break,
  narrow no-break, thin or figure space).
- **A fraction** follows a point or a decimal comma, so `6.729.102,50` and `6 729 102,50`
  are read as `6729102.5`. A leading point is read too, as in `.5`.
- **An exponent** may follow, as in `6.7291025e6`.
- **Digits and marks** may be ASCII, fullwidth or Arabic.
- **Character escapes** (`\u00a0`, `\x36`) and HTML character references (`&nbsp;`,
  `&#54;`) are read as the characters they spell.

Signs, currency signs and codes, percent signs, brackets, quotes and letters beside a
number never hide it, and only magnitude is compared: a listed figure refuses whatever
its sign. Zero padding of any length never hides a value.

The screen over-reads on purpose, because a row of digits and separators can be read in
more than one way. Every start and every role of a separator is tried: listed `234` also
refuses `1,234` and `7,234,9`, and `0`, `1` and `12` can refuse ordinary constants. Three
readings are left out, because they would refuse unrelated numbers:

- **A point between digits is a decimal point first.** Listed `73026` does not refuse
  `73026.04` or `1.73026`. Digits after a point are read as a number of their own only
  when they carry their own fraction or groups: `1.48,213.57` holds `48213.57`.
- **A longer uninterrupted run of digits is another number.** `91234567.89` does not
  match listed `1234567.89`.
- **Inside a row of more than nine three-digit groups,** a figure is matched when it
  starts the row or has at most nine groups (27 digits).

Not read as figures: spelled-out amounts, a figure broken up by other text, percent-encoding
and other encodings, and, outside `.py` files, hexadecimal.

### Figure sources and digit matching

Two optional settings build the list from files you already hold, and match more than the
exact value:

- **`forbidden_token_sources`** names up to 16 delimited text files, such as custody exports:
  comma, semicolon, tab or bar separated, at most 8 MB each. Each is an absolute path, or one
  starting with `~`, outside every checkout of the repository.
  - Every cell that holds exactly one number becomes a listed figure, whatever its notation,
    sign, currency sign or code, brackets or percent sign.
  - A cell is not a figure when it has fewer significant digits than
    `forbidden_token_min_digits` (5 unless set, from 4 to 18), when it is a date, or when it
    holds other text.
  - A source with no figure is refused with `forbidden_token_source_invalid`. It is never
    treated as an empty list.
- **`forbidden_token_match`** is `value` unless set: a listed figure refuses the same value in
  any notation. With `digits` it also refuses:
  - the same significant digits at any scale: listed `48213.57` refuses `4821357`, `48.21357`
    and `0.4821357`;
  - a two-place rounding, in either direction: listed `48213.5712` refuses `48,213.57`, and
    listed `905.13` refuses `905.125`.

  Digit matching applies to `forbidden_token_file` entries and to sources. An entry in
  `forbidden_token_hashes` is always matched by value.

Digit matching leaves two things out, so that it does not refuse ordinary code:

- a figure with fewer than `forbidden_token_min_digits` significant digits;
- a run of digits inside a hexadecimal word of seven or more characters that holds a letter
  other than `e`, such as a commit id.

It still refuses more unrelated numbers than value matching does. A list of 1,000 figures
with five significant digits matches about one five-digit number in a hundred by chance.
Raise `forbidden_token_min_digits` when a large list refuses code that holds none of its figures.

Both settings work the same way in a configuration and in a gate policy. `doctor` opens a
policy's sources only with `--policy-sha256`, as it does the token file, and the budget ledger
records how many sources and figures were screened, never a path, a digest or a figure.

Every file is screened as text, because what leaves the machine is text: the tuple
`(6,729,102.50)` in Python code still reads as the figure. In `.py`/`.pyi` files, each
numeric literal, including one inside an f-string field, is also read with Python's own
tokenizer and parser and its exact value compared with the deny list. So forms the
text screen does not parse are refused too, such as underscores in any position and
integers in any base (for example a hexadecimal literal of a listed whole number).
A string or bytes literal is also screened by its value when that can differ from its source
text: a spelling escape such as `\N{DIGIT SIX}` or `\066`, a line continuation, or adjacent
literals, which Python joins.
Leading and trailing zeros never change a value, in text or in code, and values as
long as any policy entry can expand to (up to 256 digits) are compared. While screening
is enabled, a `.py` file that Python cannot tokenize is refused with
`forbidden_token_python_unreadable` instead of being screened another way. A file that
tokenizes but does not parse is refused the same way when it has such a string, or, on
Python before 3.12, f-string fields, because only the parser can read them.

This is a bounded backstop, not a proof that arbitrary source cannot encode a
confidential figure. The primary control is keeping client figures out of reviewed
source.

The gate screens complete before/after source contents, including deleted lines,
unchanged context, comments and allowed text fixtures, plus selected profile
instructions. The exempt outbound fields are the model id, schema text, allow paths, generated
paths, profile name, SHAs and modes. Only typed metadata is exempt:
a filename containing a listed figure may pass, while the same filename spelled
inside source content is screened. Ordinary mandatory privacy checks still apply.
A match returns `BLOCKED` with `forbidden_token_present`, before credential lookup
or a budget reservation. Invalid file configuration returns the generic
`forbidden_token_file_invalid` without echoing the file contents or OS error.

History evaluation screens every case before any credential lookup or dispatch.
The execution path reloads the private list before request preparation and
reservation. A changed snapshot refuses with
`forbidden_token_configuration_changed`; even an equivalent file rewrite
invalidates earlier screening. The base policy hash still identifies the exact
base policy bytes, and the request hash still identifies the exact outgoing
request. Neither hash attests the mutable private file contents. Filesystem
checks are not an isolation boundary against a malicious process running as the
same user; operators must protect the file and its parent directories.

The file contents, token hashes and private file digest are never added to the
request, report or audit. After source/request preflight passes, the private
budget ledger records only the configured path and line count in a
`forbidden_token_file_screened` event, alongside its standard event metadata.
A path matching the deny set is replaced with `[redacted]`. Early refusals create
no budget ledger or separate token-file audit record. Hash-only mode records no
file event. Provider-returned free text is screened before findings are exposed;
a refusal after a response preserves its recorded usage and settled charge.

These declarations apply to the policy-approved model gate and history callers.
They do not configure the legacy `review` or `propose` commands. When omitted, existing request
bytes and offline/model-neutral defaults are unchanged.
