# Using finledgerpoli as a pre-merge gate

An external gate can run one unattended model-review component through the same
core locally or in GitHub Actions. This requires an explicitly reviewed version-2
model policy. The default configuration remains offline. Version-1 check policies
retain their existing behavior, including blocking required model review.

This component reviews committed source and executes no candidate code, checks,
patches, merges or financial operations. Pair it with your deterministic checks
and your project's approval process. PASS means this component completed under
its policy; it does not mean financial correctness or permission to merge.

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
pattern screening cannot establish those properties. Credential-bearing key labels
(`secret_key`, `aws_secret_access_key`, `access_key` and labels containing private,
signing, encryption, client, master, auth or api) are screened when their values
meet the length/shape threshold. Bare `key` and database/cache/idempotency key
labels are not treated as credentials. The added rule excludes unquoted calls,
dotted identifier references and identifier-shaped annotations; quote literal
credential values to make their intent explicit. Identifier-shaped values followed
by `(` stay excluded, while non-identifier literals remain screened. Existing
password/secret/token patterns retain their prior behavior. Short or differently
formatted secrets can still escape screening; inspect outgoing requests yourself.
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
Source paths, fixture roots and fixture paths refuse format controls and pinned
Unicode18 default-ignorable characters, including embedded zero-width spaces.
Reserved directory and private-filename comparisons use compatibility normalization,
case folding, trailing-dot/space removal and a pinned ASCII-target Unicode18
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
breaks are flattened. Invisible control characters are refused. Output paths
must be new. No PR comment is posted and no source is executed. The Action still
publishes metadata-only summaries; claims and notes remain in private artifacts.
Inspect content for confidentiality before choosing to share a generated trace;
escaping markup does not remove private information from human notes.

`score --report` returns disposition counts and a completeness flag, never
precision or recall. Missing judgments remain unresolved; a blocked review is
never complete even if it returned no findings. Human dispositions do not change
the original gate verdict or grant merge/deployment authority. Existing
`score --evaluation --labels` contracts are unchanged; evaluation/compare flags
cannot be mixed with report/adjudication mode.

## Confidential numeric tokens (policy-approved model gate)

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

For example, the synthetic `6729102.50` and `$6,729,102.500` normalize to
`6729102.5`, whose SHA256 is
`5717d161608c9711d081c00901d8091210e5c7f00a77f0493cb873a8ba0f82b7`.
Normalization uses decimal strings without floating-point rounding. It accepts
Unicode decimal digits; an optional `$`, `€`, `£` or `¥` prefix; signs or
accounting parentheses; dot decimals; comma or consistently spaced groups of
three digits (ASCII space, NBSP or narrow NBSP); and decimal exponents up to
absolute value 128. At most 128 digits are accepted. Leading integer zeros and
trailing fractional zeros are removed; integer trailing zeros are preserved.
Normalization preserves signs except for zero, but screening compares magnitude:
a listed figure refuses regardless of sign, accounting parentheses or function-call
parentheses. A plain digit-bounded pass also screens punctuation and CSV neighbours.
It fails closed on short figures: listed `234` also refuses `1,234`; `0`, `1` and
`12` can refuse ordinary constants. A longer uninterrupted digit sequence such as
`91234567.89` does not match listed `1234567.89`. Decimal commas, spelled-out amounts,
hexadecimal, underscores and alternative encodings are not supported numeric
forms. This is a bounded numeric screen, not a proof that arbitrary source
cannot encode a confidential figure.

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
