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
```

Replace `BASE` with the reviewed full commit SHA. Do not hash a CRLF-converted
working copy. The policy pin similarly binds its exact committed blob bytes.

Both forms accept 1–64 nonblank instruction lines, at most 2,000 characters per
line. Each inline string must be exactly one line, including no trailing newline
or Unicode line separator. Instruction lines reject Unicode control/format
characters (`Cc`, `Cf`, `Zl`, `Zp`), including BOM and zero-width-only content;
ordinary visible Unicode text is preserved. Profile files are split into lines
before this validation. A profile file is capped at 128,000 bytes, and inline
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
pattern screening cannot establish those properties. Version-1 checks policies
and manual review configuration retain their existing profile behavior.

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
ending in `/`. Globs, absolute paths, `..`, links and special Git objects are
refused. The match is literal: `tests/fixtures/public/` does not cover
`tests/fixtures/public-extra/`, and an exact CSV does not admit its siblings.
Only `.csv`, `.tsv`, `.yaml` and `.yml` qualify for the text-fixture exception.
Other denied formats remain denied. Ordinary source `allow_paths`, v2
`deny_paths`, coverage accounting and request/packet byte caps still apply.

A root qualifies when one complete component is exactly `tests` or `fixtures`
(nested roots such as `packages/x/tests/fixtures/` qualify; `tests-old/` does not).
Otherwise place `.finledgerpoli-synthetic` in the listed directory, or beside an
exact listed file, with its first line exactly:

```text
synthetic: true
```

Commit and review this UTF-8 marker on the pinned base before enabling the root.
The marker is read only from that Git commit, capped at 4,096 bytes and screened;
a marker in the working tree or PR head cannot qualify a root. Missing or invalid
markers refuse the policy with `fixture_root_unqualified`. Marker edits/deletions
in the candidate require separate policy review; marker bytes are never provider
context or recipe inputs. History evaluations use the selected policy repository
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

The [version-1 report schema](../schemas/model-gate-report.schema.json) defines:

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
and symbols plus ASCII space. Invisible fillers, variation selectors, private-use,
unassigned and surrogate characters are refused. File instructions use LF or CRLF
physical lines; other separators are refused rather than creating instructions.
Synthetic markers require exactly `synthetic: true` before the first LF (or EOF).
Fixture roots and fixture paths reject reserved components with compatibility
Unicode spellings or trailing dots/spaces. Paths are compared without rewriting
Git names. Enabling fixtures does not add fixture-only private-path restrictions
to ordinary files in a v1 checks snapshot; all original screening still applies.
