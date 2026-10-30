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
based on configured prices and reported usage. A fresh hosted runner with fresh
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

Supply a caller-managed private retained state directory explicitly. With
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
