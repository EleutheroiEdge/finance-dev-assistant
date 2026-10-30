# Evaluating review results

Compare review results from finledgerpoli against independently reproduced synthetic cases using repeatable evaluation and scoring. Its command is `finassist`.

The versioned synthetic review suite contains cash-sign, tenant-isolation,
point-in-time and negative-control changes. `evaluate` builds reproducible
temporary Git fixtures. Only before/after source enters model context;
expected labels are held out of the prompt.

```sh
# Validate the fixture construction without any model call
finassist evaluate --suite examples/review-cases.json --output .finassist/evaluation.json

# The command prints a suite hash; inspect the suite before external evaluation
finassist --config finassist.json evaluate --suite examples/review-cases.json \
  --approve-suite YOUR_INSPECTED_SUITE_HASH --allow-network \
  --output .finassist/model-evaluation.json
```

Every live case uses the same provider budget ledger. A refusal, missing key,
invalid output or unknown billable attempt stops the evaluation; no automatic
fallback/retry occurs. Inspect the audit before starting again. Do not reset
state to bypass reserved spend.

A human independently reproduces and classifies each case using one outcome:
`confirmed-hit`, `miss`, `clean`, `false-alarm`, or `unresolved`. Write JSON with
the run's `evaluation_hash` and an `outcomes` mapping from case id to outcome,
then run:

```sh
finassist score --evaluation .finassist/model-evaluation.json \
  --labels YOUR_REVIEWED_LABELS_FILE --output .finassist/score.json
```

Scoring rejects changed evaluations, partial labels, label/type conflicts and
offline runs. It reports case recall, negative-control false-alarm rate and
unresolved cases.

For an adoption decision, also compare severity calibration, reproducible tests,
coverage gaps, prompt-injection behavior, dollars per confirmed defect and elapsed
time on identical frozen tasks. Retain failures and repeated trials. A second
model is worthwhile only if it adds useful verified findings at acceptable cost.

## Benchmark on your own history

Keep the suite, labels, reports and journals in a private directory outside public
Git. Select frozen source pairs with independently reproduced findings, plus
reviewed negative controls. Separate case selection from the person doing the
review; freeze ground truth before seeing the output. A control with no known
defect is an assumption to check, not proof of correctness. Never place client,
holdings, credential or licensed vendor data in a suite or source packet.

A history file has `version: 1` and `cases`, each with these fields:

```json
{
  "id": "cash-sign",
  "repo_path": "../local-repository",
  "base_sha": "1111111111111111111111111111111111111111",
  "head_sha": "2222222222222222222222222222222222222222",
  "profile": "finance-saas",
  "expected": [{"label": "cash-sign-inversion", "paths": ["src/cash.py"], "severity": "high"}],
  "negative_control": false
}
```

Use actual full commit SHAs, not the illustrative values above. Repository paths
are local, relative to the suite file or absolute; URLs and linked paths are
refused. Objects must already exist. Evaluation never fetches, switches branches,
changes files or executes the repository. All changed source is screened; omitted,
ignored, private, binary, oversized or unsupported source refuses the case.
Expected paths must be inside that complete scope. Case IDs, expected labels,
severities, control flags and repository locations are excluded from requests.
Only the frozen source packet and the selected review instructions enter context.

Start with offline inspection. The public example uses only this project's own
PR history and includes two controls; see `examples/history-cases.md` for its
exact provenance and local-object prerequisites.

```sh
finassist --config examples/history-offline-config.json evaluate \
  --history-suite examples/history-cases.json --trials 2 \
  --output .finassist/history-offline.json
```

`--trials` is 1–20 per case (at most 50 cases). The printed `suite_hash` binds
the complete suite, held-out labels, policy pins and trial count. Inspect the
suite and frozen source before approving that exact hash; changing trials or
labels requires new approval. Offline output is deterministic and cannot be
scored as model quality.

For a model run, each case additionally needs a reviewed `policy` object with
`path` and `sha256`: the policy file's repository-relative path and SHA-256 of
its exact committed bytes at that case's **base SHA**. Its profile must equal
the case profile. Policy values choose the provider, model, endpoint, named key,
scope, pricing and limits. The normal gate's policy pin, full source screening,
immutable ignores, exact wire-request hash and retained budget reservations apply.
An offline inspection configuration does not authorize a model call.

```sh
finassist evaluate --history-suite /private/benchmark/history.json --trials 3 \
  --approve-suite YOUR_INSPECTED_SUITE_HASH --allow-network \
  --state-dir /private/benchmark/state --output /private/benchmark/evaluation.json
```

The whole suite is preflighted before the first request. Trials run sequentially
through one shared ledger. A gate FAIL means a completed review with a blocking
finding and does not stop later trials. BLOCKED stops the evaluation; later
trials remain `not-run`. There is no retry, provider fallback or automatic resume.
A private `state/history/*.json` journal marks the attempt before dispatch and
is updated after each result. If interrupted, retain it and the audit database;
unknown usage stays reserved. Reconcile actual provider billing before any new
run. Do not reset or change state directories to evade that hold.

### Adjudicate each finding

Independently reproduce the claims, then bind judgments to the exact
`evaluation_hash`. A history labels file has `evaluation_hash` and `runs`:

```json
{
  "evaluation_hash": "EXACT_EVALUATION_HASH",
  "runs": [
    {"case_id": "cash-sign", "trial": 1, "findings": {
      "FINDING_ID_FROM_EVALUATION": {"outcome": "confirmed-hit", "label": "cash-sign-inversion"}
    }}
  ]
}
```

Include exactly one entry for every completed trial, including `findings: {}`
for a completed review with no findings. Every returned finding ID needs one
judgment. Outcomes are `confirmed-hit` with an expected label, or `false-alarm`,
`confirmed-other`, or `unresolved` with `label: null`. A hit must name a target
whose paths include the cited file. A confirmed new defect outside the expected
targets is `confirmed-other`, not a false alarm. Such a finding contaminates a
negative control; investigate and revise ground truth before claiming quality.
Blocked/unattempted trials get no judgment. Missing targets in a fully
adjudicated completed trial are misses; unresolved work is never silently clean.

`score` detects the history format and retains the original synthetic scoring
format for existing evaluations. It reports per-case weighted recall, negative
control false-alarm rate, pairwise trial agreement and total dollars/seconds per
confirmed target hit. Fixed weights are critical=5, high=4, medium=3, low=2,
info=1. Expected labels set weights; model severity claims do not change them.
Duplicate descriptions of the same target count once per trial. Costs and time
include misses and false alarms. Time measures each gate attempt, excluding
initial suite preflight and human adjudication. Unknown amounts remain null; zero hits gives
null cost per hit. Incomplete runs, unresolved judgments or contaminated
controls withhold aggregate quality and efficiency metrics.

Agreement is the mean pairwise Jaccard similarity of confirmed target-label sets
per case; two empty sets agree. False-alarm agreement is reported separately.
Agreement can be consistently wrong and does not establish correctness.

### Compare reviewers

```sh
finassist score --evaluation /private/benchmark/model-a.json \
  --labels /private/benchmark/model-a-labels.json \
  --compare /private/benchmark/model-b.json \
  --compare-labels /private/benchmark/model-b-labels.json \
  --output /private/benchmark/comparison.json
```

Both evaluations need complete independent adjudication, identical case IDs,
source identities and ground truth. Profiles/models may differ. The report
shows labels detected by both reviewers, each reviewer alone, and overlap.
Detection in any trial counts for this overlap, so unequal trial counts change
opportunity; prefer matched counts and disclose the sampling choice.

An external review can use a `schema_version: 2`, `kind: history-evaluation`,
`mode: external` envelope with the same `suite_hash`, `trials` and case fields
as the local output. Retain each case's `source_hash`, `expected` and
`negative_control`; give each trial a status, stable finding IDs with paths and
severities, `actual_usd` (decimal string or null) and `elapsed_seconds` (number or
null). Use null for unknown external cost/time. Recompute `evaluation_hash` as
SHA-256 of compact, sorted-key JSON for the entire envelope except that hash
field (`finassist.security.canonical` defines the encoding). Human labels then
bind that envelope exactly. This is an operator attestation of source/reviewer
identity, not authentication of an external service or proof of completeness.

Keep adoption holdouts separate from public examples, profile tuning and prompt
development. Public PRs and reproduced tests may appear in model training or be
memorized; recall on those cases can overstate performance on unseen changes.
Record model/profile versions, failures, trial counts and label revisions.
No benchmark grants merge, publication or financial authority.

## Limits

The offline demo and unit tests verify deterministic code paths. Fake HTTP
transports verify protocol parsing and failure behavior. Neither measures a
model's ability to discover defects. No provider ranking is claimed.

A matching path, fluent explanation, model vote or valid JSON cannot establish semantic correctness. Public cases may be memorized: keep a separate private synthetic holdout. See the [threat model](threat-model.md).
