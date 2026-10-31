# Advisory triage contracts

The experimental finledgerpoli Python API validates data and calculates offline evaluation
metrics. It does not invoke models, train weights, discover plugins, install
packages, run checks or change required CI. The CLI works on explicit local
files and has no network service.
Reports grant no test-reduction, review, merge or deployment authority.

The [research and qualification plan](research/triage-research.md) explains
independent labels, model adaptation, source/license admission, prospective
confidence requirements and the public/private boundary. Those later phases
are not completed by validating this contract.

`finassist.triage_contract` provides `parse_triage_json`, `validate_request`,
`request_hash`, `validate_model_manifest`, `validate_result` and `validate_gold`.
The corresponding version 1 JSON schemas ship under `finassist/resources/`.
Call the Python validators as well as any schema validator: identity, complete
vectors, disjoint catalogs and other cross-field checks are enforced in Python.
Validation failures use `AssistantError` codes without embedding input text.

## Offline CLI

Validate a supplied model result against its exact request and a separately
pinned model identity:

```sh
finassist triage validate --request request.json --result result.json \
  --model-manifest model.json --output validation-new.json
```

Calculate metrics from three separate collections:

```sh
finassist triage evaluate --requests requests.json --gold gold.json \
  --predictions predictions.json --model-manifest model.json --output metrics-new.json
```

Each collection is an object with exactly `schema_version: 1` and its named
array (`requests`, `gold` or `predictions`). The manifest file contains the
model-manifest object described below. Each input file is bounded to 2 MB and
parsed strictly, including rejection of duplicate JSON keys and non-finite
numbers. These commands never load a project configuration, inspect environment
credentials, notify about updates or create an implicit audit directory.
Explicit global `--config` or `--audit-dir` is rejected for these commands.

Reports are created exclusively at the named new private output path; existing
files and symlinks are refused. Stdout contains a compact report hash and
advisory flags, not source or labels. Validation exits 0 for a valid recommend
report, 1 for a valid abstain/invalid-action report and 2 for a contract/input
error. Evaluation exits 0 when calculation completes and 2 on an invalid cohort;
exit 0 does not mean the model met an accuracy gate. All reports preserve the
requirement to run the baseline CI matrix. Run `finassist guide triage` for this
guide offline.

Validation reports bind `request_hash`, `result_hash`, the exact expected
`model_manifest` and its `model_manifest_hash`. These hashes use SHA256 of
`finassist.security.canonical`: UTF-8 JSON, sorted object keys, compact separators,
ASCII-escaped Unicode and no non-finite numbers. Array order is preserved. Evaluation
reports contain `input_hashes` with scheme `sha256-finassist-canonical-json` for
each complete version 1 collection envelope (`requests`, `gold`, `predictions`)
and the expected model-manifest object. Invalid but JSON-representable predictions
remain included in their collection hash. Python API inputs without a canonical
JSON representation fail with `triage_input_not_canonical_json`.

Both CLI reports additionally contain `input_file_hashes`: SHA256 of each exact
input file's bytes, including whitespace, key order and trailing newline. These
digests come from the same bounded reads used for parsing, without reopening the
files. Formatting changes affect file hashes but not semantic hashes; reordered
arrays affect both. These bindings detect changes, not authenticity, completeness
or independently approved exclusions. Input files can still change after a read.

## Request and model boundary

A request has `schema_version`, opaque `case_id`, immutable `task_revision`,
`source_digest`, source `context`, `max_selected_checks` and three candidate
lists: `patterns`, `files` and `checks`. Each candidate has an opaque stable
`id` and a description. IDs are unique across the three lists. Candidate
descriptions and context are untrusted data, never executable instructions.

`request_hash(request)` hashes the exact canonical validated JSON, including
the declared selection budget. Freeze that budget and the task policy before
adjudicating gold; the validator cannot verify when an operator made a decision.
The budget may exceed the retrieved check count so candidate omissions remain
measurable. It cannot exceed the gold's complete check catalog. This first
version implements a count budget, not variable execution-cost accounting.

Requests have no label, family, control, gold or outcome fields. Unknown keys
are rejected. Nevertheless, source text can itself reveal sensitive material
or answers: the caller must inspect and approve any outgoing context. The
existing content screen is not a proof of confidentiality or leakage absence.

A result binds `case_id`, `request_hash` and an exact caller-expected
`model_manifest` containing `model_id`, `model_digest`, `scorer_revision` and
`calibration_digest`. These are supplied identities, not verified files or
signatures. Results include complete probability vectors for every supplied
candidate. Patterns and checks are independent probabilities in `[0,1]`;
nonempty file vectors sum to 1 within absolute tolerance 1e-9.

Actions and reasons are closed pairs:

| Action | Reasons |
| --- | --- |
| `recommend` | `scored` |
| `abstain` | `uncertain`, `insufficient_context`, `out_of_distribution` |
| `invalid` | `invalid_input`, `inference_error`, `timeout` |

Only `recommend` emits `selected_patterns`, `selected_checks` and a full
`ranked_files` permutation consistent with nonincreasing file probabilities.
Abstention/invalid reports keep complete vectors but all selections/ranks empty.
If a failed process cannot produce a valid report, omit it from the prediction
list; the evaluator records a missing prediction as a miss. No free-text reason,
unknown ID, duplicate ID, non-finite probability or extra field is accepted.
Probability normalization is not evidence of calibration or model correctness.

## Independent gold and end-to-end scoring

Gold stays separate from requests and binds the same case/request hash. It
declares `source_kind` (`real` or `synthetic`), `family_id`, adjudication status,
applicability reason, `is_control`, `defect_status`, a full catalog, disjoint
required/optional/forbidden partitions for patterns/checks, and acceptable
first-file IDs. The partitions must cover the complete respective catalogs.

Catalogs may include IDs absent from retrieved candidates. If a required check
is omitted, the case remains eligible and routing fails. Gold cannot redefine
the catalog as only the retrieved candidates without an external adjudication
error: completeness is an operator assertion, not discoverable from JSON.

Confirmed cases are eligible. Unconfirmed cases use `pending_adjudication`;
headline quality rates are withheld when a source cohort has any unconfirmed
cases. A confirmed case with a required set larger than the predeclared budget
must state `budget_infeasible`; it remains in the primary denominator as a
routing miss and is separately counted as a frozen-policy failure. The library
also accepts `not_applicable`/`outside_scope` as a caller-supplied exclusion, even
if that case's required set exceeds its budget. It cannot determine whether a
caller improperly relabeled a policy failure. A separate cohort and adjudication
review must enforce predeclared, justified exclusions; reported exclusion counts
and input hashes do not authenticate those decisions.

`evaluate_triage(requests, gold, predictions, expected_model_manifest=...)` in
`finassist.triage_metrics` requires exactly one gold record for every request.
Duplicate or unknown cases fail evaluation; absent predictions count as misses.
Invalid/stale/mismatched results and abstentions also count as misses. No
provider call or fallback is performed, and no output is treated as executed CI.
The eligible-case outcomes histogram distinguishes `contract_invalid` (a result
failed validation) from `declared_invalid` (a contract-valid result declared
action `invalid`). `recommend`, `abstain` and `missing` retain their meanings.
This replaces the formerly combined `invalid` report bucket; the input action
enum and version 1 schemas are unchanged. Both invalid categories remain misses.

The primary model-only routing success is:

```
action == recommend
and required_checks <= selected_checks <= required_checks | optional_checks
and len(selected_checks) <= max_selected_checks
```

Its denominator is every eligible supplied case, including inference failures
and candidate-retrieval omissions. Pattern accuracy and file ranking are
separate endpoints; a pattern/file mistake does not redefine the routing target.
The selected-only rate is reported beside recommendation coverage so abstention
cannot hide its cost. A successful optional selection is not a false positive.

Real and synthetic metrics remain separate. Reports count declared eligible
family groups and give an all-cases-successful family rate; family IDs do not
prove independence. Required-review/no-required-review and control/noncontrol
strata are distinct: clean code and controls can still require review checks.
First-file top1/top3 use eligible cases with a nonempty acceptable set, including
missing predictions as misses; per-label
precision/recall exclude optional labels from positive/negative judgments.
Zero denominators return `None`, never a perfect score.

These descriptive metrics establish no statistical acceptance threshold,
confidence bound, representative sampling or deployment certification. A
separate prospective design must establish those claims. Missing predictions
remain failures; incomplete adjudication is not silently reported as success.

## Private assets and CI integration

Keep real examples, labels, holdouts, workflow mappings, trained weights,
private prompts, retrieval indexes and raw traces outside the public package
source/build tree. Schemas and neutral synthetic fixtures can be distributed.
The library does not auto-discover those private assets.

A separately reviewed private scorer may emit the typed artifact; validation
does not authorize that process. Keep candidate code away from scorer and
publisher credentials. On any absent, invalid, stale or abstained advisory
result, preserve the existing required test matrix. Public packaging and
ordinary CI continue to need their existing review and release gates.
