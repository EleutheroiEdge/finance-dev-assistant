# Evaluation without self-certification

The offline demo and unit tests verify deterministic code paths. Fake HTTP
transports verify protocol parsing and failure behavior. Neither measures a
model's ability to discover defects. No provider ranking is claimed.

The versioned synthetic review suite contains cash-sign, tenant-isolation,
point-in-time and negative-control changes. `evaluate` builds reproducible
temporary Git fixtures. Only before/after source enters model context;
expected labels are held out of the prompt. Public cases can be memorized,
so keep a separate private synthetic holdout for consequential comparisons.

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
unresolved cases. It does not infer semantic correctness from a matching path,
an impressive explanation, a model vote or a valid JSON schema.

For an adoption decision, also compare severity calibration, reproducible tests,
coverage gaps, prompt-injection behavior, dollars per confirmed defect and elapsed
time on identical frozen tasks. Retain failures and repeated trials. A second
model is worthwhile only if it adds useful verified findings at acceptable cost.
