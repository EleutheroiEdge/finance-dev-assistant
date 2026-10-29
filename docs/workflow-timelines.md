# Workflow audit timelines

Use finledgerpoli's read-only timeline to inspect the history behind a workflow
checkpoint. It links the exact plan, source revision, execution, step attempts,
snapshot hashes and recorded result hashes without opening source or test logs.
It does not execute checks, adopt results or change the ledger.

```sh
finassist workflow timeline --repo . --run-id RUN_ID --limit 100
```

The default state is `REPO/.finassist`. An explicit `--state-dir` or global
`--audit-dir` selects another private state root. Configuration is not loaded;
even a missing or invalid `--config` cannot prevent historical inspection.
The database must already exist. The connection uses SQLite read-only mode,
does not initialize or repair schema, change permissions, or append lifecycle
events. An explicit `--output NEW_PRIVATE_FILE.json` writes a new private report
and emits `{output, report_hash}`; otherwise the report goes to stdout.

## Understand the report

The version-1 report includes the run/plan/execution/source identities, recorded
status, a verified ledger-prefix anchor, filtered transition events, step states,
dependency blockers and suggested next checks. Each event carries its original
global sequence, preceding hash and event hash. Unrelated ledger entries create
gaps between those sequences; a filtered page is not a standalone contiguous
hash chain. Full-ledger integrity and workflow transition replay are verified
inside one read transaction before a report is returned.

Step summaries explain unmet dependencies, a failed check, cancellation or an
unresolved attempt. Suggestions are fixed descriptions, not executable commands
or new permission. A recorded `running` state does not prove a process is alive;
inspect ownership and cleanup before reconciliation. See [durable workflow
execution](workflow-execution.md) for the existing recovery gates.

The flags `artifacts_verified`, `current_bindings_verified`, `readiness_evaluated`
and `execution_authorized` remain false. A historical `completed-checks` state
can coexist with missing artifacts or changed source/configuration. Use
`workflow status --run-id RUN_ID` for retained-artifact checks, normal preflight
for current bindings, and the separate [readiness gate](readiness-and-auditing.md)
for fresh review/check evidence. Inspect generic unfinished operations and
unresolved charges through `audit`; the timeline does not assess them.

## Page a stable historical snapshot

`--limit` permits 1 through 1000 transitions, default 100. `--after` is an
exclusive global sequence cursor, default zero. For another page, take
`pagination.next_after`. To exclude later appends and retain the same historical
step summaries, also pass the first page's exact snapshot pair:

```sh
finassist workflow timeline --repo . --run-id RUN_ID --after NEXT_AFTER \
  --through THROUGH_SEQUENCE --anchor FULL_THROUGH_HASH --limit 100
```

Replace placeholders with actual returned values. `--through` and `--anchor`
must be supplied together; mismatched or unavailable anchors are refused. Without
the pair, a later query observes a fresh verified snapshot and may include new
transitions. `pagination.has_more` distinguishes remaining filtered events from
the end of the selected prefix. An end-of-page cursor reaches the prefix tail
when no matching events remain, including when other runs occupy its last rows.

All ledger entries are integrity-checked before pagination. Invalid transitions
or unsupported workflow versions, even for a different run or outside the page,
cannot be hidden by the filter. Later valid appends do not alter a pinned report.
Missing state, unknown run IDs, invalid cursors and corrupt history produce
structured refusal errors with exit 2. A successfully inspected historical
failed/unknown run exits 0: the query succeeded, not the workflow.

## Privacy and limits

Only an explicit projection of validated workflow transition metadata is
exported. Arbitrary diagnostic events, prompt/source text, output, recipe
arguments, environment values and local artifact paths are excluded. Retained
artifacts are not opened by timeline queries. `report_hash` covers the returned
document except that field; it establishes identity, not authorship or approval.

Keep reports local and excluded from Git. Run and step identifiers are still
private operational metadata. This mechanism provides local integrity checks;
it does not defeat a malicious same-user rewrite or establish independent
recordkeeping, financial correctness, merge or deployment authority. No telemetry
exporter, background process, retention purge or dashboard execution UI is added.
