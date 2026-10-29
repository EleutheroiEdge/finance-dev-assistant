# Durable workflow execution

finledgerpoli can execute the check recipes in an approved [workflow plan](workflow-plans.md),
save checkpoints and resume remaining work. Execution is sequential and bounded.
It uses the existing screened committed snapshots and approved runner. It does
not call models, prepare patches, merge, deploy, trade or start recurring jobs.

## Run and resume

Review the template, methodology, configuration and exact plan hash first.
Container execution is the default: configure a digest-pinned `runner_image`
and make it available locally. The runner does not pull images and disables
network access inside the container. `doctor` does not establish daemon access.

```sh
finassist --config finassist.json workflow run --repo . \
  --packet .finassist/context.json --plan .finassist/workflow.json \
  --approve-plan FULL_PLAN_HASH --backend docker --max-steps 1
```

The first stdout object identifies the new `workflow_run_id`. The final object
describes the resulting state, step attempts, blockers and successful
`check_records`. Record the actual ID and hash; placeholders above are not
literal arguments. `--output` saves the final result privately while stdout
still identifies the run and saved result. A run can exist and have performed
checks even when output saving or the invoking process fails. Inspect state
before repeating a command.

```sh
finassist workflow status --run-id RUN_ID
finassist --config finassist.json workflow resume --repo . \
  --run-id RUN_ID --approve-plan FULL_PLAN_HASH
```

`resume` uses the stored plan, packet and backend, with the currently supplied
configuration. It rechecks configuration/source identity and verifies retained
completed artifacts before reuse or new dispatch. Source or policy changes
require a new reviewed plan; changing a backend requires a new run.
Changed valid configuration returns a blocked report even when its narrower
scope no longer permits the old methodology. Invalid inputs or missing approval
are refused before a new CLI run initializes persistent state.

Each invocation permits at most `--max-steps` checks, an integer from 1 through
64, default 64. Exhausting this bound returns `paused`; a later resume continues
with eligible steps. Dependencies must have succeeded before a step starts.
A failed or uncertain step stops execution, including independent pending work.
There are no automatic retries. Another unfinished run of the same plan in the
same state directory is refused; use its recorded ID rather than creating a
duplicate to work around an interruption.

Local execution requires `--backend local --approve-local` at creation and
`--approve-local` on every resume. It is trusted-code execution without OS
filesystem/network isolation. The runner's clean environment and process
cleanup are not a security sandbox. Do not use local execution for hostile
source. `allow_local_readiness` remains a separate explicit configuration
choice; completing local checks does not override that readiness policy.

## Inspect truthful outcomes

`workflow status --run-id RUN_ID` reads historical checkpoints and verifies
retained result hashes without running recipes or contacting providers. Without
an ID it lists recorded runs, with `artifacts_verified: false`; the list does not
inspect every artifact. A single-run report includes:

- `status` and `recorded_status`: `pending`, `running`, `unknown`, `failed`,
  `completed-checks` or `cancelled`. Missing/changed artifacts produce `blocked`.
- Step IDs, dependencies, latest attempt IDs and saved artifact hashes/paths.
- `check_records`: successful retained results that can be supplied through
  existing `verify-gate --receipt` arguments.
- Stable `blocking_reasons`, the bound plan/execution hashes and event sequence.

`paused` describes an invocation that reached its step bound; its recorded state
remains `pending`. `running` is the last recorded dispatch state, not proof a
process is alive. Status does not check today's source/configuration or establish
financial correctness. `completed-checks` is not readiness: model review,
freshness, isolation, coverage and all other gate requirements still apply.

Readiness blocks on `unfinished_workflow` while the same audit directory has a
pending, running, unknown or failed workflow. A known failed run still needs
explicit retry or cancellation before its validation work is closed.
`audit` reports these as
`unfinished_workflows`. Statistics also exposes reduced workflow states; the
existing dashboard does not yet provide a workflow inspector or execution UI.

Normal execution exits 0 when it completes or intentionally pauses, and 1 for
known failed/blocked/unresolved results. Refused inputs, lock conflicts and
handled operational failures exit 2. An interrupted dispatch can return
`workflow_step_outcome_unknown` or `workflow_outcome_audit_unavailable`; neither
permits an automatic retry. Status may show a committed result even after an
acknowledgement failure. Inspect the final state and artifacts, not just an
earlier stdout object or process exit.

## Reconcile an interrupted attempt

Dispatch intent is committed before invoking a recipe. The process holds a
per-run OS file lock throughout execution; another executor or reconciliation
command is refused while that lock is held. There is no expiring lease that can
authorize a second executor during slow work. After an abrupt exit, the lock is
released, but a recorded running attempt remains uncertain. Resume classifies
it as `unknown` and stops without dispatching it again.

If the result file was saved before its checkpoint, status can show a
`recovery_artifact_hash`. Inspect the private file and approve that exact hash:

```sh
finassist --config finassist.json workflow reconcile --run-id RUN_ID \
  --step-id STEP_ID --approve-attempt ATTEMPT_ID \
  --approve-artifact FULL_ARTIFACT_HASH
```

Adoption verifies the original configuration, recipe, output hash, process
cleanup and the snapshot digest saved **before dispatch**. The existing check
audit event and workflow result checkpoint are then committed atomically. An
exact artifact hash alone is insufficient. An artifact claiming uncertain
cleanup cannot be adopted as success.

Workflow check freshness is measured conservatively from the dispatch intent,
not the later reconciliation date. Delayed adoption cannot make an old check
fresh. The original timestamp appears as `started_at` in step inspection and
`evidence_recorded_at` in the check audit event; readiness requires both that
time and the event's own recording time to satisfy the configured age limit.

If no valid result exists, first independently verify that the attempt's
processes/containers have stopped and cleanup is complete. Lock release alone
does not prove descendant cleanup. Then record an explicit failed outcome:

```sh
finassist workflow reconcile --run-id RUN_ID --step-id STEP_ID \
  --approve-attempt ATTEMPT_ID --confirm-cleanup
```

This records failure and never creates passing financial evidence. It can exit
1 because the check remains failed. It does not kill processes or delete
containers. If another attempt is warranted, approve the failed attempt and
exact plan explicitly, then resume:

```sh
finassist workflow retry --run-id RUN_ID --step-id STEP_ID \
  --approve-attempt ATTEMPT_ID --approve-plan FULL_PLAN_HASH
finassist --config finassist.json workflow resume --repo . \
  --run-id RUN_ID --approve-plan FULL_PLAN_HASH
```

`retry` changes eligibility only. The next dispatch gets a new attempt ID while
retaining a stable operation ID for that run/step. IDs do not make a downstream
side effect idempotent. No exactly-once execution guarantee is claimed.

`workflow cancel --run-id RUN_ID --approve-plan FULL_PLAN_HASH` can close a
pending or failed run without deleting evidence. It refuses running/unknown
attempts; reconcile them first. Cancellation never interrupts an active owner.

## State and audit boundaries

Every state command accepts `--repo`; its default state is `REPO/.finassist`,
including when invoked from another directory. Use the same target repository
for status, reconciliation, retry and cancellation. An explicit `--state-dir`
or global `--audit-dir` overrides this default; use that same directory for the
readiness gate so unfinished work remains visible.

All workflow transitions use schema version 1 in the existing private SQLite
audit chain. Replay rejects invalid dependency transitions, reused attempt IDs,
unsupported versions and inconsistent outcomes. Successful/failed check records
are added in the same transaction as their result checkpoint. Audit failure
before intent prevents dispatch; failure after dispatch retains an uncertain
attempt or an already committed result for inspection.

These commands use workflow transitions as their lifecycle, rather than leaving
generic command-run markers that cannot be closed after a crash. Existing
`workflow plan` and `preflight` command auditing is unchanged. Step IDs, hashes,
attempt IDs and reduced outcomes appear in audit metadata; raw source, recipe
arguments, methodology text and test output do not. Test output remains
untrusted data in private result artifacts and cannot authorize further work.
Saved results are limited to 4,000,000 encoded bytes including the trailing
newline. State inspection and the readiness gate accept that same bound for
check records, including JSON escaping overhead. Other JSON CLI inputs retain
their 2,000,000-byte limit.

Retained inputs/results live under `STATE/workflow-runs/RUN_ID/`; stable lock
files live under `STATE/workflow-locks/`. Do not delete lock files to recover a
busy run or edit database/hash state to clear a blocker. Orphan input files may
remain if creation fails before its audit event; they never authorize dispatch.
Keep the whole directory local, excluded from Git and protected by owner-only
permissions or reviewed Windows ACLs. Local hashes cannot prevent a malicious
same-user rewrite. No remote storage, provider billing, dynamic plugin loading
or new infrastructure authority is introduced.
