# CLI exit codes and output contracts

Use finledgerpoli in scripts through documented JSON records and exit codes. Its command is `finassist`; global options precede the subcommand.

Use `finassist --help` and `finassist COMMAND --help` for argument syntax. Global options include `--config` and `--audit-dir`. Do not parse human prose,
error messages or dashboard console URLs as structured records.

| Exit | Meaning |
| --- | --- |
| `0` | Command completed or its deterministic check passed. A completed review/evaluation can still contain findings or unknown professional validity. Offline review does not satisfy model-review readiness. |
| `1` | A deterministic check failed, publication findings were found, readiness was blocked or GitHub protection inspection found issues. Inspect the JSON result. |
| `2` | Refused operation, invalid input/configuration or handled operational error. Structured runtime errors go to stderr; argument-parser errors instead use argparse's human-readable usage text. |

`--help` and `--version` exit 0 with human-readable stdout. Interrupts/signals and
unexpected interpreter/host failures are outside this normalized contract; do not
interpret absence of a result as success. Dashboard exits 0 after a handled
keyboard shutdown. Starting it is not a readiness check.

A **receipt** is a saved record that binds an action and its outcome to hashes; this technical term appears in JSON field names and command flags. Readiness means the configured prerequisites for human review are satisfied.

## Encoding, streams and artifacts

Normal structured output is UTF-8, one JSON object per line, terminated by LF.
An invocation can emit several objects: parse each line rather than treating all
stdout as one JSON document. Progress/result records may precede a later error.
Check the exit status and expected final artifact; a partial stdout stream is not
completion. Keys may be added compatibly; consume named keys rather than ordering.
Hash-bound artifact schemas are stricter and carry their own schema/version checks.

`--output` writes the full result privately when that command supports it. Where
listed below, stdout still contains a saved record or summary. Without `--output`, the
full result goes to stdout, followed by any summary. Audit export is JSON Lines;
render writes escaped HTML. Artifact paths and source-bearing results can contain
private information: keep them local and do not paste full outputs into public issues.

Handled runtime refusals use this stderr shape:

```json
{"status":"error","code":"network_not_approved"}
```

Handled input/OS/database classes use `{"status":"error","code":"invalid_input","kind":"ValueError"}`
with the actual stable exception class. The code family/keys are the contract;
raw provider errors, secrets and private paths are not included. A nonzero exit
can follow a mutation or uncertain provider call: inspect audit/state before retrying.

## Commands

The fields below name the result's integration surface; nested full artifact
contracts are in the linked guides and implementation. An ellipsis in prose
means other documented/context-specific fields can exist, not a literal JSON value.

| Command | JSON/result shape and streams | Normal exits |
| --- | --- | --- |
| `config` | `config migrate --dry-run` returns `{changed, source_sha256, diff, written: false, backup: null}` without writes. A non-dry run applies only supported key renames after validation, with exact original bytes in a timestamped backup; unchanged files remain byte-identical. | 0, 2 |
| `gate` | `gate run` writes a version-1 model component report at required new `--output`; stdout `{verdict, report_hash}`. Explicit v2 pinned base policy and private retained `--state-dir` required. Verdict PASS/FAIL/BLOCKED, reasons, structured advisory findings, source/policy/request hashes, usage and spend. Unknown usage stays reserved. Summary/Action outputs omit raw provider text. See [pre-merge gate](pre-merge-gate.md). | 0 PASS, 1 FAIL, 2 BLOCKED/error |
| `ci` | `ci gate` returns a version-1 deterministic-check report: status, exact policy/source/plan/configuration hashes, required/completed counts, model-review status and blockers. With `--output`, stdout is `{output, status, report_hash}`. Reads a pinned base policy, not workspace config. See [CI gates](ci-gates.md). | 0, 1, 2 |
| `guide` | Without a topic: stdout `{topics: [{topic, title}]}`. With a topic: bundled UTF-8 Markdown, not JSON. No config, state writes or network. Unknown topics return `unknown_guide` on stderr. | 0, 2 |
| `init` | stdout `{created: string, network_enabled: false}`; writes validated config JSON. | 0, 2 |
| `doctor` | stdout health object: `version`, `python`, `platform`, `provider`, `model_configured`, `network_enabled`, `key_present` (boolean/null), runtime binary presence, `container_daemon_checked: false`, recipes/profile, deprecated keys and private-state warning. Explicit `--fix` preflights and applies safe reversible configuration/evidence migrations, adding `fixes` metadata without network calls. | 0, 2 |
| `demo` | result `{status, data_class: "synthetic", checks: array, counterexamples_detected: array, model_called: false, trade_execution: false, qualification, tax_example}`. | 0, 1, 2 |
| `plan` | outgoing request artifact with `schema_version: 2`, base/head/merge-base hashes, profile/path policy, files, omissions and `packet_hash`; stdout summary `{packet_hash, output, triage}`. | 0, 2 |
| `workflow` | `plan`/`preflight` bind and inspect plans; `run`/`resume` execute approved checks; `status`/`reconcile`/`retry`/`cancel` inspect and manage durable state. See [workflow plans](workflow-plans.md) and [execution](workflow-execution.md). | 0, 1, 2 |
| `workflow plan` | separate version-1 plan binding template, methodology, recipes, packet and configuration hashes; writes the plan privately and emits `{output, plan_hash, status: "plan-bound"}`. No execution. See [workflow plans](workflow-plans.md). | 0, 2 |
| `workflow resolve` | Writes a new private directory with `config.json`, `template.json` and `resolution.json`; stdout `{directory, resolution_hash, config_hash, template_hash, execution_authorized: false}`. Local pinned packs only, with no activation or execution. See [workflow packs](workflow-packs.md). | 0, 2 |
| `workflow preflight` | `{schema_version: 1, status: "preflight-passed"/"blocked", plan_hash, head, blocking_reasons, required_recipes, execution_authorized: false, merge_authority: false, deployment_authority: false, qualification}`. With `--output`, writes the full result and emits `{output, plan_hash, status}`. No execution or readiness claim. | 0, 1, 2 |
| `workflow run` | First stdout `{workflow_run_id, status: "created"}`, then a durable run report with `status`, `recorded_status`, IDs/hashes, steps, successful `check_records`, blockers and no merge/deployment authority. Requires exact `--approve-plan`; default container runner, local requires opt-in. `--max-steps` bounds work; `paused` is exit 0, not completion. | 0, 1, 2 |
| `workflow resume` | Same final run report, using stored plan/packet/backend and current exact configuration. Reuses verified completed artifacts; unknown attempts are held. | 0, 1, 2 |
| `workflow status` | With `--run-id`: historical run report with artifact verification. Without: `{schema_version: 1, artifacts_verified: false, workflows: [{workflow_run_id, status, plan_hash}]}`. No recipe/model execution. Unresolved/blocked single-run reports exit 1. | 0, 1, 2 |
| `workflow timeline` | Version-1 metadata-only historical report with run/plan/source identities, verified snapshot anchor, bounded transition page, dependency blockers and `report_hash`. No configuration load, artifact verification or actions. With `--output`, stdout is `{output, report_hash}`. See [timelines](workflow-timelines.md). | 0, 2 |
| `workflow reconcile` | Run report after exact attempt approval plus either exact saved artifact approval or explicit cleanup confirmation. Cleanup confirmation records failure, never passing evidence. | 0, 1, 2 |
| `workflow retry` | Run report after returning an approved failed attempt to pending. Requires the plan hash and attempt ID; no execution or implicit resume. | 0, 1, 2 |
| `workflow cancel` | Run report after closing an approved pending/failed run. Refuses active/unknown attempts; preserves artifacts and audit. | 0, 1, 2 |
| `watch` | one stdout `{head, triage, network_called: false}` record initially, then one for each observed committed-head change, within configured iteration bounds. | 0, 2 |
| `review` | full report: `status`, `packet_hash`, `head`, provider, findings and qualification; offline includes triage and no model claim. Remote adds model/review evidence metadata. Stdout summary `{output, status}`. Findings do not change the exit status to 1. | 0, 2 |
| `propose` | full `{artifact: {head, patch, summary}, approval_hash, reservation, applied: false, audit_receipt}`; stdout `{output, status}`. No patch is applied. | 0, 2 |
| `apply` | stdout saved patch record with `patch_hash`, head and changed paths/recovery metadata. Exact artifact hash approval required. | 0, 2 |
| `rollback` | stdout `{rolled_back: patch_hash, paths: array}` after guarded restoration. | 0, 2 |
| `check` | full `{receipt, output, snapshot}`; stdout saved record includes `passed`, exit code, timeout/output/cleanup/isolation metadata, head, config and snapshot hashes. A command failure and cleanup failure both prevent a pass. | 0, 1, 2 |
| `finance-check` | kind-specific deterministic result: cash/weights have `passed` and reconciliation fields; observation has `passed`, `issues`, `decision_time` and qualification; tax has estimated arithmetic/rates and qualification, without a `passed` requirement. | 0, 1, 2 |
| `audit` | stdout `{events_verified: integer, unresolved: array, incomplete_runs: array, unfinished_workflows: array}`. Optional export writes verified event JSON Lines. Exit 0 does not mean reservations/runs are resolved. | 0, 2 |
| `reconcile-budget` | same summary shape as audit after settling the named reservation with your actual USD charge. | 0, 2 |
| `render` | writes escaped HTML; stdout `{output: string}`. | 0, 2 |
| `scan` | stdout `{files: integer, findings: [{path, code}], passed: boolean, qualification}`. Supplementary tracked-file scan, not a confidentiality proof. | 0, 1, 2 |
| `evaluate` | stdout `{suite_hash, provider}` first; full evaluation artifact with hash, cases and provider metadata, then `{output, model_quality_measured: false}`. Independent scoring is separate. | 0, 2 |
| `score` | result `{evaluation_hash, counts, case_recall: number/null, negative_control_false_alarm_rate: number/null, complete: boolean, qualification}`. Unresolved labels are represented, not treated as a process error. | 0, 2 |
| `evidence` | see action table below; stdout one evidence record. | 0, 2 |
| `export-kit` | stdout `{directory, templates: array, installed_into_host: false}`; writes a new private directory only. | 0, 2 |
| `verify-gate` | `{status: "blocked"/"eligible-for-human-review", head, blocking_reasons: array, required_recipes, policy_hash, merge_authority: false, deployment_authority: false, qualification}`. Optional `--workflow-plan` adds plan preflight, extra recipe requirements and `workflow_plan_hash`; after passing preflight, `workflow_missing_requirements` names absent check records. | 0, 1, 2 |
| `github-audit` | protection snapshot with repository/branch, observations, `issues: array` and `snapshot_hash`; read-only API inspection after network approval. | 0, 1, 2 |
| `dashboard` | Human stdout `Dashboard: http://127.0.0.1:<port>`; persistent local HTTP server, no CLI JSON success record. See dashboard API errors below. | 0, 2 |

`evidence` actions are positional: `finassist evidence add`,
`approve`, `reject`, `latest`, `verify` or `migrate`. Add/decision records contain `id`, content `hash`,
status and record metadata; latest returns the unique approved revision matching
the requested entity/metric/period/unit, or refuses ambiguity/missing matches.
Use the IDs and hashes printed by the tool, not list position. See [research inputs](research-inputs.md).
`evidence verify` returns `{verified, schema_version, entries, decisions}` without
writes. `evidence migrate --dry-run` adds `{changed, written: false, source_sha256,
target_schema_version, backup, destination}`. The explicit non-dry run copies to
a new versioned filename and adds `destination_sha256`, keeping the original as
the untouched backup. A current-schema no-op reports `changed: false` and
`written: false`. `--dry-run` is refused on other evidence actions. See the
[compatibility policy](https://github.com/EleutheroiEdge/finance-dev-assistant/blob/main/docs/maintainers/compatibility.md).

## Dashboard HTTP errors

The dashboard is a same-user browser interface, not a public API service. It uses
same-origin and per-session-token checks; clients must not expose it externally.
Configuration/statistics failures return HTTP 409 with
`{"kind":"configuration","code":"configuration_invalid"}`. Health still reports
configuration validity. Other refused API requests use a `code`; a post-mutation
unknown save reports uncertainty and must not be blindly retried. Keys are only
presence booleans. See [dashboard guide](dashboard.md) for preview/confirmation.

See [workflow artifacts](workflows.md), [readiness/auditing](readiness-and-auditing.md),
[configuration](configuration.md) and [provider behavior](providers.md). These
contracts do not replace the strict validators for saved outgoing requests/proposals.

## Limits

Partial output, missing artifacts and unknown outcomes are not success; reconcile state before retrying a mutation or provider call. JSON shape and citations do not establish correctness. Readiness grants no action authority. Private outputs must remain local. See the [threat model](threat-model.md).
