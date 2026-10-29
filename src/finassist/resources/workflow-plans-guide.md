# Workflow plans

Use finledgerpoli's offline workflow plans to declare financial validation
obligations before running checks. The existing `plan` command still creates a
screened source packet. `workflow plan` adds a separate versioned artifact that
binds a project's methodology, required recipes and dependency graph to that
packet and configuration. Neither planning nor preflight executes a recipe,
calls a provider or approves any action.

## Declare a workflow

Start with [the synthetic cash template](../examples/cash-workflow.json). Adapt
its methodology and recipes to the target project's reviewed rules.

For reusable composition, [workflow packs](workflow-packs.md) resolve separate
profiles, checks and restrictive policies into this same version-1 format.

A template has exactly these fields:

```json
{
  "schema_version": 1,
  "name": "cash-validation",
  "goal": "Validate cash conservation under the project's approved fee policy",
  "methodology": ["docs/cash-policy.md"],
  "requirements": [
    {"id": "unit-tests", "recipe": "unit", "methodology": ["docs/cash-policy.md"]},
    {"id": "cash-conservation", "recipe": "cash", "methodology": ["docs/cash-policy.md"]}
  ],
  "steps": [
    {"id": "unit", "requirement": "unit-tests", "depends_on": []},
    {"id": "cash", "requirement": "cash-conservation", "depends_on": ["unit"]}
  ]
}
```

`methodology` names nonempty UTF-8 documents in the packet's committed **head**.
Documents must satisfy the configured source allowlist, screening, size and Git
object-mode rules. Generated artifacts cannot govern a workflow. Local edits
are excluded. Every declared document must be referenced by a requirement.
Hash binding records which bytes were used; it does not establish that a
document is authoritative or that a recipe implements its rules correctly.

Each requirement maps a unique ID to one unique recipe from the existing
`recipes` configuration and one or more methodology paths. All configured
`required_recipes` must appear, and a workflow can add further obligations.
There is exactly one step per requirement. Step IDs are unique; dependencies
must reference known steps and form an acyclic graph. Array order does not
define execution order. Schema version 1 accepts up to 64 documents,
requirements and steps. Unknown fields and unsupported versions are refused.

The graph can be consumed by the explicitly approved [durable check executor](workflow-execution.md),
or checks can still be run individually. A plan alone does not grant
shell/network permissions or replace exact outgoing-request,
local-runner or patch-application approvals. Profiles remain checklists; they
cannot expand capabilities.

## Bind and inspect

From the target repository, using its reviewed configuration and template:

```sh
finassist --config finassist.json plan --repo . --base main --head HEAD \
  --output .finassist/context.json
finassist --config finassist.json workflow plan --repo . \
  --packet .finassist/context.json --template cash-workflow.json \
  --output .finassist/workflow.json
finassist --config finassist.json workflow preflight --repo . \
  --packet .finassist/context.json --plan .finassist/workflow.json
```

The plan embeds the complete template and its hash, base/head commit IDs,
packet hash, complete configuration hash, methodology content hashes/Git modes,
and recipe argument hashes. `plan_hash` binds the whole artifact except itself.
Treat it as private: its goal and paths can describe your project. Plans can
only use version-2 source packets, which retain Git object-mode evidence.

Preflight revalidates these bindings against committed source, current
configuration and repository HEAD, and accounts for review omissions. It checks
for a committed change to review. It emits `preflight-passed` or `blocked` with
stable `blocking_reasons`, `required_recipes` and `plan_hash`.
`execution_authorized`, `merge_authority` and `deployment_authority` are false.

Exit 0 means identity/coverage preflight passed. Exit 1 means blocked preflight;
for example `workflow_head_changed`, `workflow_configuration_changed`,
`workflow_packet_changed` or `workflow_coverage_incomplete`. Exit 2 means invalid
input or a refused operation, including missing methodology, an unconfigured
recipe, a dependency cycle or tampered/unsupported artifacts. Rebuild and review
a plan when its inputs change; do not edit hashes to suppress a refusal.

Preflight inspects committed inputs, so it does not assess worktree cleanliness,
run tests, validate financial semantics, check model-review evidence or establish
readiness. The readiness gate separately checks those applicable prerequisites,
including a clean worktree and current audited check records.

## Require the planned evidence at readiness

Run the existing review/check commands with their existing approvals. Include
the workflow artifact explicitly when evaluating readiness:

```sh
finassist --config finassist.json verify-gate --repo . --expected-head FULL_SHA \
  --packet .finassist/context.json --review .finassist/review.json \
  --receipt .finassist/unit.json --receipt .finassist/cash.json \
  --workflow-plan .finassist/workflow.json
```

The gate first preflights the plan. It then requires the union of configured and
workflow recipes through the existing evidence verifier. Configuration hashes
are preserved; the workflow does not manufacture a replacement configuration
that invalidates earlier check records. Each supplied record still needs audited
identity, matching snapshot/source/configuration/recipe hashes, freshness,
successful cleanup and the configured isolation policy. A fabricated green
check record cannot substitute for a matching audit event.

If unit tests pass but the cash-invariant record is absent, readiness remains
blocked with `required_recipe_evidence_missing`; `workflow_missing_requirements`
identifies `cash-conservation`. That list names absent records, not every
invalid record. Other existing blockers explain failed, stale, duplicate or
unaudited evidence. With a preflight failure, the result reports those reasons
without claiming an assessment of supplied records.

The integration is opt-in: callers must pass `--workflow-plan` whenever they
want these extra obligations enforced. Omitting it preserves the existing gate
contract. A template change creates a different plan; there is no automatic
policy registration or approval of that change. Reviewers must verify the
intended plan hash and governing configuration, and retain normal project gates.
Readiness remains eligibility for human review, with no merge, deployment or
financial execution authority. Offline model analysis does not satisfy the
existing model-review requirement.

## Audit and limitations

The CLI adds metadata-only `workflow_plan_bound` and
`workflow_preflight_evaluated` events, correlated through existing command-run
IDs. They contain plan/configuration hashes, commit identity and fixed outcome
codes, excluding goals, methodology paths, source and command arguments.
Workflow-aware readiness events include `workflow_plan_hash`. The existing
private audit chain and unfinished-operation checks still apply. An audit event
records an assessment, not a guarantee that an output file was saved; reconcile
command outcomes and inspect the artifact after an interrupted invocation.

Local hashes do not prevent a malicious same-user rewrite of all state. Plans
do not prove the sufficiency of the selected checks, correctness of a financial
methodology or professional suitability. Planning adds no execution authority,
browser adapters, dynamic plugins, remote calls or telemetry export. The
separate executor requires exact plan approval and the existing runner controls.
