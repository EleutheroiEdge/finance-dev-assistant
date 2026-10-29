# Workflow packs

Use finledgerpoli's local declarative packs to adapt financial validation to a
project without adding an executable plugin. Resolve reviewed inputs into a
frozen configuration, a version-1 workflow template and a provenance record.
Resolution runs no checks or models and never activates the generated files.

## Four kinds of pack

- **Profile:** named checklist arrays. New names can supplement the registry;
  an existing definition must be identical or resolution fails. Profiles remain
  untrusted review data, with no shell, network or financial authority.
- **Workflow:** one complete version-1 [template](workflow-plans.md), including
  the goal, methodology references, requirements and steps. Exactly one workflow
  pack is required per bundle.
- **Checks:** additional `requirements` and `steps`. Their dependencies can
  reference steps in the workflow pack. The combined graph must still account
  for every requirement, use unique IDs/recipes and remain acyclic.
- **Policy:** restrictive caps and required-evidence unions, applied below the
  reviewed base configuration. A policy cannot provide new commands or enable
  capabilities.

Each JSON pack has exactly `schema_version: 1`, `name`, stable semantic `version`
(for example `1.0.0`), `kind`, `compatibility` and `data`. Compatibility is
`{"config_schema": 1, "workflow_schema": 1}`. Unknown fields, unsupported
versions, duplicate JSON keys and nonfinite numbers are refused. Packs are not
installed, imported as code, downloaded or discovered recursively.

The [synthetic starter bundle](../examples/workflow-packs/bundle.json) composes
all four kinds. Its references are paths relative to `--repo`, with exact SHA-256
digests of file bytes. Whitespace changes therefore require an updated pin.
Local references must pass the existing private-path/content screening and
cannot traverse directories, use drive/absolute paths or pass through symlinks.
There are at most 16 uniquely named pack files, each at most 128,000 bytes.
Source screening is supplementary; inspect all inputs for private information.

## Bind the project, then resolve

Adapt the starter to the target project's approved methodology and reviewed
recipes. The starter's `docs/cash-policy.md`, `unit` and `cash` are placeholders
for project-owned rules and existing checks; resolution does not establish
their financial correctness. Methodology bytes are bound from committed source
when the later workflow plan is created.

Bundle fields are `schema_version`, `name`, `profile`, `packs` and
`recipe_bindings`. A reference is `{"path": "packs/checks.json", "sha256": "FULL_SHA256"}`.
Recipe bindings map symbolic pack contracts to names already present in the
base configuration's `recipes`, for example `{"unit": "python-unit", "cash": "cash-invariants"}`.
An unlisted contract uses its own name. Unknown targets, unused bindings and
two obligations resolving to one recipe are refused. This mapping never supplies
arguments or grants execution permission. All base `required_recipes` remain
required and must appear in the resolved graph.

```sh
finassist --config finassist.json workflow resolve --repo . \
  --bundle examples/workflow-packs/bundle.json --output .finassist/resolved-cash
```

The output directory must be new. It contains private `config.json`,
`template.json` and `resolution.json` files. Stdout reports their configuration,
template and resolution hashes, with `execution_authorized: false`. Failure can
leave partial files; inspect them and use a new directory rather than treating
partial output as a successful resolution. No existing configuration is edited.
Each generated document is limited to 2,000,000 encoded bytes including its
trailing newline, so it remains within the corresponding CLI input limit.

Inspect the resulting settings and provenance before using them:

```sh
finassist --config .finassist/resolved-cash/config.json plan --repo . \
  --base main --head HEAD --output .finassist/context.json
finassist --config .finassist/resolved-cash/config.json workflow plan --repo . \
  --packet .finassist/context.json --template .finassist/resolved-cash/template.json \
  --resolution .finassist/resolved-cash/resolution.json --output .finassist/workflow.json
```

`--resolution` checks that the provenance record matches the exact effective
configuration/template and links its hash to the plan's audit event. The plan
format remains version 1, with its existing hashes and approvals. Runtime
permissions come from the inspected configuration and explicit execution gates,
not the provenance record. Existing commands without packs remain compatible.

## Policy composition

Numeric caps use the minimum of the base value and every policy contribution:
`max_file_bytes`, `max_packet_bytes`, `max_output_tokens`, `timeout_seconds`,
`readiness_max_age_seconds`, `max_run_usd`, `daily_budget_usd` and
`monthly_budget_usd`. Integer limits retain their existing supported range;
policy cost caps range from zero to one billion USD. A larger cap cannot loosen
the base limit. Equal numeric cost caps are normalized so declaration order
does not change the effective configuration.

`allow_network`, `allow_partial_review` and `allow_local_readiness` accept only
`false`, to disable a base capability. Enabling a capability requires a separate
review of the base configuration. `required_recipes` and `blocking_severities`
use unions, so they cannot remove an existing gate. Policy-required recipes use
the same explicit bindings and must be covered by the final graph.

Policies cannot set providers, endpoints, key variables, source allowlists,
images, recipe arguments, plugin paths or arbitrary settings. No last-writer
rule can overwrite stronger restrictions. Conflicting profile/graph definitions
fail visibly. Base profile-file checklists are materialized into the generated
configuration and `profile_files` is cleared, so moving outputs does not silently
reload different definitions. This is an explicit snapshot, not a live overlay.

## Provenance and limits

`resolution.json` records the source pack paths, raw digests, names, versions and
kinds; the bundle/base/effective configuration hashes; the template hash; and
which source/rule contributed each setting. `resolution_hash` covers this record
except itself. `workflow_bundle_resolved` and resolution-aware plan audit events
record hashes, excluding raw profiles, paths and pack contents.

Changing pack files does not mutate already-resolved outputs. Re-resolve
explicitly and compare the new hashes when adopting a change. Normal workflow
preflight and [execution](workflow-execution.md) continue to bind the exact
effective inputs. A resolution hash establishes byte identity, not authorship,
organizational authority, sufficiency of financial checks or professional
approval. This is a same-user local configuration mechanism, not a multi-tenant
policy boundary or defense against a malicious rewrite of all local state.

Keep outputs, private methodology and any project-specific packs local and out
of public source as appropriate. Resolution does not authorize outgoing model
requests, patch application, merge, deployment, credentials or trading. The
starter's network-disabled policy also means its offline review cannot satisfy
the separate model-review requirement without a separately reviewed configuration.
