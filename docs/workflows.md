# Workflow contracts

Review committed changes, reproduce numerical behavior and prepare approved patches with finledgerpoli. Its command is `finassist`; follow the target project’s governing methodology throughout.

A receipt is a saved action record bound to exact source, configuration and execution hashes.

## Source review

Use the project's governing methodology/specification as authority. Open a scoped
task, resolve its commits, inspect the outgoing request and identify required
baseline/candidate cases. A source-only review cannot claim a run was executed.
Coverage omissions are explicit and block external model review by default.
Amend the allowlist and rebuild the outgoing request for complete review. You may
set `allow_partial_review` to true for a scoped review; its report remains labeled
partial and lists omissions. An outgoing request with no included source never calls a model.

Choose `finance-saas` for tenant authorization, money movement, audit and recovery;
`investment-research` for as-filed periods, source precedence, approved inputs and
revisions; `quant-review` for portfolio calculations and optimization invariants;
or `general` for ordinary engineering. Profiles are checklists, not economic canon.

## Evidence before conclusions

For material numerical changes, compare immutable baseline and candidate source
on the same synthetic book. Recompute final cash, fees, weights and disclosures.
Use order reversal, lot splitting, identity substitutions and mode boundaries
only where the specification says those should be invariant. Freeze prices and
label hypothetical values. A changed number can be correct; a matching number
can result from an unexercised path.

Research records carry entity, units, period kind, start/end, publication and
retrieval timestamps. A decision cannot use a later filing. Draft analyst
judgments never enter approved calculations. Missing evidence is reported as
missing, not replaced by zero or inferred from model memory.

## Test execution

Configure named `recipes`, for example `unit: ["python", "-m", "pytest", "-p",
"no:cacheprovider"]`. Build and inspect a suitable test image yourself, install
the project's pinned dependencies there, and configure its immutable
`runner_image` digest. The assistant does not pull images automatically. Only
allowlisted text files from the chosen commit enter the snapshot. Add synthetic
fixtures and build metadata to the allowlist as needed; never add private input roots.

An example test image is supplied at `examples/runner.Dockerfile`, with a pinned
public Python base and the exact development lock. The Docker build context is
allowlisted by `.dockerignore`. Build it explicitly, inspect its local image id,
and use that `sha256:` id as `runner_image`; no registry push is necessary.
The image does not bundle a project's engine or private data. Adapt dependencies
through a reviewed image build for your project. Git-dependent integration tests
also need Git installed in that project image.

The default container is network-disabled, non-root, capability-dropped and read-only, with scratch temporary storage and resource limits. A test requiring writable project files needs an explicit reviewed adapter; do not grant the real checkout write access.

`--backend local --approve-local` is for trusted recipes only. It receives a
minimal environment and temporary HOME. Your team owns that decision. Logs stay local; only recipe/exit/hash receipts are
intended as reduced evidence. Logs are not automatically sent to a provider.

## Proposed changes

A proposal is a JSON artifact containing the exact head and a text Git patch.
Inspect it, create a clean feature branch, then pass its approval hash to `apply`.
The assistant rejects protected paths, special files, rename/binary patches,
stale heads, dirty worktrees and common default branch names. Coordinate exclusive ownership of the worktree. Re-run the project's checks and ordinary PR review.

Backups are private under `.finassist`. Rollback requires the original head and
unchanged post-apply bytes; later work stops rollback. An interrupted
apply without its receipt requires manual reconciliation from the saved backup.
The assistant does not force history, stage, commit or push.

Build/dependency files and `scripts/` are protected from proposals by default.
Configure `protected_paths` deliberately for your project; entries also protect
descendants without a trailing slash. `protected_branches` accepts glob patterns.
The local branches named by fetched remote default-HEAD references are always
excluded from patch application. Verify fetched references and current server policy yourself.

New outgoing requests use schema2 and carry executable-mode metadata. Schema1
outgoing requests remain inspectable but cannot pass `verify-gate`; rebuild old outgoing requests.
Public image assets are listed as omissions without reading their bytes.
Sensitive data/key paths still block until resolved even outside the source allowlist.

Read [auditing/readiness](readiness-and-auditing.md) for event export, required
recipes, blocking severities and the explicit GitHub metadata inspection command.

## Proactive operation

`watch` is a bounded foreground observer of committed-head changes. It emits
risk and suggested checks when the head changes and stays quiet otherwise.
It does not install a timer, create accounts, call a paid model, submit issues
or restart services. Use its output to dispatch the next authorized task.

## Limits

Each check receipt carries its committed head, snapshot digest, recipe digest,
runtime image and cleanup result. `check` tests committed source; it does not
validate uncommitted applied patches. Commit a candidate on an isolated feature
branch before testing it, or use a separately reviewed project adapter.

Container isolation depends on the image, daemon and host kernel. Local execution has no OS filesystem isolation; process supervision provides cleanup only. Multi-file patch checks are not atomic against other same-user writers. Prompt/source text cannot authorize actions. See the [threat model](threat-model.md).
