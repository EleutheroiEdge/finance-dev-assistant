# Workflow contracts

## Source review

Use the project's governing methodology/specification as authority. Open a scoped
task, resolve its commits, inspect the context packet and identify required
baseline/candidate cases. A source-only review cannot claim a run was executed.
Coverage omissions are explicit and block external model review by default.
Amend the allowlist and rebuild the packet for complete review. An operator may
set `allow_partial_review` to true for a scoped review; its report remains labeled
partial and lists omissions. A packet with no included source never calls a model.

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

The default container is network-disabled, non-root, capability-dropped, read-only
with scratch temporary storage and resource limits. It is not a defense against
a compromised container daemon or host kernel. A test requiring writable project
files needs an explicit project adapter; do not grant the real checkout write access.

`--backend local --approve-local` is for trusted recipes only. It receives a
minimal environment and temporary HOME, but no OS filesystem isolation. The
operator owns that decision. Logs stay local; only recipe/exit/hash receipts are
intended as reduced evidence. Logs are not automatically sent to a provider.

## Proposed changes

A proposal is a JSON artifact containing the exact head and a text Git patch.
Inspect it, create a clean feature branch, then pass its approval hash to `apply`.
The assistant rejects protected paths, special files, rename/binary patches,
stale heads, dirty worktrees and common default branch names. Coordinate exclusive
ownership of the worktree; checks do not make a multi-file apply atomic against
other same-user writers. Re-run the project's checks and ordinary PR review.

Backups are private under `.finassist`. Rollback requires the original head and
unchanged post-apply bytes; later operator work stops rollback. An interrupted
apply without its receipt requires manual reconciliation from the saved backup.
The assistant does not force history, stage, commit or push.

## Proactive operation

`watch` is a bounded foreground observer of committed-head changes. It emits
risk and suggested checks when the head changes and stays quiet otherwise.
It does not install a timer, create accounts, call a paid model, submit issues
or restart services. Use its output to dispatch the next authorized task.
