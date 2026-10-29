# Auditing and readiness

Use finledgerpoli audit records and readiness checks to see which review requirements are satisfied and what blocks human review. Its command is `finassist`; a receipt is a hash-bound record of a completed action.

Operational CLI commands record start/completion/failure events in a private
SQLite ledger. Events carry UTC timestamps, a run ID, event schema, configuration
digest and reduced action identifiers. Model spend, proposal, apply, rollback
and recipe events share the run ID. Raw source, arguments, provider output,
environment values and test logs are excluded. Basic guide/demo/doctor/scan/render and audit queries do not add lifecycle events.

The global `--audit-dir PRIVATE_DIRECTORY` selects the state root. It takes
precedence over command-specific `--state-dir`. Otherwise commands use their
state directory, or the target repository's `.finassist`. Keep this directory
outside Git. Patch backups remain in the target repository's `.finassist/patches`.
Tracked private state is rejected; untracked state does not count as a source edit.

```sh
finassist --audit-dir YOUR_PRIVATE_STATE plan --repo . --base main --head HEAD --output YOUR_PACKET_FILE
finassist audit --state-dir YOUR_PRIVATE_STATE --export NEW_PRIVATE_EVENTS.jsonl --after 0 --limit 1000
```

Export pages contain sequence/previous/hash/payload and preserve chain links.
Advance `--after` to the last exported sequence for another page. Verification
cross-checks reservation balances against the event history in a transaction.
Readiness holds that same transaction across verification, open reservations,
incomplete commands and event reads. Export verification and its page read also
share a transaction.
Lifecycle verification rejects duplicate starts, mismatched completion commands
and caller-supplied envelope fields. Interrupted patch backups block further
application until reconciled; rollback records a terminal state.
Corrupt/unavailable auditing stops operational commands before work begins.


## Configurable evidence gate

Add named recipes to your reviewed provider configuration and set:

```json
{
  "required_recipes": ["unit", "isolation"],
  "blocking_severities": ["critical", "high"],
  "readiness_max_age_seconds": 86400,
  "allow_local_readiness": false
}
```

Required recipe names must exist in `recipes`; an empty requirement set blocks
readiness. Configure an approved immutable `runner_image` and dependencies.
Generate the review and checks under the same configuration and state root.
Changing configuration invalidates both review and check configuration digests.

```sh
finassist --config finassist.json --audit-dir YOUR_PRIVATE_STATE verify-gate \
  --repo . --expected-head YOUR_FULL_HEAD_SHA --packet YOUR_PACKET_FILE \
  --review YOUR_MODEL_REVIEW_FILE --receipt YOUR_UNIT_CHECK_FILE \
  --receipt YOUR_ISOLATION_CHECK_FILE --output NEW_PRIVATE_GATE_REPORT.json
```

The gate requires schema2 mode metadata, complete source coverage, a model review
with no configured blocking findings, fresh hash-matching audit receipts,
head/snapshot/image/recipe consistency, reviewed-file hash/mode coverage in the
tested snapshot, passing checks/cleanup and no unknown
spend. Offline analysis is not a model review. A freely edited success flag or
self-consistent file hash does not replace the corresponding audited event.
Local checks are ineligible unless explicitly selected in policy.
Stale or invalid review reports return `blocked` with stable reason codes.
The review's base must match the outgoing request base. The CLI checks source cleanliness
before and after evaluation; private untracked `.finassist` state is excluded.

## GitHub control inspection

Select `allow_network: true` in a reviewed configuration and explicitly approve
the metadata request. The configured model is never called by this command.

```sh
finassist --config finassist.json github-audit --repository YOUR_OWNER/YOUR_REPOSITORY \
  --branch main --allow-network --output NEW_PRIVATE_GITHUB_REPORT.json
```

The existing trusted `gh` executable performs bounded `github.com` metadata GETs
with its own authentication. Tokens are not copied into arguments or reports.
The command checks stable branch identity and reports classic PR/CI/admin/
force-push/deletion controls. Ruleset equivalence is explicitly left for review;
a missing classic policy does not claim that all rulesets are ineffective.
Zero formal approvals produces the observation `formal_approvals_not_required`,
even when PRs and CI are enforced. It is a visible policy choice, not a claim
that independent approval is required or has occurred.
PR approvals/threads and actual deployment outcomes are not inspected by this
configuration snapshot. No setting or PR is changed.

## Release and deployment

This package is a CLI/skill, not a hosted service. A release should bind the
reviewed commit, tested wheel/image digest, dependency provenance, install/smoke
results and a rollback version. Deployment to a service additionally needs its
named environment, identity, secret delivery, health checks, rollback procedure
and authorized release decision. Preserve the target project's checks; do not
treat a model report or this local gate as a release approval.

## Limits

A failure recording completion can happen after an operation; reconcile from
its start event and artifacts before retrying. An unfinished start is unknown,
not proof that work failed or never occurred. Do not prune/reset billing state.

Hashes are local integrity evidence, not signatures or protection against a
malicious same-user rewrite. An integration requiring independent records needs a separately controlled collector, identity/retention controls and external anchoring.
JSON Lines export is a local integration surface; no remote telemetry is enabled.

`eligible-for-human-review` means the configured prerequisites for human review are satisfied. It grants no merge,
security-policy, deployment or economic authority. Independently check the live
PR head, current required CI, independent approval, resolved discussions, holds,
branch protections and target environment before acting.

Local budget admission does not cap provider billing. See the [threat model](threat-model.md).
