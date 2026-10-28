# Security and readiness review

This document describes durable control checks and limitations. Revision-specific
reviewer verdicts, execution results and repository settings belong in PR/release
records. A static review or severity label is not execution evidence.

## Reproduced findings and hardening in this change

| Area | Verified trigger | Resulting control |
|---|---|---|
| Container arguments | A leading option character could satisfy the old image pattern | Reject option-shaped image values and terminate CLI options before the pinned image |
| Sensitive content | Quoted keys and unquoted scalar values bypassed assignment screening | Cover JSON/dict/YAML/assignment forms; apply project patterns to scans, reports and evidence |
| Mixed commits | Unselected lockfiles/assets stopped ordinary source planning | List public assets as omissions without reading bytes; retain strict private-path rejection |
| Build/patch scope | Build metadata/scripts were editable under the default proposal scope | Protect build/dependency files and scripts; validate/normalize protected prefixes |
| Patch parsing | Hunk content and traditional file headers can be confused | Count both hunk sides, reject undeclared sections and compare Git's complete path list before backups/mutation |
| Provider accounting | Null/zero/implausible usage could discard output or clear spend incorrectly | Keep paid unknown usage reserved; treat explicit zero-rate self-hosted usage separately |
| Evidence/error handling | Approved observations lacked the oracle's derived status; malformed Decimal escaped CLI handling | Return derived approval status and a fixed error for invalid reconciliation |
| Git/source identity | Ambient Git overrides and omitted mode metadata weakened source binding | Reduce child environment, disable hooks/fsmonitor, use literal paths and record executable modes |
| Audit | Operational failures/actions were missing from the shared trail | Correlated lifecycle/typed events, verified export and reservation/event cross-checking |
| Readiness | Success receipts lacked standalone revision/image binding | Head/snapshot/image/recipe receipts plus a configurable, audited evidence gate |

Tests use synthetic data, fake transports and actual bounded local Git/process
operations. CI separately exercises the real OCI isolation/cleanup path. A model
severity label was not used as the sole reason for a fix or acceptance claim.

## Evidence consistency

A check run under a narrower configuration must not qualify a broader review.
Receipts and audit events bind the exact configuration; the gate verifies source
hashes/modes, base/head consistency and complete coverage in the tested snapshot.
Invalid or stale reviews produce blocked reports. CLI readiness checks clean
source before and after evaluation, excluding the tool's private state.

Readiness reads verified events, open reservations and incomplete commands in
one database transaction. Export and incomplete-run queries also bind their
verification and reads. Regression cases cover interrupted patch backups,
lifecycle mismatches, primary evidence-side line bounds, inherited routing/debug
variables and ruleset-only branch classification. These checks are not a
security certificate or proof of semantic correctness.

## GitHub and deployment observations

A local proposal guard cannot substitute for server branch protection. The
read-only inspector distinguishes PR requirements from formal approval counts;
zero is an explicit observation, not a guarantee of independent approval.
Fork owners should review the generic [policy template](branch-protection-proposal.json),
adapt check identities to their own CI and select settings with their operator:

- Require PRs and current successful `test (3.11)`, `test (3.12)`, `test (3.13)`
  and `isolation` checks from GitHub Actions; require the branch to be up to date.
- Enforce rules for administrators, prevent force pushes/deletion, require
  conversation resolution and retain linear history.
- Require an independent formal approval when an eligible independent GitHub
  reviewer is available. Model comments are not GitHub approvals. With one owner
  account authoring all work, an approval count of one blocks self-authored PRs;
  any interim zero-approval policy must be an explicit owner decision.

The CLI/skill has no settings-write command, hosted service or production target.
Package/install/OCI checks establish their own limited readiness scope.
See [audit/readiness contracts](readiness-and-auditing.md).

## Remaining limitations and disposition

- Complete dependency artifact-hash locking/attestations and independent log
  anchoring remain improvements; version pins and local hash chains are limited.
- Native macOS path aliases and rootless Podman helper/environment configurations
  are not newly validated. Linux is the tested execution platform.
- `check` runs committed source. A future approved-patch-in-snapshot adapter could
  test a proposal before committing it; this change does not claim that ability.
- Prompt delimiters do not establish a security boundary, and native
  protocol support varies. Existing separate policy/source input, strict result
  validation and explicit adapter compatibility remain the enforced controls.
- Live vendor/model quality and semantic correctness of findings are not proven
  by synthetic transports or by the independent static review.
