# Security and readiness review

Baseline: `7a5cfb8be0e433e7abc461338de6f7fcce358266`.
Independent reviewer: Cursor CLI, Gemini 4 Argon High, October 28, 2026.
The model received all public committed files inline in ask mode, with sandbox
enabled and read/write/shell/MCP tool permissions denied. It performed a static
review; its findings and severity labels were not execution evidence.

## Reproduced findings and hardening in this change

| Area | Verified trigger | Resulting control |
|---|---|---|
| Container arguments | A leading option character could satisfy the old image pattern | Reject option-shaped image values and terminate CLI options before the pinned image |
| Sensitive content | Quoted keys and unquoted scalar values bypassed assignment screening | Cover JSON/dict/YAML/assignment forms; apply project patterns to scans, reports and evidence |
| Mixed commits | Unselected lockfiles/assets stopped ordinary source planning | List public assets as omissions without reading bytes; retain strict private-path rejection |
| Build/patch scope | Build metadata/scripts were editable under the default proposal scope | Protect build/dependency files and scripts; validate/normalize protected prefixes |
| Patch parsing | A removed SQL comment resembled a file header | Track hunk context and bind each header to its declared current path |
| Provider accounting | Null/zero/implausible usage could discard output or clear spend incorrectly | Keep paid unknown usage reserved; treat explicit zero-rate self-hosted usage separately |
| Evidence/error handling | Approved observations lacked the oracle's derived status; malformed Decimal escaped CLI handling | Return derived approval status and a fixed error for invalid reconciliation |
| Git/source identity | Ambient Git overrides and omitted mode metadata weakened source binding | Reduce child environment, disable hooks/fsmonitor, use literal paths and record executable modes |
| Audit | Operational failures/actions were missing from the shared trail | Correlated lifecycle/typed events, verified export and reservation/event cross-checking |
| Readiness | Success receipts lacked standalone revision/image binding | Head/snapshot/image/recipe receipts plus a configurable, audited evidence gate |

Tests use synthetic data, fake transports and actual bounded local Git/process
operations. CI separately exercises the real OCI isolation/cleanup path. A model
severity label was not used as the sole reason for a fix or acceptance claim.

## GitHub and deployment observations

The live baseline inspection found that this repository's main branch was
unprotected and had no ruleset. This is a server configuration gap; a local
proposal guard cannot substitute for branch protection. A read-only GitHub
inspection command now makes the distinction explicit. Proposed owner settings:

- Require PRs and current successful `test (3.11)`, `test (3.12)`, `test (3.13)`
  and `isolation` checks from GitHub Actions; require the branch to be up to date.
- Enforce rules for administrators, prevent force pushes/deletion, require
  conversation resolution and retain linear history.
- Require an independent formal approval when an eligible independent GitHub
  reviewer is available. Model comments are not GitHub approvals. With one owner
  account authoring all work, an approval count of one blocks self-authored PRs;
  any interim zero-approval policy must be an explicit owner decision.

No branch setting was changed by this review. The CLI/skill has no hosted service
or production deployment target; package/install/OCI checks establish their own
limited readiness scope. See [audit/readiness contracts](readiness-and-auditing.md).

## Remaining limitations and disposition

- Complete dependency artifact-hash locking/attestations and independent log
  anchoring remain improvements; version pins and local hash chains are limited.
- Native macOS path aliases and rootless Podman helper/environment configurations
  are not newly validated. Linux is the tested execution platform.
- `check` runs committed source. A future approved-patch-in-snapshot adapter could
  test a proposal before committing it; this change does not claim that ability.
- A model suggested random prompt delimiters and native structured-output modes
  for every provider. Delimiters do not establish a security boundary, and native
  protocol support varies. Existing separate policy/source input, strict result
  validation and explicit adapter compatibility remain the enforced controls.
- Live vendor/model quality and semantic correctness of findings are not proven
  by synthetic transports or by the independent static review.
