# Security design

finledgerpoli screens outgoing source, constrains execution and binds approvals to exact evidence so you can review changes with explicit control over disclosure and mutation. Its command is `finassist`; the [threat model](threat-model.md) describes the boundaries and assumptions.

## Source and request controls

| Area | Protection |
| --- | --- |
| Sensitive content | Screen both committed source versions for credential assignments, quoted JSON/dict keys, YAML/scalar values and configured sensitive patterns; apply the same patterns to reports and evidence. |
| Source identity | Read immutable Git blobs without checkout filters, hooks, fsmonitor or ambient Git overrides; bind base/head, source hashes and executable modes. |
| Coverage | Account for public binary assets as omissions without reading bytes; reject private paths even outside the allowlist. Require complete coverage unless partial model review is explicitly selected; readiness always requires complete coverage. |
| Generated files | Bind configured exclusions to outgoing requests and snapshots; retain publication screening, source rebuild comparisons and startup asset integrity checks. |
| Model responses | Validate structured findings, source references and line bounds. Keep source and provider text separate from fixed authority instructions. |
| Network | Require reviewed provider configuration, explicit network approval and approval of the exact outgoing-request hash. Existing keys do not enable a provider. |

## Execution and patch controls

Container images must be prebuilt and digest-pinned. Image values reject option-shaped arguments, and option termination precedes the image. Approved argument arrays run on screened committed snapshots with read-only source, no network, non-root execution, dropped capabilities, bounded scratch storage and resource limits. Cleanup is checked separately from the test result.

Patch proposals protect policy, build, dependency and script paths by default. Application requires inspection and approval of the exact patch hash, the original head and a clean feature branch. Parsing counts both sides of hunks, rejects undeclared sections and checks Git's complete path list before backups or mutation. Special files, binary/rename patches, stale heads and default/protected branches are rejected. Backups and guarded rollback preserve original bytes and supported modes; later changes prevent automatic restoration.

## Audit, spend and readiness controls

Operational commands record correlated lifecycle events with reduced metadata. Verification checks event envelopes, start/completion correspondence, reservation balances and incomplete runs. Readiness, export and incomplete-run queries verify and read in one SQLite transaction. Corrupt or unavailable audit state blocks operations before work begins. Unknown paid usage stays reserved until explicitly reconciled; zero-rate self-hosted usage is treated separately.

A saved record binds an action to hashes. Readiness requires matching configuration, base/head, source hashes and modes, complete coverage, fresh audited model review, passing required recipe records and cleanup, and no unknown spend or incomplete commands. Source must be clean before and after the CLI check. Stale or invalid evidence returns a blocked result. Observation checks receive derived approval status; malformed reconciliation values produce a bounded error.

## Repository and release controls

A local patch guard and a live server policy protect different boundaries. The read-only GitHub inspector reports classic PR, CI, administrator, force-push and deletion controls. A zero formal-approval count is an explicit policy observation. Your team must independently verify actual reviews, discussions and current server rules.

Adapt the [branch-protection template](maintainers/branch-protection-proposal.json) to your check identities, including native platform and isolation checks. Require up-to-date successful CI, PRs, resolved conversations, administrator enforcement and linear history; prevent force pushes and deletion. Require an independent formal approval when an eligible reviewer exists. With a sole author, select a workable approval policy explicitly; model comments are not GitHub approvals. See the [settings checklist](maintainers/repository-settings.md).

## Limits

- Pattern screening cannot establish confidentiality. Inspect the outgoing request yourself; prompt delimiters cannot make untrusted text safe.
- Local hash chains detect corruption but do not defeat a malicious same-user rewrite. Independent identities, retention and external integrity anchors require a separate integration.
- `check` tests committed source, not an uncommitted applied proposal. Commit a candidate in an isolated feature branch or use a separately reviewed adapter.
- Native tests cover Windows, macOS and Linux; real OCI isolation is exercised on Linux. Runtime sharing, contexts and host/kernel safety remain your responsibility. Local recipes require trusted-code approval and have no OS sandbox.
- Synthetic tests and mocked transports exercise contracts, not live protocol compatibility, model quality or the truth of findings. Version pins and release provenance do not replace complete dependency artifact-hash locking or security review.
- Configuration and local evidence do not authorize merges, deployment, settings changes or financial actions. No settings-write command or hosted production target is provided.

Credential key screening requires a credential word in the label: secret,
private, signing, encryption, access, client, master, auth or api, optionally
followed by access and then key (underscore/hyphen separators are supported).
Bare key, primary/foreign/partition/sort/cache/idempotency keys are not secrets
by name alone. The added matcher screens quoted literals of at least 12
characters and unquoted values; it excludes unquoted calls,
dotted references and digit-free uppercase-leading whole identifiers. Whitespace,
end of input and annotation punctuation (`[`, `]`, `)`, `,`, `;`) can end such an
identifier; `/`, `+`, `=`, `-`, `:` and `@` continue a candidate literal.
Uppercase-leading unquoted literals containing digits are screened too. Parseable
Python source identified by a `.py`/`.pyi` path uses a parsed annotation-free
view for label-assignment checks. Complete variable/parameter annotations,
including unions, forward references and parenthesized expressions, are hidden
from the credential-key heuristic. Other secret rules inspect both raw text and
this view, so typed password, token, credential-key and account/routing assignments
remain screened. Comments and custom patterns remain screened; source/request
bytes are never rewritten. Unparseable Python, YAML and text without a Python path
retain strict screening, including Markdown snippets, TypeScript and Kotlin.

Review output may quote an exact credential-label match from a screened Python
annotation in its hash-bound request; a value merely occurring elsewhere in source
is insufficient. The screening view retains the label and hides the complete
recorded annotation, including a union, so a new value appended after `=` remains
subject to the assignment patterns. Shorter `label: Type` quotes also pass; an
unrecorded union/subscript continuation is refused conservatively. This does not
prove output confidentiality. Original output strings
are screened before JSON escaping as well as in the serialized envelope. Proposed
and approved patches are parsed and applied only to private disposable copies for
screening each complete post-image with its path, before any target worktree
mutation. Rollback screens the original and current file with their Python paths
when an active policy is supplied. Approval, head, scope and recovery checks remain.

Identifier-shaped values followed by `(` are excluded; quote literal credentials.
Digit-free all-caps literal values can resemble constants and escape this heuristic.
A credential written as the annotation itself, such as a bare key-shaped type name,
is indistinguishable from a Python type reference and can escape the credential-key
heuristic. Filename and syntax are not proof of privacy. This supplements inspection,
not a confidentiality proof.

Confidential numeric screening in the policy-approved model gate and history
compares listed magnitudes in source, allowed fixtures, profiles and provider
free text before exposing findings. It fails closed on grouped short figures;
legacy `review` and `propose` remain outside this opt-in guard. See the
[pre-merge gate](pre-merge-gate.md#confidential-numeric-tokens-policy-approved-model-gate)
for exact exemptions, encoding limits and private token-file rules.
