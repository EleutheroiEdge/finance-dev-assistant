# Architecture and trust boundaries

finledgerpoli coordinates source review, deterministic checks and approved patch proposals through replaceable adapters. Its command is `finassist`.

Models produce advisory JSON and proposed patches through bounded requests. They receive no execution tools or credentials through source context.

1. `scope`: resolves immutable Git commits and their merge base, reads blobs
   without checkouts/filters and records both versions and hashes.
2. `security`: source paths, private formats, links, size and content checks.
3. `profiles`: project-adaptable software, finance and research review criteria.
4. `providers`: explicit HTTP protocol adapters with separate system instructions.
5. `review`: validates reports and binds findings to supplied source references.
6. `ledger`: concurrent budget reservations and a local tamper-evident hash chain.
7. `runner` / `workspace`: approved recipes on screened, committed snapshots.
8. `proposal` / `patching`: propose, inspect, approve, apply and guarded rollback.
9. `finance`: deterministic arithmetic and evidence-metadata checks.
10. `cli`: explicit user actions, static HTML and bounded change watching.
11. `dashboard` / `statistics` / `health`: prebuilt local React UI, shared
    configuration validation and reduced, verified audit statistics. A loopback
    HTTP boundary uses exact origins and per-session tokens; browser actions
    cannot execute tools or access environment key values. See [dashboard](dashboard.md).
12. `workflow`: versioned declarative validation plans, committed methodology
    and recipe bindings, acyclic dependency contracts and offline preflight.
    Optional workflow-aware readiness adds evidence obligations through the
    existing verifier. This is not an executor. See [workflow plans](workflow-plans.md).

Finance profiles separate source authority, approved analyst judgments and
algorithmic decisions. Do not replace a project's methodology with generic
tax rates, holding-period rules, optimization constraints or credential assumptions.
No issuer scoring, securities recommendation or order submission is implemented.

## Why a small core

Portable skills describe method; deterministic code enforces contracts. Native
coding-agent SDKs can be added as adapters when interactive tool loops are needed.
The current adapters are direct model requests, not bundled native coding agents.
Checkpoints and a larger workflow framework are appropriate when jobs need durable
resumption, but do not improve a bounded review merely by adding orchestration.

Research informing this design:
- https://agentskills.io/specification
- https://developers.openai.com/blog/codex-as-a-platform
- https://code.claude.com/docs/en/agent-sdk/overview
- https://www.anthropic.com/research/demystifying-evals-for-ai-agents
- https://modelcontextprotocol.io/docs/draft/tutorials/security/security_best_practices

## Limits

The same user's ability to edit an audit database or approvals is outside the
integrity guarantee. The chain detects accidental corruption; it is not a signed
external attestation. Hashes establish byte identity, not semantic truth or ownership.
Model source citations are checked for existence and line bounds, not entailment.

These references describe options and evaluation methods, not certification of
this implementation. Credentials and private context from another assistant are
never transferred to configure this project.

The installed code, dependencies, Python, Git, reviewed configuration and host OS are components you rely on. Source and model output remain untrusted. See the [threat model](threat-model.md).
