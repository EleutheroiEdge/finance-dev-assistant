# Architecture and trust boundaries

The runtime is a deterministic coordinator with replaceable model adapters.
Models produce advisory JSON and proposed patches; they never receive execution
tools or credentials through source context. This is a bounded developer workflow,
not an unbounded autonomous service.

1. `scope`: resolves immutable Git commits and their merge base, reads blobs
   without checkouts/filters and records both versions and hashes.
2. `security`: source paths, private formats, links, size and content checks.
3. `profiles`: project-adaptable software, finance and research review criteria.
4. `providers`: explicit HTTP protocol adapters with separate system instructions.
5. `review`: validates reports and binds findings to supplied source references.
6. `ledger`: concurrent budget reservations and a local tamper-evident hash chain.
7. `runner` / `workspace`: approved recipes on screened, committed snapshots.
8. `proposal` / `patching`: propose, inspect, approve, apply and guarded rollback.
9. `finance`: deterministic arithmetic and evidence-metadata oracles.
10. `cli`: visible operator actions, static HTML and bounded change watching.
11. `dashboard` / `statistics` / `health`: prebuilt local React UI, shared
    configuration validation and reduced, verified audit statistics. A loopback
    HTTP boundary uses exact origins and per-session tokens; browser actions
    cannot execute tools or access environment key values. See [dashboard](dashboard.md).

The same user's ability to edit an audit database or approvals is outside the
integrity guarantee. The chain detects accidental corruption; it is not a signed
external attestation. Hashes establish byte identity, not semantic truth or ownership.
Model source citations are checked for existence and line bounds, not entailment.

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

These references describe options and evaluation methods, not certification of
this implementation. Credentials and private context from another assistant are
never transferred to configure this project.
