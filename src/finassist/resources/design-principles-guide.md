# Design principles

finledgerpoli combines a small deterministic core with replaceable model adapters, local state and explicit approvals. Its command is `finassist`; these principles explain the design choices and the primary sources behind them.

## Keep authority outside model text

Separate input/output checks, tool validation and human approval for sensitive actions. Typed commands and exact source/patch approvals keep a source comment, model vote or report from granting authority. The core provides no GitHub mutation or deployment tools. [Guardrails and human review](https://developers.openai.com/api/docs/guides/agents/guardrails-approvals).

Keep provider reasoning, recipe execution, durable state and host-specific skills behind separate interfaces. Native SDKs can be adapted at those boundaries without requiring one model or a large orchestration framework. [Managed agent architecture](https://www.anthropic.com/research/managed-agents).

## Observe decisions and failures safely

Record correlated UTC events with stable schemas and reduced metadata. Model calls, tools and guard decisions need observable outcomes, including unknown ones. Export local JSON Lines instead of automatically sending prompts or logs to an observability vendor. [Agent observability](https://developers.openai.com/api/docs/guides/agents/integrations-observability), [OpenTelemetry GenAI conventions](https://github.com/open-telemetry/semantic-conventions-genai).

Integrations that require organizational controls should add independently managed storage and retention, identities, authorization, external integrity anchors and telemetry access controls.

## Treat release infrastructure as a separate boundary

Check live server branch rules, required checks, exact revisions, independent approvals and unresolved discussions. A read-only inspector informs that review. [Protected branches](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches).

Use minimal workflow permissions, SHA-pinned actions and no credential persistence in CI. The approval-gated release job separately receives its narrowly scoped publishing permissions and records provenance. Keep pinned dependencies under review. [Actions secure use](https://docs.github.com/en/actions/reference/security/secure-use).

Bind deployment approval to an exact target and artifact or plan digest, with health checks and rollback. Protected environments provide another approval boundary. [Deployment environments](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments).

## Evaluate the workflow as well as the model

Exercise input formats, argument boundaries, source and action-record binding, stale policy, process failures and audit corruption with regression tests. Independently adjudicate defect detection on private synthetic cases across candidate models. Use [OWASP's agentic risk taxonomy](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) to inform test selection.

## Configure without silent escalation

Choose exact models, endpoints and approved hosts, budgets, sensitive patterns, source scope, protected files and branches, required recipes, blocking severities, state location and evidence age. Defaults remain offline and operations block until unresolved prerequisites are satisfied.

## Limits

Local hash chains cannot prevent their owner rewriting state; use an independent collector when required. Local patch safeguards do not protect a remote branch. Version pins and attestations cannot replace dependency artifact-hash locking or correctness review. Regression results do not establish comprehensive coverage of a risk taxonomy or model quality. The package creates no environments, retrieves no production secrets and deploys no services. There is no automatic provider fallback, GitHub-write tool, background scheduler, telemetry or deployment activation. See the [threat model](threat-model.md).
