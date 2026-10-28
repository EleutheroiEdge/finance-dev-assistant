# Production agent design: research and decisions

Reviewed October 28, 2026. These are implementation choices for a portable
developer assistant, not an assertion of certification or measured model quality.

## Keep authority outside model text

OpenAI separates input/output checks, per-tool validation and human approval
for sensitive side effects. This project follows that split through typed
commands, exact source/patch approval and a core without GitHub mutation or
deployment tools. A source comment, model vote or report cannot create authority.
[Guardrails and human review](https://developers.openai.com/api/docs/guides/agents/guardrails-approvals).

Anthropic's current Managed Agents design separates model reasoning, execution
and durable sessions behind stable interfaces. Here the provider adapters,
isolated recipe runner, local state and host-specific skills remain separate.
Native SDK integration can be added at those boundaries; no particular model
or large orchestration framework is required by the core.
[Scaling Managed Agents](https://www.anthropic.com/research/managed-agents).

## Observe decisions and failures safely

OpenAI's tracing guide treats model calls, tools, handoffs and guards as workflow
events. OpenTelemetry's GenAI conventions likewise describe common spans,
events and usage signals; their current definitions live in a separate repository.
We use correlated UTC events and stable schema/version fields with reduced
metadata and local JSON Lines export. No prompts or secret-bearing logs are
automatically sent to an observability vendor.
[OpenAI observability](https://developers.openai.com/api/docs/guides/agents/integrations-observability),
[OpenTelemetry GenAI conventions](https://github.com/open-telemetry/semantic-conventions-genai).

An enterprise adapter should add independently controlled storage/retention,
SSO identities, authorization, external integrity anchors and telemetry access
controls. A local hash chain detects corruption but cannot stop its owner from
rewriting the database. Do not label it an immutable compliance archive.

## Treat release infrastructure as a separate boundary

GitHub documents server-side branch rules, required checks and merge conditions.
Our read-only inspector surfaces missing controls; it does not imply that local
patch safeguards protect a remote branch. Required check identities, exact
revisions, fresh approval and unresolved discussions need live verification.
[Protected branches](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches).

GitHub recommends minimal workflow token permissions and pins for trusted
actions. The checked-in CI uses read-only permissions, immutable action references
and no credential persistence. Dependency versions are pinned; complete
artifact-hash locking and provenance attestations remain a supply-chain improvement.
[Actions secure use](https://docs.github.com/en/actions/reference/security/secure-use).

Deployment environments can enforce additional protection before jobs or secrets
become available. A project adapter should bind release approvals to an exact
target and artifact/plan digest, with health checks and rollback. This package
does not create an environment, retrieve production secrets or deploy services.
[Deployment environments](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments).

## Evaluate the harness as well as the model

OWASP's Agentic Top 10 covers goal manipulation, tool/identity misuse and
agentic supply-chain risk. Our regression cases exercise input formats,
argument boundaries, source/receipt binding, stale policy, failures and audit
corruption. This is evidence about tested controls, not a claim of comprehensive
OWASP coverage. Maintain private synthetic adversarial cases and independently
adjudicate real defect detection across candidate models.
[OWASP Agentic Top 10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/).

## Configuration without silent escalation

Users choose exact models, endpoints/approved hosts, limits, sensitive patterns,
source scopes, protected paths/branch patterns, required recipes, blocked
severities, state location and evidence age. Defaults remain offline and
fail closed. There is no automatic provider fallback, broad GitHub-write tool,
background scheduler, remote telemetry or deployment activation.
