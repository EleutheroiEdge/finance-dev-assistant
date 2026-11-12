# Provider configuration

Select a model provider for finledgerpoli with explicit endpoint, authentication and spend settings. Its command is `finassist`; start offline and inspect the outgoing request before enabling a remote review.

Run `finassist init --provider PROVIDER --model YOUR_MODEL --input-usd-per-million IN --output-usd-per-million OUT --output finassist.json`.
A paid provider needs both prices from your provider's price list; without them `init` refuses with
`provider_prices_required`. Add `--api-key-env NAME` to choose the key variable.
Edit the generated JSON; the CLI accepts it only with `--config finassist.json`.
Keep your project policy and provider setup under review. Configuration is not
authorization to transmit: each request also needs `--allow-network` and the
hash of the inspected outgoing request.

Provider settings:

- `provider`: `offline`, `openai`, `anthropic`, `google`, `compatible`, `ollama`.
- `model`: the exact identifier available to your account; no vendor is preferred.
- `endpoint`: optional for built-in services; mandatory for `compatible`.
- `allowed_hosts`: exact hostnames for custom endpoints. HTTPS is required, except that an `ollama` or `compatible`
  endpoint on loopback (127.0.0.1, localhost or ::1) may use plain HTTP. Credentials in URLs, redirects and proxy inheritance are refused.
- `api_key_env`: the variable name, never its value. Built-in adapters use
  `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, or `GEMINI_API_KEY`. Compatible services
  can select their own variable. An empty name means no authentication header.
- `auth_header`: `Authorization` (bearer), `api-key`, or `x-api-key` for compatible
  and custom Responses services. Built-in Anthropic/Google use their native header.
- `allow_network`: explicit configuration permission, false by default.
- `input_usd_per_million`, `output_usd_per_million`: user-maintained prices;
  both must be positive for remote paid services.
- `max_run_usd`, `daily_budget_usd`, `max_output_tokens`, `timeout_seconds`:
  local safeguards; provider billing and cancellation are separate.

Primary protocol references:
- https://developers.openai.com/api/docs/guides/text
- https://platform.claude.com/docs/en/api/messages
- https://ai.google.dev/api/generate-content
- https://docs.ollama.com/api/chat

## Limits

The transport uses bounded HTTP reads and response size, no automatic retries,
no redirects and no environment-proxy trust. HTTP phase timeouts can each consume
time; the streaming deadline is checked between chunks. Remote service work may
continue after a client disconnects. Failed or unknown billable attempts remain
reserved until `reconcile-budget --reservation ID --actual-usd AMOUNT` records
user-verified cost. Missing, zero or implausibly large usage also remains
reserved. Self-hosted Ollama with zero configured rates settles at zero; that is
your cost assumption, not a promise that hosting is free.

Examples in `examples` are templates with model placeholders, not live credentials.
For Azure-style deployments, configure the appropriate deployment endpoint,
approved hostname and API-key header; verify that endpoint accepts the selected
Responses or Chat Completions shape. Managed-cloud authentication protocols such
as cloud request signing are not emulated by a bearer token adapter.

No live provider compatibility or comparative-quality result is implied by the
mocked protocol contract tests. Use a synthetic, reviewed outgoing request for your first live check.

Cached and reasoning token prices may differ from configured rates; reconcile with actual billing. No automatic fallback is selected. See the [threat model](threat-model.md).

## Installation and key diagnostics

Run `finassist --config finassist.json doctor` for a local `environment` section.
It names the Git executable and version, feature floors (2.28 for evaluation
fixture creation, 2.40 for revision attributes, 2.45 for native no-lazy-fetch),
the chosen configuration and state directory, and user settings/cache directories.
Older Git retains the existing full-clone fallback; missing optional features
have warnings, while a missing/unusable executable is a blocker. Directory
writability is estimated from metadata and access checks: doctor creates no probe
files, and ACLs or mount restrictions can still refuse a later write. Sensitive
path text is replaced with `[redacted]`. Keep this local report private.

The key-use table has these fields:

| Field | Meaning |
|---|---|
| `variable`, `state` | Variable name and `set`, `empty`, or `missing`; only the selected variable's presence and emptiness are inspected. Values never appear. |
| `used_by` | Configuration uses: review, propose, evaluate. Policy use: gate run. |
| `uses[].provider`, `model`, `host` | The configured provider/model and destination hostname. |
| `uses[].host_permission`, `network_permission` | The setting allowing this host and the approval still required. Configuration alone never authorizes a request. |
| `uses[].sends` | Screened packet and instructions plus the required response schema. The key authenticates this request; other environment values and local files are not sent. |
| `uses[].limits` | Each use's packet/request, output-token and run/day/month limits. Configuration packet size excludes instructions and protocol framing. The gate policy has a request cap and run/day reservations; its adapter also applies a fixed US$1,000,000 monthly ledger guard, shown separately from configurable policy limits. |

For both configuration and policy uses in one report, run
`finassist --config finassist.json doctor --repo . --base BASE --head HEAD --policy gate-policy.json --policy-sha256 HASH`.
The configuration is displayed alongside the policy; it does not override gate
settings. A shared variable appears once with separate `uses` preserving different
hosts, models and budgets. The range's top-level status describes that route;
environment diagnostics and any other configuration's blockers remain separate.
With `--policy-file`, the policy is a local preview and authorizes nothing.
Preflights do not select a gate state directory: gate run requires `--state-dir`.

An empty or missing selected key blocks a model preflight. A known provider's
default key name assigned to a different host produces a warning: use a dedicated
variable and confirm the exact host. This warning grants no permission.
Proxy and custom-CA environment variable names are reported without their values.
The provider transport uses `trust_env=False`; inherited proxies and custom CA
settings are unsupported. No provider connection is tested by doctor.

HTTP failures include `http_status`. HTTP 401, 403, 404 and 429 have distinct
`provider_http_unauthorized`, `provider_http_forbidden`,
`provider_http_not_found` and `provider_http_rate_limited` codes and hints.
Other statuses retain `provider_http_error`. Response bodies and headers are
never echoed, redirects are not followed, and retries are never automatic.
Unknown billable reservations stay held until actual cost is reconciled.

Version status remains cached unless you explicitly request `doctor --check-updates`
with network-enabled configuration, or have opted into update notifications.
This performs no provider/model probe and changes no release or approval gate.
