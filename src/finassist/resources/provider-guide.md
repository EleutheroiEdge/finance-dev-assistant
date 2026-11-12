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

Run finassist --config finassist.json doctor for a local environment section.
It names Git's executable/version and feature floors (2.28 for evaluation fixtures,
2.40 for revision attributes, 2.45 for native no-lazy-fetch). Older Git retains
the full-clone fallback; missing optional features warn. Missing/unusable Git blocks.

Doctor names the configuration, state and user settings/cache directories. POSIX
writability uses os.access on the nearest existing directory. Windows writable is
null because its ACLs are not checked. No probe file is created; later writes may
still fail. A missing root/drive or an unexpandable user path reports
doctor_directory_unusable. Sensitive path text is redacted; keep this report private.

The deduplicated key-use rows have these fields:

| Field | Meaning |
|---|---|
| variable, state | Selected variable name and missing/empty/set. Values and lengths never appear. |
| used_by | Commands from the shared registry below. |
| uses[].provider, model, host | Provider/model and destination hostname for each use. |
| uses[].host_permission, network_permission | Host setting and approval still required. Configuration grants no request authority. |
| uses[].sends | Screened packet and instructions plus response schema. The key authenticates only this request. |
| uses[].limits | Separate packet/request, output-token and run/day/month limits per use. Configuration packet size excludes protocol framing. Gate request/run/day limits come from policy, with a separate fixed US$1,000,000 monthly adapter guard. |

For configuration and policy diagnostics together, use
finassist --config finassist.json doctor --repo . --base BASE --head HEAD --policy gate-policy.json --policy-sha256 HASH.
Configuration never overrides gate settings. A shared variable appears once with
separate uses preserving hosts, models and budgets. Findings that stop the selected
range join top-level blockers; other configuration keys and installation paths warn.
With --policy-file, the local policy preview authorizes nothing. Preflights select no
state directory. Gate run requires --state-dir; configuration plan/review use their
own output/audit options.

Empty or missing selected keys block model preflights with provider_key_empty or
provider_key_missing respectively. key_variable_set retains its existence meaning:
true for empty and non-empty assignments. key_value_read is true when any selected
value was inspected for emptiness, including a diagnostic configuration key alongside
a missing policy key. key_values_returned is false. In CI, an empty variable can mean
the event/job does not receive a configured secret, such as a fork PR.

Plain installation doctor treats key and directory findings as warnings; only
missing/unusable Git blocks that check (exit 1). A blocked range preflight exits 1.
A default provider key name aimed at another host warns: prefer a dedicated variable
and confirm that host. This warning grants no permission.

Proxy/custom-CA variable names are reported without values. Requests use
trust_env=False: inherited proxies/custom CAs are unsupported. No provider connection
is tested by doctor. Provider failures use this stable mapping:

| Failure | Code |
|---|---|
| HTTP 401 | provider_http_unauthorized |
| HTTP 403 | provider_http_forbidden |
| HTTP 404 | provider_http_not_found |
| HTTP 408 or client timeout | provider_timeout |
| HTTP 429 | provider_http_rate_limited |
| HTTP 5xx | provider_http_server_error |
| Other non-200 HTTP status | provider_http_error |
| Connection or protocol failure | provider_connection_failed |
| Malformed response data or other HTTP transport error | provider_transport_failed |

HTTP failures include http_status. Gate v2 reports preserve that safe numeric field
in reason_details: [{code, http_status}], with the code also in reasons. Response
bodies/headers and transport exception text never appear. Redirects are not followed,
no retries occur, and unknown billable reservations remain held until actual cost
is reconciled.

### Commands that use a selected key

This table is generated from the same registry doctor uses.

| Command | Key variable | Destination host | What is sent |
|---|---|---|---|
| review | api_key_env or provider default | configured endpoint | Screened packet and instructions, with the required response schema; the key authenticates only this request. No other local files or environment values. |
| propose | api_key_env or provider default | configured endpoint | Screened packet and instructions, with the required response schema; the key authenticates only this request. No other local files or environment values. |
| evaluate | api_key_env or provider default | configured endpoint | Screened packet and instructions, with the required response schema; the key authenticates only this request. No other local files or environment values. |
| gate run | model_review.api_key_env | model_review.allowed_host | Screened packet and instructions, with the required response schema; the key authenticates only this request. No other local files or environment values. |
| GitHub Action model-review mode | model_review.api_key_env | model_review.allowed_host | Screened packet and instructions, with the required response schema; the key authenticates only this request. No other local files or environment values. |

### Package self-check

Plain doctor reports the running code version, distribution metadata version and
Python executable path. A mismatch warns to reinstall with that interpreter. It
loads packaged hint tables, guides and schemas locally; missing or malformed
resources warn. Docker, Podman and GitHub CLI paths are found through absolute PATH
entries only, or null when absent; none is executed.

Version update status stays cached unless --check-updates is explicitly requested
with network-enabled configuration, or update notifications were enabled. This
performs no provider/model probe and changes no release or approval gate.
