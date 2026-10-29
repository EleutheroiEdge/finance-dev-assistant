# Provider configuration

Select a model provider for finledgerpoli with explicit endpoint, authentication and spend settings. Its command is `finassist`; start offline and inspect the outgoing request before enabling a remote review.

Run `finassist init --provider PROVIDER --model YOUR_MODEL --output finassist.json`.
Edit the generated JSON; the CLI accepts it only with `--config finassist.json`.
Keep your project policy and provider setup under review. Configuration is not
authorization to transmit: each request also needs `--allow-network` and the
hash of the inspected outgoing request.

Provider settings:

- `provider`: `offline`, `openai`, `anthropic`, `google`, `compatible`, `ollama`.
- `model`: the exact identifier available to your account; no vendor is preferred.
- `endpoint`: optional for built-in services; mandatory for `compatible`.
- `allowed_hosts`: exact hostnames for custom endpoints. HTTPS is required except
  local loopback Ollama. Credentials in URLs, redirects and proxy inheritance are refused.
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
