# Troubleshooting

When finledgerpoli refuses something, it prints one JSON record on stderr and exits nonzero:

```json
{"status":"error","code":"file_limit_exceeded","limit":48000,"bytes":51200,"hint":"..."}
```

- **`code`** is stable: scripts and agents should key on it.
- **`hint`** says what to do. It is fixed text for that code and never contains anything from your run.
- **The other fields** are bounded details such as an option name, a limit or a size. They are never values, paths or file contents.

## First steps
1. **Read the explanation.** Run `finassist explain CODE`, or paste the whole record: `finassist explain '{"status":"error","code":"..."}'`. It works offline and prints what happened, how to fix it, related codes and the guide to read. `finassist explain --list` lists every code.
2. **For a gate range, check everything at once.** Run `finassist doctor --policy POLICY --repo . --base BASE --head HEAD`. It lists every blocker for that range in one run, names the refused files in local output only, and spends nothing. See [the pre-merge gate](pre-merge-gate.md).
3. **For configuration, run `finassist --config finassist.json doctor`.** It reports settings that have no effect, such as a suffix the deny list always refuses.

Fix the cause that the hint names. Never make an error go away by weakening screening, removing a pin, editing an approved hash or deleting audit history.

## Codes often seen on a first run
The summaries and fixes below are the same text that `finassist explain` prints. A test keeps them in step.

<!-- hint-table:start -->
| Code | What happened | How to fix |
| --- | --- | --- |
| `config_file_not_loaded` | A finassist.json file is present but this run used the defaults, so the report describes defaults, not that file. | Pass `--config finassist.json` before the command to check that file. |
| `invalid_config` | The configuration can't be read as a UTF-8 JSON object: the file is missing, unreadable, malformed or not an object. | Check that the `--config` path exists and is valid UTF-8 JSON whose top level is an object. `finassist init` writes a valid starting file. |
| `invalid_limit` | A size, token or timeout limit is not a whole number from 1 to 2,000,000; the error's `option` names it. | Set the named option (`max_file_bytes`, `max_packet_bytes`, `max_output_tokens` or `timeout_seconds`) to an integer from 1 to 2,000,000, without quotes. |
| `invalid_cost_limit` | A budget or price option is negative, not finite, or not a number; the error's `option` names it. | Set the named option (`max_run_usd`, `daily_budget_usd`, `monthly_budget_usd` or a `*_usd_per_million` price) to a non-negative number in USD, not a string or boolean. |
| `text_suffix_always_denied` | A suffix in `text_suffixes` is always refused as data or binary, so listing it has no effect. | Remove the suffix from `text_suffixes`. For synthetic CSV, TSV or YAML test data, admit it with `fixture_roots` in a gate policy; other denied formats can't be admitted at all. |
| `model_required` | A non-offline `provider` is selected but `model` is empty. | Set `model` to the exact model identifier for your account (or pass `--model` to `init`), or set `provider` to offline. |
| `https_required` | The endpoint doesn't use HTTPS; plain HTTP is allowed only for ollama or compatible on 127.0.0.1, localhost or ::1. | Use an https:// endpoint. Use http:// only for a local ollama or compatible server on a loopback address. |
| `endpoint_host_not_approved` | The endpoint host is neither the provider's built-in host nor listed in `allowed_hosts`, so nothing is sent there. | If you intend to send reviewed source to this host, add its exact hostname to `allowed_hosts` in the reviewed configuration. Otherwise use the provider's default endpoint. |
| `provider_prices_required` | A paid provider has a zero input or output price, so spend can't be estimated and the call is refused. | Set `input_usd_per_million` and `output_usd_per_million` above zero, in the configuration or the gate policy's `model_review`. The `missing` field lists the zero ones. |
| `network_not_approved` | A network call needs both `allow_network: true` in the configuration and the command's `--allow-network`; one is missing. | If the call is intended, set `allow_network` to true in the reviewed configuration and pass `--allow-network`. The `allow_network` and `allow_network_flag` fields show which is false. |
| `invalid_input` | An input, file or local database couldn't be read or parsed; `kind` names the error class. | Check the paths and JSON files the command was given, and that the audit directory is writable. Run `finassist doctor` to check the setup. The class in `kind` shows the type of failure. |
| `packet_limit_exceeded` | The serialized packet is larger than `max_packet_bytes`, so it can't be built or sent. | Raise `max_packet_bytes` (up to 2,000,000), narrow `allow_paths` or plan a smaller range. A packet built under a larger limit is refused by a config with a smaller one; in a policy gate the cap is fixed. |
| `file_limit_exceeded` | A file version is larger than the byte limit that applies to it, so it can't be read or reviewed. | Raise `max_file_bytes` (up to 2,000,000; `fixture_max_file_bytes` for gate fixtures) or keep the file out of the range. The error's `limit` shows the cap; 128000 and 4096 are fixed caps on policy, profile, ignore and marker files. |
| `private_or_binary_path` | The path has a data, credential or binary suffix (such as .csv, .pdf, .zip or .key), which is never reviewed. | Keep such files out of the range; a changed one blocks planning even outside `allow_paths`. Only a synthetic .csv or .tsv fixture can be admitted, through `fixture_roots` in a reviewed gate policy. |
| `private_path` | A path component is private by policy (such as .git, .env, .ssh, secrets, holdings or node_modules), so it's never reviewed. | Keep the file out of the range; a changed private path blocks planning even outside `allow_paths`. Approved source can be admitted by removing its component from `denied_parts`; .git, .finassist and .env names always stay private. |
| `sensitive_content` | Text matched a built-in credential or private-identifier pattern, so it's blocked from review, output or config. | Remove the secret or identifier from the file, rotate any real credential, and refer to keys only by environment variable name. Both versions of a changed file are screened; screening has no bypass. |
| `forbidden_token_present` | Source, instructions or model output contain a figure on the policy's confidential list, so the gate blocks. | Remove the figure from the changed files, or keep those files out of the range. Both file versions are screened, including context and comments. Very short listed numbers can match ordinary constants. |
| `scope_incomplete` | Some changed files are omitted from the review packet, so complete coverage can't be shown and the review is refused. | Run `finassist plan` and read `omitted`. Add the paths to `allow_paths` or keep generated and image files out of the range; a history case also needs a changed file. Only `review` and `propose` accept `allow_partial_review`. |
| `packet_approval_required` | `--approve-packet` is missing or doesn't equal the packet's hash, so no model request is sent. | Inspect the packet, then pass its `packet_hash` (printed by `finassist plan`) to `--approve-packet`. A packet changed after you inspected it needs a fresh inspection. |
| `empty_review_scope` | The range changes no files, so there is nothing to review. | Check `--base` and `--head`. The range runs from their merge base to head, so equal revisions, a head already merged into base, or swapped values give no changes. Pass the target branch as base and the change as head. |
| `invalid_revision` | A revision argument is empty, starts with '-', or didn't resolve to a full commit hash. | Pass a commit hash, branch or tag that exists in this repository to `--base` or `--head`. Option-like values beginning with '-' are refused. |
| `git_commit_unavailable` | A requested commit isn't in the local repository, and the tool never fetches it. | Fetch the branch or commit yourself (for example `git fetch origin BRANCH`) and pass a revision that `git rev-parse` resolves locally, then rerun. |
| `gate_policy_missing_at_base` | The model gate policy file does not exist at --base, and the gate never reads it from the working tree. | Commit the reviewed policy on the base branch first, and check that `--policy` is its repository-relative path and `--base` is the right commit. |
| `gate_policy_pin_required` | --policy-sha256 is not 64 lowercase hex characters, or the preflight needs it before opening the policy's token file. | Pass `--policy-sha256` as the full lowercase SHA-256 of the reviewed policy bytes at base. `finassist doctor --policy` run without a pin shows that value in policy.sha256. |
| `gate_policy_pin_mismatch` | The SHA-256 of the policy bytes at base does not match --policy-sha256, so the policy is not the reviewed one. | Don't pin unreviewed bytes. Check `--policy` and `--base`; if a reviewed change landed, inspect the policy at base and use the policy.sha256 value from `finassist doctor --policy` as the new `--policy-sha256`. |
| `gate_policy_invalid` | The model gate policy at base is not a valid version-2 policy: bad JSON, a missing or unknown field, or a wrong type or range. | Run `finassist doctor --policy FILE --repo . --base BASE --head HEAD` to list every schema error with its field and allowed values. Fix them (`model_review.enabled` must be true), commit on base through review and update the pin. |
| `gate_path_not_allowed` | A changed file is outside the policy's allow_paths, so the gate won't send it for review. | Keep the file out of the range, or add a covering entry to `allow_paths` (an exact path or a directory prefix ending in /) in a reviewed policy change on base, then update the policy pin. |
| `gate_private_path` | The path has a private component or name (such as data, private, client or household), so it's never sent for review. | Keep these files out of the reviewed range. Names such as client.json or secrets.json, names containing client_config or household_settings, and paths over 512 characters are also refused; there is no override. |
| `gate_ignored_path` | A changed file, the profile or a fixture marker matches a Git ignore rule, and ignored files are never reviewed. | Keep the ignored file out of the range. Rules come from the current checkout and from .gitignore at the base and merge base. If the file is meant to be tracked source, change the rule in a separate reviewed change on base first. |
| `gate_policy_change_requires_review` | The range changes the gate policy file itself, and a pull request can't approve its own policy. | Land the policy change on its own through review on the base branch, then update the pin. If the base changed the policy after this branch was cut, update the branch with the current base. |
| `gate_request_bytes_exceeded` | The exact request body is larger than the policy's max_request_bytes, so it isn't sent. | Review a smaller range, or raise `max_request_bytes` (up to 2,000,000) in a reviewed policy change on base and update the pin. `finassist doctor --policy` shows the body size against the limit. |
| `run_budget_exceeded` | This model call's estimated cost exceeds the per-call limit `max_run_usd`, so it isn't made. | Review a smaller range, lower `max_output_tokens`, or raise `max_run_usd` in the reviewed configuration or gate policy after checking the configured prices. |
| `daily_budget_exceeded` | This model call's estimated cost would push today's spend, including unresolved reservations, over the daily budget. | Run `finassist audit` and settle open reservations with `finassist reconcile-budget` from verified billing, wait for the next UTC day, or raise `daily_budget_usd` in the reviewed configuration or gate policy. |
| `provider_key_missing` | The environment variable named for the provider key is unset or empty, so no request is sent. | Set the variable named by `api_key_env` (built-in defaults: OPENAI_API_KEY, ANTHROPIC_API_KEY, GEMINI_API_KEY) in this shell. Never put the key itself in a config or policy file. |
| `unknown_error_code` | The code given to `explain` is not one this version raises or reports. | Check the spelling; any close codes are listed in `suggestions`. A code from a newer version may need an upgrade. Run `finassist explain --list` for every code. |
<!-- hint-table:end -->

## When an outcome is unknown
Some codes mean an action may have happened even though the command failed. Examples are an upgrade that timed out or a workflow step that was interrupted. Don't retry straight away. Inspect first with `finassist audit`, `finassist workflow status` or your installer, and reconcile from what you find. See [auditing and readiness](readiness-and-auditing.md).

## Reporting a problem
Include the `code`, any `kind`, the output of `finassist --version` and the command you ran. Leave out file contents, paths, keys and full outputs: these can hold private information. The repository is public.
