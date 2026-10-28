# Configuration reference

The CLI and library use the same `Config.validate()` rules. Unknown fields fail
with `unknown_config_option`; no provider is selected from an existing key.
[Complete example](../examples/fork-config.json) lists every option. It stays offline.

| Option | Meaning |
|---|---|
| `schema_version` | Configuration format version; use 1. |
| `provider` | offline, openai, anthropic, google, compatible or ollama. No automatic fallback. |
| `model` | Exact operator-selected model identifier; empty for offline. |
| `endpoint` | Explicit provider API URL, or the built-in protocol default. |
| `api_key_env` | Environment variable NAME only. Never a key value. |
| `auth_header` | Authorization, api-key or x-api-key for the selected endpoint. |
| `profile` | Selected name from the resolved profiles registry. |
| `profiles` | Registry of names to nonempty checklist arrays. Replaces built-ins when supplied; general is required. |
| `profile_files` | JSON registry files, strict relative POSIX .json paths inside this config directory. Definitions overlay profiles; duplicate paths, names and empty files fail. |
| `denied_parts` | Lowercase private path component names (matched case-insensitively). Remove portfolios only for approved source code; .git and .finassist remain required. |
| `text_suffixes` | Lowercase source suffixes including the dot. Add .tf/.cs explicitly. Binary/credential file restrictions remain. |
| `github_host` | GitHub DNS hostname, without scheme, path or port. Defaults to github.com; Enterprise uses existing gh auth. |
| `allow_network` | Enable potential network use. Each command still needs its own explicit network approval. |
| `allow_partial_review` | Permit model calls with explicitly accounted-for omissions. Readiness still requires complete coverage. |
| `allowed_hosts` | Additional approved MODEL endpoint hostnames; distinct from github_host. |
| `allow_paths` | Exact source paths or prefixes ending in /. Denied components still apply. |
| `protected_paths` | Proposal-protected paths or directories. Source may still be inspected if allowed. |
| `protected_branches` | Glob patterns where local patch application is prohibited. |
| `extra_sensitive_patterns` | Additional case-insensitive regular expressions. Invalid patterns fail; matches block content. |
| `max_file_bytes` | Maximum bytes per source file version. |
| `max_packet_bytes` | Maximum serialized review packet bytes. |
| `max_output_tokens` | Requested output token ceiling. Anomalous reported usage stays unreconciled. |
| `timeout_seconds` | Bounded provider and recipe timeout; remote cancellation is separate. |
| `max_run_usd` | Local per-call spend admission limit in USD; not a provider-enforced cap. |
| `daily_budget_usd` | Local UTC daily admission budget, including unresolved reservations from prior days. |
| `input_usd_per_million` | Operator-supplied input token price in USD per million. |
| `output_usd_per_million` | Operator-supplied output token price in USD per million. |
| `recipes` | Named arrays of literal executable/argument strings. Never shell command strings. |
| `runner_image` | Prebuilt digest-pinned OCI image used for isolated recipes. |
| `required_recipes` | Configured recipe names whose fresh passing receipts readiness requires. |
| `blocking_severities` | Finding severities that block readiness: critical/high/medium/low/info. |
| `readiness_max_age_seconds` | Maximum age of audited review and check evidence. |
| `allow_local_readiness` | Explicit trusted-code opt-in for local recipe evidence; false by default. |

## Path and file policy

Today’s denied component names and source suffixes remain the defaults. A path
under `src/portfolios/` needs both an allowed source prefix and explicit removal
of `portfolios` from `denied_parts`. Paths stay relative, reject traversal and
links, and are rechecked throughout planning, verification, export, evaluation,
proposals and rollback. Packets capture `allow_paths` and the selected profile;
active review/readiness requires an exact match and re-screens custom content
patterns. Rebuild older packets lacking scope-policy evidence before active use.
The approved path policy is saved in patch backups; CLI rollback also enforces
the active configuration before writing any file.
Runtime/Git internals, environment files, private profile filenames, credential
formats and binary restrictions remain intrinsic protections. There is no bypass switch.

## Custom profiles

`profile_files` contains UTF-8 JSON objects mapping profile names to checklist
arrays. See [engineering profile](../examples/profiles/engineering.json). Files
are data, never Python/plugins or executable templates. File paths resolve from
the config file directory, not the shell working directory. Missing, malformed,
linked or oversized files fail before model work. Names are lowercase slugs;
checklists have 1–64 nonempty entries of at most 2,000 characters. At most 16
files of 128,000 bytes each are loaded. References must pass the configured denied
path policy and cannot contain absolute paths, home expansion, traversal or links.
Directories and FIFOs are rejected before opening. Duplicate JSON keys and names
across files fail.

The loaded registry is captured once per `load_config` call. Its content and
file references enter the configuration digest. Changing a checklist invalidates
old review/readiness evidence on reload. Saving preserves references and only the
original inline definitions, so deleting a file definition removes it on reload.
A save checks the destination's referenced files against the captured snapshot.
`init --output` materializes resolved definitions and clears file references, making
copies portable across directories. Library callers supply `profiles` directly or
use `load_config` for files; a raw `Config(profile_files=...)` fails explicitly with
`profile_files_require_load_config` instead of silently ignoring references.
The fixed authority instructions remain outside all custom checklist content.

## GitHub Enterprise

Set `github_host` to a lowercase DNS name such as `git.example.com`. The same
fixed metadata GETs pass it as a literal `gh api --hostname` argument. The GitHub
CLI selects the Enterprise API prefix and consumes its existing authentication;
the assistant does not log in, extract a token, change TLS verification or follow
model-selected URLs. Reports include the host so public and Enterprise snapshots
cannot be confused. IP literals and single-label hosts are rejected. Public
`GH_TOKEN`/`GITHUB_TOKEN` values are used only for github.com. Other hosts use
existing per-host CLI authentication or explicitly supplied Enterprise token
variables; for .ghe.com the selected Enterprise credential is mapped to gh's cloud
variable, without forwarding the public token. `allow_network` and `--allow-network` are still both required.
See the [GitHub CLI API reference](https://cli.github.com/manual/gh_api).

## Validation errors

`invalid_denied_parts`, `required_denied_parts_missing`, `invalid_text_suffixes`,
`invalid_github_host`, `invalid_profiles`, `invalid_profile_name`,
`invalid_profile_checklist`, `unknown_profile` and `invalid_profile_files` identify
policy configuration problems. `profile_file_unavailable`, `profile_file_invalid`,
`profile_file_too_large` and `duplicate_or_invalid_profile_file` identify file
loading problems. Errors never print file contents, credentials or private paths.
An allowed/protected prefix must also satisfy the configured path policy.
Configuration files are bounded to 2 MB. Budget values must be finite and nonnegative;
limits must be positive integers. Unknown configuration keys are rejected.
