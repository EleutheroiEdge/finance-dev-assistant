# Local dashboard

Use the finledgerpoli dashboard to preview configuration changes, inspect audit statistics and check local health. Its command is `finassist`; the prebuilt app needs Python 3.11+ and no Node installation at runtime.

## Start and stop

After installing the package, these commands work in PowerShell, macOS Terminal
and a Linux shell:

```text
finassist init --output finassist.json
finassist --config finassist.json dashboard
```

Open the printed `http://127.0.0.1:PORT` address in your browser. Stop the foreground
process with Ctrl+C. The default port is selected by the operating system; use
`dashboard --port 8765` for a fixed port. `--state-dir .finassist` selects the local
audit directory. Use the same directory as your CLI runs to see their statistics.
There is no host option, background service, browser launcher or telemetry.

## Configuration

The form edits only the following settings. Every value is validated by the same
`Config.validate()` schema used by the CLI. A complete small starting example is
[`examples/dashboard.json`](../examples/dashboard.json).

| Setting | Meaning | Example |
| --- | --- | --- |
| `provider` | Explicit model adapter; choosing one makes no network call | `offline` |
| `model` | Identifier accepted by your configured provider | `your-model-id` |
| `daily_budget_usd` | Local admission limit for each UTC booking day | `5.0` |
| `monthly_budget_usd` | Local admission limit for each UTC booking month | `100.0` |
| `generated_paths` | Literal paths or prefixes excluded from review/snapshot source | `src/finassist/resources/dashboard/` |
| `allow_paths` | Reviewable path prefixes; one per line | `src/`, `tests/` |
| `protected_paths` | Paths that patches cannot modify | `.github/` |
| `extra_sensitive_patterns` | Case-insensitive content regular expressions | `synthetic-restricted-marker` |
| `profile` | Active review checklist from the loaded configuration | `general` |
| `required_recipes` | Names of existing recipe definitions | `unit` |
| `blocking_severities` | Finding severities that block readiness | `critical`, `high` |
| `readiness_max_age_seconds` | Maximum evidence age, positive integer seconds | `86400` |

Recipe definitions, provider endpoints, network authorization, custom profile files
and other advanced settings stay in the JSON configuration. The dashboard preserves
them, including the original inline/file profile provenance. Configured custom profiles appear in the selector when supported by the
installed configuration schema. Sensitive patterns apply to reviewed material;
they do not screen their own definitions. Built-in credential screening still
screens the configuration before it can be displayed or saved.

Editing never saves automatically. Select **Preview changes**, inspect the before
and after values, then select **Confirm and save**. Any further edit discards the
preview. A preview is bound to the current configuration revision and is single-use.
Changes made elsewhere invalidate it. Saves normalize JSON and preserve a private,
content-addressed recovery copy under the state directory's `config-backups/`.
The save captures one byte snapshot for revision and backup identity.
Only field names and hashes enter save audit events, not setting values.

There is no key entry field or API for key values; only whether each supported variable and the configured variable are set is returned.
Network authorization remains a separate CLI/configuration decision.

## Statistics and health

Statistics verifies the audit hash chain and reads events and reservations in one
SQLite transaction. A corrupt or unavailable ledger produces an error rather than
plausible partial totals. Reading an absent ledger does not create fake runs.

- Settled spend and token usage show up to 90 recorded booking days, with accessible
  tables alongside the uPlot charts. Daily and monthly limits and available amounts
  account for all open or unknown reservations, including earlier periods.
- Reviews show totals, profiles, and findings by severity and profile. Offline
  analyses are counted separately. Older reviews may lack finding metadata.
- Readiness shows satisfied prerequisites, blocked results and reasons.
  Older or failed evaluations without outcome metadata remain unclassified.
  Exit code 1 is displayed distinctly as blocked or failed; an unknown mutation
  never receives a false terminal failure event.
- Recipe results show recorded pass rates; older checks without result metadata
  are explicitly counted. The last 50 audited commands include unknown outcomes.

The monthly default also applies to model admission through the CLI. Health shares the
`finassist doctor` implementation and checks configuration validity without calling
a model, GitHub or a container daemon. Invalid configurations return a typed API
error and a persistent banner on every tab; refresh clears stale data, and Health
remains available.

## Generated artifacts and repository checks

`generated_paths` defaults to the packaged dashboard output directory. Entries are
literal relative POSIX files or directory prefixes ending in `/`, without globs,
traversal or private-path exceptions. The list is configuration-bound in outgoing requests.
Planning accounts for these paths as `generated_artifact_excluded` without reading
large generated bytes; snapshot export excludes them too. Verified generated
omissions are outside review coverage. Other omissions still block full coverage.
Publication/secret scans continue to inspect generated artifacts.

The existing **Verify shipped assets match their source** CI step rebuilds the
bundle and rejects drift; the packaged integrity manifest verifies bytes at startup.
Generated exclusions do not themselves claim that either check has run. Keep the
relevant CI checks required in your fork's protection policy. `.gitattributes` is
reviewable and protected by default.

Regression checks run `plan` and an explicitly approved synthetic local `check`
against this repository's actual committed tree. They retain the 48 KB file limit;
the whole-repository plan uses an explicit larger outgoing request limit. A bounded synthetic
comparison ancestry preserves the exact committed tree without changing source,
index or branch references, and works in shallow or single-commit forks. A generated file
outside a configured exclusion still fails the file limit.

## HTTP boundary

The server listens only on IPv4 loopback. It checks an exact Host header and,
when present, an exact same Origin. Mutations require Origin and a random,
per-process session token; all data APIs require that token. Cross-site fetches,
CORS preflights, oversized bodies and arbitrary static paths are rejected. A
restrictive Content Security Policy, no-store responses and no request-body logs
reduce accidental exposure. Assets are served from a packaged hash manifest.

## Contributor checks

Use Node 22.23 or newer in the supported Node 22 line, with pinned pnpm 12.9.1:

```text
cd dashboard
pnpm install --frozen-lockfile --ignore-scripts
pnpm run build
pnpm run test
pnpm exec playwright install chromium
pnpm run e2e
```

`FINASSIST_TEST_PYTHON` can select an installed Python executable for browser tests.
Build output and its integrity manifest live inside `src/finassist/resources/dashboard`;
commit them with their TypeScript source. CI rebuilds and checks for drift. Component
tests cover explicit confirmation and keyboard-accessible controls; API tests cover
origin/token enforcement, shared validation, stale previews, private recovery,
metadata statistics and uncertain save outcomes. Browser tests exercise actual
Python-served assets and charts and reject external requests. Windows, macOS and
Linux also test a clean installed wheel with Node absent from its runtime PATH.

Design references: [Vite static builds](https://vite.dev/guide/build.html),
[OWASP CSRF guidance](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html),
and [uPlot](https://github.com/leeoniya/uPlot).

## Limits

Use a private user directory for configuration and state. POSIX files use owner-only
modes (0600, with private newly created directories). Windows uses inherited ACLs;
the Health page warns that POSIX modes do not establish a Windows access boundary.
Review directory permissions, especially on shared machines.

The revision check detects observed concurrent edits; it is not a filesystem
compare-and-swap transaction. Avoid two writers to the same configuration. If an
audit write fails after replacement, the app reports that the configuration may
already be saved. Its audit run remains open/unknown and blocks readiness.
Reload and reconcile the ledger and recovery copy before retrying.

Session token and origin checks precede all request-body handling. Payloads over
65,536 bytes remain rejected. For an authenticated request of at most 131,072
bytes, rejected-body cleanup discards bytes without parsing them for at most
0.25 seconds total. This helps Windows clients receive the refusal before the
connection closes; larger or stalled requests are not drained without bounds.

No external requests, remote fonts, telemetry or CDN assets are used. The session
token stays in page memory. This is a local same-user tool, not multi-user
authentication or a sandbox against another process running as your OS user.
Do not expose it through proxies, tunnels or port forwarding. It cannot run
recipes, launch reviews, change GitHub protection, merge, deploy or execute shell
commands from the browser.

Cost figures are local UTC-booked estimates, not invoices or provider-enforced caps; missing historical usage is not zero. Reconcile uncertain calls from actual billing. Keys stay in environment variables; never paste them into other fields. See the [threat model](threat-model.md).
