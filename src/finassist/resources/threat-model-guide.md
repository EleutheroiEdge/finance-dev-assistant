# Threat model

Understand what finledgerpoli protects, which components it relies on and where your own controls are required. Its command is `finassist`; it provides local advisory developer workflows.

The components it relies on include
its installed code/dependencies, Python, Git, your reviewed configuration
and host OS. Keep source and private state in user-controlled directories. Run
candidate code only in an appropriately isolated, patched environment.

| Asset or boundary | Guards and intended protection | Evidence in this repository |
| --- | --- | --- |
| Secrets and private source | Path/type/content screening of both committed file versions; explicit network and outgoing request-hash approval; keys read only from named environment variables | `tests/test_security_scope.py`, `tests/test_hardening.py`, `tests/test_providers_review.py` |
| Private paths and filesystem | Relative path policy, immutable Git reads, symlink/reparse/Git-mode checks, private state files and snapshot exclusions | `tests/test_review_defaults.py`, `tests/test_review_platforms.py`, `tests/test_platform_support.py` |
| Protected files and branches | Configured allowed/protected paths, clean branch checks, exact patch hash, snapshots and guarded rollback | `tests/test_patching_runner.py`, `tests/test_review_defaults.py`, `tests/test_review_regressions.py` |
| Spend | Explicit provider/model/rate assumptions, concurrent SQLite reservations, daily/monthly admission and unknown calls retained until reconciliation | `tests/test_finance_ledger.py`, `tests/test_hardening.py`, `tests/test_dashboard.py` |
| Audit integrity | Hash-linked metadata events, bounded reads, run start/outcome tracking and unknown mutation outcomes | `tests/test_readiness.py`, `tests/test_dashboard_review.py`, `tests/test_dashboard.py` |
| Model provider | Explicit endpoint/host approval, no automatic fallback, structured response validation, source/line and complete-coverage checks | `tests/test_providers_review.py`, `tests/test_proposal.py`, `tests/test_review_defaults.py` |
| Container/recipe execution | Approved recipes, screened committed snapshots, pinned image, no network, read-only source, bounded output/time and verified cleanup | `tests/test_container_contract.py`, `tests/test_review_platforms.py`, `scripts/container_smoke.py` |
| GitHub API | Read-only inspection, explicit network opt-in, configured public/Enterprise host and tenant-specific credential routing | `tests/test_readiness.py`, `tests/test_review_defaults.py` |
| Localhost dashboard | IPv4 loopback only, exact Host/Origin, per-session token, restrictive CSP, bounded JSON requests, revision-bound preview and single-use explicit confirmation | `tests/test_dashboard.py`, `tests/test_dashboard_review.py`, `dashboard/src/App.test.tsx`, `dashboard/e2e/dashboard.spec.ts` |
| Generated dashboard assets | Configured, outgoing request-bound exclusions with explicit omissions; source rebuild compared with shipped bytes and a hashed asset manifest | `tests/test_dashboard_review.py`, CI shipped-assets comparison |
| Readiness evidence | Exact source/config binding, required recipes, severity and freshness policy, missing/unknown coverage and incomplete runs block eligibility | `tests/test_readiness.py`, `tests/test_dashboard_review.py` |

Tests named above use synthetic fixtures and mocked provider responses. Native CI
covers supported Python versions on Linux, Windows and macOS; the real container
smoke runs on Linux. See [security policy](../SECURITY.md), [architecture](architecture.md),
[platform limits](platforms.md) and [auditing/readiness](readiness-and-auditing.md).

## Limits

The tool does not protect against a malicious administrator, compromised OS,
dependencies or container runtime; a user who deliberately authorizes an
unsafe payload; cloud-provider retention/training policy; arbitrary same-user
filesystem changes; live financial execution; or incorrect business methodology.
It cannot establish compliance, investment suitability, absence of vulnerabilities or model quality. No telemetry or paid provider call occurs merely because a key
is present. Explicitly enabled network workflows and the selected provider have
their own network behavior. Editor schema fetching is controlled by the editor,
not the CLI.

- Runtime and policy: installed code, dependencies, Python, Git, your reviewed configuration and OS must be trustworthy. A hostile provider, browser, daemon or kernel can defeat local controls. No secret-scanning pattern can classify all private data. The selected provider receives the approved request; review its retention and training policy yourself.
- Source and patches: generated exclusions require independent rebuild checks. Partial review is explicitly labeled and cannot satisfy readiness; empty source never calls a model. Legacy schema1 requests must be rebuilt with modes. Checks execute committed snapshots, not uncommitted patches. Application and configuration revision checks cannot make multi-file writes atomic against same-user writers. Interrupted backups or saves must be reconciled before retrying.
- Execution and platforms: only screened committed text enters snapshots. Writable-project tests require a reviewed adapter. Windows inherited ACLs need review; executable-bit changes unsupported by the filesystem are refused. Local execution is trusted and unsandboxed. Docker Desktop needs Linux containers and shared native paths; a skip is not isolation success.
- Spend and audit: incorrect rates, provider work continuing after disconnection, phase/chunk timeouts and other users of the same key can exceed local estimates. Missing/implausible paid usage remains held across periods until verified reconciliation; zero self-hosted rates are your cost assumption. Never reset reservations or unfinished events. A completion-write failure can follow mutation. Independent identity, retention and integrity anchoring require an external integration.
- Provider and evidence: URL, response and citation validation cannot establish semantic truth or live adapter compatibility. Drafts and future filings cannot qualify as approved point-in-time facts; ambiguous revisions block selection. Local database triggers cannot enforce organizational separation of duties. Synthetic public evaluation cases may be memorized; retain separate synthetic holdouts and independent labels.
- GitHub and release: API tokens may have broader rights outside this tool. Classic-policy snapshots do not establish ruleset equivalence, actual PR approval/discussion state or deployment outcomes. Verify the exact live head, current CI and target environment independently. Zero formal approvals must be a deliberate policy choice. Release provenance binds workflow identity and bytes, not correctness; pinned versions do not replace complete artifact-hash locking. Forks must establish their own publisher and repository controls.
- Dashboard: never expose the loopback server with a proxy, tunnel or port forward. Session tokens do not isolate same-user processes or provide multi-user authentication. Keys are presence booleans only; advanced configuration and credential screening remain enforced. Preview revision checks are not an atomic filesystem transaction. Statistics are verified local estimates, not invoices; legacy or missing metadata is unknown. The browser cannot run reviews, recipes, shell commands, merges or deployments.

## Reporting and review

Use the private reporting route in SECURITY.md, with a minimal synthetic
reproducer. Preserve uncertain billing/mutation evidence. Review path-policy,
endpoint, recipe, generated-path and readiness changes as security-sensitive
configuration changes, then exercise both allowed and refused cases.
