# Threat model

finassist is a local, advisory developer tool. Its trusted computing base includes
its installed code/dependencies, Python, Git, the operator's reviewed configuration
and host OS. Keep source and private state in user-controlled directories. Run
candidate code only in an appropriately isolated, patched environment.

| Asset or boundary | Guards and intended protection | Evidence in this repository | Limits and operator responsibility |
| --- | --- | --- | --- |
| Secrets and private source | Path/type/content screening of both committed file versions; explicit network and packet-hash approval; keys read only from named environment variables | `tests/test_security_scope.py`, `tests/test_hardening.py`, `tests/test_providers_review.py` | Patterns cannot prove confidentiality. Inspect every outgoing packet; a permitted provider receives the approved contents. |
| Private paths and filesystem | Relative path policy, immutable Git reads, symlink/reparse/Git-mode checks, private state files and snapshot exclusions | `tests/test_review_defaults.py`, `tests/test_review_platforms.py`, `tests/test_platform_support.py` | A hostile same-user process or compromised host is outside the boundary. Windows inherits ACLs; review them yourself. |
| Protected files and branches | Configured allowed/protected paths, clean branch checks, exact patch hash, snapshots and guarded rollback | `tests/test_patching_runner.py`, `tests/test_review_defaults.py`, `tests/test_review_regressions.py` | No automatic push/merge/deploy. Configuration owners can change policy; approval is not semantic correctness. |
| Spend | Explicit provider/model/rate assumptions, concurrent SQLite reservations, daily/monthly admission and unknown calls retained until reconciliation | `tests/test_finance_ledger.py`, `tests/test_hardening.py`, `tests/test_dashboard.py` | Local estimates are not provider-enforced caps. Other consumers of a credential are outside this ledger. Do not delete unknown reservations to retry. |
| Audit integrity | Hash-linked metadata events, bounded reads, run start/outcome tracking and unknown mutation outcomes | `tests/test_readiness.py`, `tests/test_dashboard_review.py`, `tests/test_dashboard.py` | Tamper evidence detects corruption; a malicious same-user rewrite of all state is not prevented. Audit hashes are not external signatures. |
| Model provider | Explicit endpoint/host approval, no automatic fallback, structured response validation, source/line and complete-coverage checks | `tests/test_providers_review.py`, `tests/test_proposal.py`, `tests/test_review_defaults.py` | Source and model output can contain prompt injection. Existing citations do not prove entailment. Fake transports test contracts, not live model quality. |
| Container/recipe execution | Approved recipes, screened committed snapshots, pinned image, no network, read-only source, bounded output/time and verified cleanup | `tests/test_container_contract.py`, `tests/test_review_platforms.py`, `scripts/container_smoke.py` | Isolation depends on runtime/image/host. Never mount credentials, home or a daemon socket. Local execution is explicitly trusted and unsandboxed; process groups/Jobs provide cleanup, not isolation. |
| GitHub API | Read-only inspection, explicit network opt-in, configured public/Enterprise host and tenant-specific credential routing | `tests/test_readiness.py`, `tests/test_review_defaults.py` | A protection snapshot can become stale and API tokens may have broader external rights. Reports grant no merge or deployment authority. |
| Localhost dashboard | IPv4 loopback only, exact Host/Origin, per-session token, restrictive CSP, bounded JSON requests, revision-bound preview and single-use explicit confirmation | `tests/test_dashboard.py`, `tests/test_dashboard_review.py`, `dashboard/src/App.test.tsx`, `dashboard/e2e/dashboard.spec.ts` | Same-user local UI, not multi-user authentication. No protection against a compromised browser/host or malicious same-user process. Revision checks are not an atomic filesystem compare-and-swap. |
| Generated dashboard assets | Configured, packet-bound exclusions with explicit omissions; source rebuild compared with shipped bytes and a hashed asset manifest | `tests/test_dashboard_review.py`, CI shipped-assets comparison | Exclusions are review policy, not proof of benign bytes. Review generated-path changes and keep build/source checks enabled. Publication screening still applies. |
| Readiness evidence | Exact source/config binding, required recipes, severity and freshness policy, missing/unknown coverage and incomplete runs block eligibility | `tests/test_readiness.py`, `tests/test_dashboard_review.py` | Eligibility means ready for human review, not approval, deployment permission or a financial decision. |

Tests named above use synthetic fixtures and mocked provider responses. Native CI
covers supported Python versions on Linux, Windows and macOS; the real container
smoke runs on Linux. See [security policy](../SECURITY.md), [architecture](architecture.md),
[platform limits](platforms.md) and [auditing/readiness](readiness-and-auditing.md).

## Outside the protection claim

The tool does not protect against a malicious administrator, compromised OS,
dependencies or container runtime; an operator who deliberately authorizes an
unsafe payload; cloud-provider retention/training policy; arbitrary same-user
filesystem changes; live financial execution; or incorrect business methodology.
It does not certify compliance, investment suitability, absence of vulnerabilities
or model quality. No telemetry or paid provider call occurs merely because a key
is present. Explicitly enabled network workflows and the selected provider have
their own network behavior. Editor schema fetching is controlled by the editor,
not the CLI.

## Reporting and review

Use the private reporting route in SECURITY.md, with a minimal synthetic
reproducer. Preserve uncertain billing/mutation evidence. Review path-policy,
endpoint, recipe, generated-path and readiness changes as security-sensitive
configuration changes, then exercise both allowed and refused cases.
