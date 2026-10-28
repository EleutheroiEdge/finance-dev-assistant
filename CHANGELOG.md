# Changelog

## 0.2.0 — Unreleased

- Exclude configurable, policy-bound generated paths from review/snapshot source,
  retain build-integrity CI checks, and test plan/check on this repository itself.
- Retain open/unknown audit runs after uncertain configuration saves, block
  readiness on them, and capture one consistent pre-save backup byte snapshot.
- Make .gitattributes reviewable and protected; show typed configuration failures
  on every dashboard tab, clear stale data, distinguish nonzero exits, and improve
  evidence-age and token-header errors. Extend the protection proposal only.

- Add an offline, loopback-only React dashboard, shipped prebuilt in the Python
  package. Configuration uses shared validation, preview and explicit confirmation;
  statistics verify reduced audit metadata, and health shares the CLI doctor.
- Enforce a configurable monthly review budget (default USD 100), retain unknown
  reservations across periods, and record token, finding and readiness outcomes.
- Test dashboard APIs, components, browser flows and installed wheels on Windows,
  macOS and Linux, including no-Node runtime and external-request checks.

- Context packets now use `schema_version: 2` and include before/after Git modes.
  Legacy schema1 packets remain inspectable but must be rebuilt for readiness.
- Add configurable readiness requirements, source/configuration-bound review and
  test receipts, and read-only GitHub protection inspection. Neither grants
  merge or deployment authority; zero formal approvals is reported explicitly.
- Add correlated command auditing, verified JSONL export and unknown-operation
  tracking. Readiness consumes verified ledger state in one transaction.
- Harden patch parsing with hunk counts and Git path-list agreement before
  backups/mutation; retain executable modes and guarded rollback/recovery.
- Fix sensitive assignment screening for prefixed/quoted names and account
  fields, apply custom patterns consistently, and report linked scan inputs.
- Keep anomalous provider usage reserved for reconciliation, reject stale review
  evidence with a blocked report, and require clean source for CLI readiness.

## 0.1.0

Initial portable CLI, offline synthetic demo, model adapters, evidence store,
review profiles, isolated test recipes and explicitly approved patch workflow.
