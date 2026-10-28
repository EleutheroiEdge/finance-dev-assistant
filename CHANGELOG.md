# Changelog

## 0.2.0 — Unreleased

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
