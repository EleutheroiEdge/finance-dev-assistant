# Changelog

## Next

- Add Windows and macOS native CI alongside Linux, retaining required check names.
- Standardize UTF-8/universal-newline reads and LF writes; lint missing encodings.
- Discover native tools, supervise Windows commands with job cleanup, support
  macOS non-reaping exit observation, and use Docker Desktop-compatible mounts.
- Test portable SQLite/temp cleanup and Git object modes/links; document Windows
  inherited ACLs and explicit refusal of unrepresentable executable-bit patches.

## 0.2.0 — Unreleased

- Harden native supervision: require positive nonempty zombie-only observations,
  launch Windows children suspended before Job assignment, and always clean up
  pipes/readers while draining completed output before deadline decisions.
- Retain host container CLI context/storage selectors through cleanup, reject
  Python 3.11 reparse points and tracked symlink modes, and preserve CRLF through
  apply/rollback with an explicit shipped-resource LF policy.
- Add fail-before-fix regressions, descendant lifecycle tests, read-only Windows
  replacement, native doctor discovery and all three Python versions on every OS.
  Extend the protection proposal without changing live repository settings.

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
