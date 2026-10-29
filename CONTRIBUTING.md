# Contributing

Contribute focused, tested improvements to finledgerpoli while preserving its offline defaults and explicit approvals. The command is `finassist`.

Work on a focused feature branch. Document the problem, scope, governing project
rules, expected behavior and validation. Keep fixtures synthetic and provider
tests on fake transports. Do not copy private source histories or datasets into
this project.

Run the full test suite, linter, offline demo and publication scan. Add regression
tests that fail on the original defect, especially around source identity,
privacy, evidence validity, budget accounting and process cleanup. Tests that
merely assert wording or duplicate implementation do not prove behavior.

Update docs when a command or boundary changes. Provider support needs request
and response contract tests, failed/truncated-response tests, explicit limits,
and honest live-verification status. Never add a paid fallback selected solely
because an environment variable exists.

Keep dependencies and CI actions pinned. No new default permissions or external
services should be introduced as an incidental refactor. Review the exact head
and green CI before merging. Security fixes use synthetic public reproducers.
