## Problem and resulting behavior

Describe the user-visible change and why it is needed.

## Validation

List relevant checks and any limitations.

- [ ] Tests cover the changed behavior; regressions fail before the fix where relevant.
- [ ] Python tests, Ruff, offline demo and publication scan pass.
- [ ] Dashboard source changes rebuild the shipped assets and pass component/browser checks.
- [ ] Documentation and CHANGELOG explain the final behavior.
- [ ] Examples, screenshots and fixtures use synthetic data only.
- [ ] No secrets, personal identifiers, private logs or machine-specific paths are included.
- [ ] Offline defaults, explicit approvals, protected paths and audit/budget gates are preserved.
- [ ] CI is green at the exact revision handed to the independent reviewer.

## Review handoff

Record `Ready for Claude at <full commit sha>` after checks pass. Add any specific
review questions. Review does not authorize publishing, settings changes or deployment.
