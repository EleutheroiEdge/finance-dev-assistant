# Repository security and maintenance

Use this finledgerpoli checklist to review repository security, dependency scanning and fork settings. These instructions describe settings to configure; they do not apply them.

## Settings for an owner to review and enable

Under Settings → Advanced Security (or Code security, depending on the GitHub UI):

- Enable secret scanning and its alerts for the public repository.
- Enable push protection. Review bypass events; do not rely on a source scanner
  alone, and revoke any exposed credential before repairing history.
- Enable private vulnerability reporting so SECURITY.md has a private intake path.
- Enable the dependency graph and Dependabot alerts/security updates if available.
- Use advanced CodeQL setup with the committed workflow. Avoid running default
  setup and advanced setup for the same language simultaneously.

Retain required PRs, current CI, administrator enforcement, resolved conversations
and no force push/deletion. Review CODEOWNERS and eligible reviewers before
requiring code-owner approval; a sole author cannot approve their own PR. Do not
change approval counts or protections as a side effect of enabling scanners.
The [release guide](releasing.md) describes the protected publishing environment.

Ask the owner before applying any of these settings or changing account access.
See GitHub's guides for [push protection](https://docs.github.com/en/code-security/how-tos/secure-your-secrets/prevent-future-leaks/enable-push-protection),
[private reporting](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/configure-vulnerability-reporting/configure-for-a-repository)
and [CodeQL setup](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/configure-code-scanning/configuring-advanced-setup-for-code-scanning).

## Dependency and scanning workflows

Dependabot checks pip, the dashboard's npm ecosystem (pnpm lockfile) and Actions
weekly, with one version-update group per ecosystem. `requirements.txt` exposes
the included exact development lockfile to pip dependency discovery. Security-update scheduling
is controlled separately by GitHub. Keep lockfiles and manifests consistent,
review grouped upgrades, regenerate assets and run all tests. No update is
merged automatically. Consult the [Dependabot reference](https://docs.github.com/en/code-security/reference/supply-chain-security/dependabot-options-reference).

CodeQL analyzes Python and TypeScript/JavaScript source on main, PRs and a weekly
schedule, using no-build mode and ignoring generated dashboard output. Only the
analysis job receives security-events write permission. Fork PRs retain GitHub's
restricted token rules. A successful scan is not proof of vulnerability absence.

Scorecard runs on main and weekly; it does not run untrusted PR code with OIDC.
Its isolated `publish` job follows the upstream permitted-action list, publishes
public repository posture to OpenSSF and uploads SARIF. OIDC is required by
Scorecard to authenticate those results; it is not a PyPI token or deployment
permission. Default GITHUB_TOKEN reads may not reveal classic branch-protection
settings, so a missing/low score is not evidence that controls are absent. Do not
add a personal admin token merely to improve a score.

Missing badge results can reflect publication delay, permissions or an unsupported repository. It reports repository posture. The [upstream Scorecard Action](https://github.com/ossf/scorecard-action)
does not support repositories marked as forks or GitHub Enterprise. This workflow
skips forks explicitly; fork maintainers can run the upstream Scorecard CLI, or
review the Action setup after establishing an independent supported repository.

## Adapting a fork

Replace `.github/CODEOWNERS` with your own write-enabled maintainer/team, update
issue/security links, badges and repository identities, and establish a private
conduct-reporting contact. Review schedules, enabled Actions and permissions.
Never copy upstream credentials or assume upstream reviewers can administer a
fork. Enabling a scanner or adding CODEOWNERS does not itself make its check
required by branch protection. See [GitHub code owners](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners).

## Limits

Settings changes require authorization from your repository administrator. Scanner results and posture badges cannot establish vulnerability absence. Forks need their own identities, reviewers and supported scanning setup.
