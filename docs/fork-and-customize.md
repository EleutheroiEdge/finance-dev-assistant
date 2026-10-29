# Fork and customize

Adapt finledgerpoli to your team through profiles, source policy, providers, budgets and the dashboard. Its command is `finassist`; this walkthrough uses Cedar Vale Research, a fictional team with synthetic data.

1. **Create your development copy.** Fork or clone the repository and install in
   a Python 3.11+ virtual environment as shown in the README. Run `finassist demo`
   and `finassist doctor` offline. Review LICENSE, SECURITY.md and the threat model.
   Replace repository links, badges and CODEOWNERS with your own maintainers;
   configure private reporting and publishing only after your owner approves them.
2. **Start with explicit configuration.** Run `finassist init --output finassist.json`.
   Add `"$schema": "./schemas/finassist.schema.json"` in a checkout, or copy the
   published schema beside your config and use its relative path. This enables
   editor autocomplete without giving the schema any runtime authority. Never add
   a key to this file. See [every option](configuration.md).
3. **Define source policy.** Cedar Vale keeps code in `src/`, tests in `tests/` and
   private inputs outside the checkout. Allow only relevant source prefixes,
   preserve private path components and add firm-specific sensitive patterns.
   Keep `.github/`, policy files, scripts and dependency manifests protected. If
   your legitimate source uses a denied directory name, remove only that component
   deliberately; `.git` and `.finassist` remain mandatory denials. Extend source
   suffixes for `.tf`/`.cs` as needed. `generated_paths` is for built artifacts
   whose source/integrity is checked separately, never a convenient source bypass.
4. **Create a profile.** Put a reviewed JSON file at `profiles/cedar-vale.json`,
   relative to the config. Reference it with `profile_files` and select its name
   in `profile`. Files must remain relative, regular, screened JSON files. For example:

   ```json
   {
     "cedar-vale": [
       "Reconcile synthetic ledger totals before rounding.",
       "Distinguish approved assumptions from source observations.",
       "Reproduce boundary and failure cases independently."
     ]
   }
   ```

   Keep `general` in inline `profiles` if replacing that registry. Profiles guide
   review; they do not supersede your project's methodology. Removing a file-only
   profile removes it on reload; dashboard saves preserve that provenance.
5. **Select a provider deliberately.** Keep `offline` until source policy is
   reviewed. For a remote model, choose provider/model, approve its exact endpoint
   hostname, set rate assumptions and supply the key through the named environment
   variable. Enable `allow_network` only deliberately. Review/propose still require
   the outgoing request's approval hash and network flag. An existing key never
   chooses a provider. See [provider setup](providers.md).
6. **Set budgets.** Choose per-run, daily and monthly admission amounts and review
   input/output prices. Cedar Vale might start with USD 0.25/run, 1/day and 10/month
   for synthetic trials. These are examples, not price recommendations or hard
   provider caps. Unknown billing remains reserved; reconcile against real billing.
7. **Configure recipes and readiness.** Use argv arrays without a shell, a reviewed
   prebuilt image pinned by digest, and no private mounts/network. Set required
   recipe names, blocking severities and evidence age. Keep local readiness off
   unless you deliberately accept trusted local execution. Exact head, configuration,
   coverage and incomplete-run checks remain required. Test both a passing synthetic
   case and deliberate blockers before treating a result as ready for human review.
8. **Use the dashboard.** Run `finassist --config finassist.json dashboard`. Open its
   printed `127.0.0.1` URL. Edit provider/model, budgets, paths, sensitive patterns,
   profile and readiness; inspect the diff and confirm explicitly. Keys are never
   displayed. Review open/unknown runs and Health warnings. Advanced JSON options
   are preserved; see [dashboard](dashboard.md).
9. **Verify the fork.** Run the Python suite, Ruff, demo, publication scan and native
   CI. Rebuild dashboard assets after source changes. Use fake transports and
   fictional fixtures, not client repositories or account data. Keep each change
   in a reviewed PR; reports never authorize deployment, trading or settings changes.

Use `finassist export-kit --output assistant-integration` to obtain portable
profiles, instructions, examples and the schema. Review templates before copying
any into a host agent. They do not install permissions or configure credentials.
See [command output contracts](cli-contracts.md) for scripts consuming results.

## Limits

Profiles do not replace your methodology, and configuration does not grant action authority. Budgets are local admission controls; uncertain billing stays reserved. Instructions do not install host permissions. Use synthetic trials and preserve the human approvals in the [agent guide](agents.md). See the [threat model](threat-model.md).
