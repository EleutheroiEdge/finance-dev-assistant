# Releasing finledgerpoli

Prepare, inspect and publish finledgerpoli releases through a tag-only build, a gates job that tests the exact wheel, and a publishing environment that only release tags can deploy to. The PyPI distribution is **`finledgerpoli`**. The Python import package and primary
console command remain **`finassist`**; **`finledgerpoli`** is an additional command
alias for the same entry point. Config/state paths remain `finassist.json` and
`.finassist/`. The first public release is 0.3.0; adapt the publisher identity for your own repository.

## One-time maintainer setup

These are account and repository settings changes. An owner must explicitly
approve and perform them; preparing this workflow does not configure them.

1. Sign in to PyPI with a secured owner account. For a new project, create a
   [pending Trusted Publisher](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/)
   with project name `finledgerpoli`, GitHub owner `EleutheroiEdge`, repository
   `finance-dev-assistant`, workflow filename **`release.yml`** and environment
   **`pypi`**. Verify whether a matching publisher exists before creating one.
   Fork maintainers configure their own project/repository binding. For an existing owned project, add the
   same publisher from its Publishing page. No API token or GitHub secret is needed.
2. In GitHub Settings → Environments, create **`pypi`** and restrict its deployment
   refs to the `v*` release tags with one environment tag rule and no branch rule.
   In Settings → Rules, add two active tag rulesets for `v*`. One blocks updates,
   fast-forward ones included, and deletions, with no bypass, so a release tag can
   never be moved or reused; it must not also restrict creations. The other
   restricts creations, and only maintainers may bypass it. The build preflight
   refuses to run without both rulesets. Its
   token can't read a ruleset's bypass list, so check before tagging that the
   first ruleset's list is empty. A required reviewer is optional:
   the gates job (step 5) stands in for one. If you add one, disable administrator
   bypass where available; “Prevent self-review” needs a second eligible reviewer.
3. Review the exact workflow pins and permissions before merging. Fork maintainers
   must replace the package name, publisher identity, repository links, the
   environment's tag rule and the rulesets with their own; a fork does not inherit
   publishing authority.

See [PyPI publisher configuration](https://docs.pypi.org/trusted-publishers/adding-a-publisher/)
and [Trusted Publishing usage](https://docs.pypi.org/trusted-publishers/using-a-publisher/).
A missing environment, a deployment rule wider than the `v*` tags, or release tags without those rulesets
fail the read-only build preflight. If the
runner cannot read environment metadata, stop and resolve access with your repository administrator;
do not remove that guard or add an upload token as a workaround.

## Prepare and release

For every new release starting with 0.5.0, use this changelog template and state
any migration or downgrade limits explicitly. The release-note preflight requires
one nonempty `Upgrading` section; historical published notes remain unchanged.

```markdown
## X.Y.Z - Unreleased

### Added

- Describe the change and its user-visible result.

### Upgrading

No action needed. Upgrades never edit project configuration or evidence.
```

1. Merge reviewed release source through a PR with all required CI green. Confirm
   project/package versions agree, release notes are complete, and the dashboard
   assets are current. Run tests, Ruff, the demo and publication scan.
2. Review source and dependencies, then build locally with `python -m build`.
   The release builds an sdist and then a wheel from that sdist. Verify both
   installed-wheel CLI and dashboard smoke checks. Node/pnpm are build-time tools.
3. An authorized maintainer creates and pushes the exact stable tag, for example `v0.3.0`, on the
   reviewed main commit. **Do not push a tag during development or review.** The
   workflow runs only for pushed `v*` tags; it has no manual, branch or PR trigger.
   The tag must exactly match the version and its commit must be in main.
4. Inspect the build run and download `release-<commit>` from Actions. It contains
   the wheel, sdist, release notes and `release-sbom.spdx.json`. The SBOM inventories source
   manifests, lockfiles and built distributions, including development dependencies;
   it is not a vulnerability report or a minimal runtime-only inventory.
5. The gates job downloads that artifact outside the checkout, builds the wheel
   and sdist again from the tagged checkout, and requires the artifact's `dist`
   folder to hold exactly those two archives, member for member: the same names
   in the same order and the same bytes, metadata included. The build is
   reproducible, so a file a build added, dropped or changed stops the release. It
   then installs that wheel by its hash and runs the whole test suite, which refuses
   to start if it would import the tree instead, and the demo. Only when it passes
   does the `pypi` job run, after any required reviewer approves. That job downloads the same artifact from the same run,
   records GitHub build/SBOM attestations and publishes with short-lived OIDC
   credentials, then attaches the distributions and SBOM to a GitHub Release
   using the notes extracted for that version. PyPI publishing also generates PyPI publish
   attestations. Only this publishing job has repository contents-write
   permission, needed to create that release. There
   is no stored token, source checkout or build execution in the privileged job.
6. Verify the PyPI version, wheel install, command version/doctor, bundled assets
   and provenance before announcing availability. Actions artifacts are retained for 30 days; the GitHub Release
   retains distributions and the SBOM for long-term records. Repository settings
   are not altered.

Verify GitHub provenance after downloading a distribution:

```sh
gh attestation verify finledgerpoli-0.3.0-py3-none-any.whl --repo EleutheroiEdge/finance-dev-assistant
```

The [GitHub attestation guide](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations) explains identity verification.

## Limits

Publishing requires account and repository setup by an authorized maintainer, and each exact release must pass the gates job before anything is published. Development does not authorize tags or publication. A fork does not inherit publisher authority. An SBOM inventories dependencies, not vulnerabilities; provenance binds identity and bytes, not correctness. A partial publication must be reconciled before any retry; published files cannot be overwritten. Do not delete or move tags to hide an attempt; fix through a new reviewed version. See the [threat model](../threat-model.md).
