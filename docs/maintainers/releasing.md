# Releasing finledgerpoli

Prepare, inspect and publish finledgerpoli releases through a tag-only build and a human-approved publishing environment. The PyPI distribution is **`finledgerpoli`**. The Python import package and primary
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
2. In GitHub Settings → Environments, create **`pypi`**. Add at least one trusted
   maintainer/team under **Required reviewers**. Each publish must wait for human
   approval. Disable administrator bypass where available. For a sole maintainer,
   enabling “Prevent self-review” requires another eligible reviewer; choose a
   workable policy deliberately. Restrict deployment refs to the reviewed `v*`
   release tags using environment tag rules. Keep branch and tag protections.
3. Review the exact workflow pins and permissions before merging. Restrict who
   can create or update release tags using repository rules. Fork maintainers must
   replace the package name, publisher identity, repository links and reviewers
   with their own; a fork does not inherit publishing authority.

See [PyPI publisher configuration](https://docs.pypi.org/trusted-publishers/adding-a-publisher/)
and [Trusted Publishing usage](https://docs.pypi.org/trusted-publishers/using-a-publisher/).
A missing environment or reviewer fails the read-only build preflight. If the
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
5. The required reviewer approves the `pypi` job only after inspecting artifacts
   and the exact commit. That job downloads the same artifact from the same run,
   records GitHub build/SBOM attestations and publishes with short-lived OIDC
   credentials, then attaches the distributions and SBOM to a GitHub Release
   using the notes extracted for that version. PyPI publishing also generates PyPI publish
   attestations. Only this approval-gated job has repository contents-write
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

Publishing requires account and repository setup by an authorized maintainer, followed by approval of each exact release. Development does not authorize tags or publication. A fork does not inherit publisher authority. An SBOM inventories dependencies, not vulnerabilities; provenance binds identity and bytes, not correctness. A partial publication must be reconciled before any retry; published files cannot be overwritten. Do not delete or move tags to hide an attempt; fix through a new reviewed version. See the [threat model](../threat-model.md).
