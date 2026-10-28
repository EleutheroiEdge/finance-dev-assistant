# Releasing finassist

The PyPI distribution, Python import and executable are named `finassist`.
Version 0.3.0 is the first intended public release. The repository name remains
`finance-dev-assistant`. On 2026-10-28 the PyPI project, JSON and simple-index
endpoints for `finassist` returned 404. This is an availability observation, not
reservation or a guarantee: PyPI may reject a reserved name. Recheck before setup;
if it is unavailable, choose another distribution name before publishing.

## One-time owner setup

These are account and repository settings changes. An owner must explicitly
approve and perform them; preparing this workflow does not configure them.

1. Sign in to PyPI with a secured owner account. For a new project, create a
   [pending Trusted Publisher](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/)
   with project name `finassist`, GitHub owner `EleutheroiEdge`, repository
   `finance-dev-assistant`, workflow filename **`release.yml`** and environment
   **`pypi`**. For an existing owned project, add the same publisher from its
   Publishing page. No API token or GitHub secret is needed.
2. In GitHub Settings → Environments, create **`pypi`**. Add at least one trusted
   maintainer/team under **Required reviewers**. Each publish must wait for human
   approval. Disable administrator bypass where available. For a sole maintainer,
   enabling “Prevent self-review” requires another eligible reviewer; choose a
   workable policy deliberately. Restrict deployment refs to the reviewed `v*`
   release tags using environment tag rules. Keep branch and tag protections.
3. Review the exact workflow pins and permissions before merging. Restrict who
   can create or update release tags using repository rules. Fork owners must
   replace the package name, publisher identity, repository links and reviewers
   with their own; a fork does not inherit publishing authority.

See [PyPI publisher configuration](https://docs.pypi.org/trusted-publishers/adding-a-publisher/)
and [Trusted Publishing usage](https://docs.pypi.org/trusted-publishers/using-a-publisher/).
A missing environment or reviewer fails the read-only build preflight. If the
runner cannot read environment metadata, stop and resolve access with the owner;
do not remove that guard or add an upload token as a workaround.

## Review and release

1. Merge reviewed release source through a PR with all required CI green. Confirm
   project/package versions agree, release notes are complete, and the dashboard
   assets are current. Run tests, Ruff, the demo and publication scan.
2. Review source and dependencies, then build locally with `python -m build`.
   The release builds an sdist and then a wheel from that sdist. Verify both
   installed-wheel CLI and dashboard smoke checks. Node/pnpm are build-time tools.
3. The owner creates and pushes the exact stable tag, for example `v0.3.0`, on the
   reviewed main commit. **Do not push a tag during development or review.** The
   workflow runs only for pushed `v*` tags; it has no manual, branch or PR trigger.
   The tag must exactly match the version and its commit must be in main.
4. Inspect the build run and download `release-<commit>` from Actions. It contains
   the wheel, sdist and `release-sbom.spdx.json`. The SBOM inventories source
   manifests, lockfiles and built distributions, including development dependencies;
   it is not a vulnerability report or a minimal runtime-only inventory.
5. The required reviewer approves the `pypi` job only after inspecting artifacts
   and the exact commit. That job downloads the same artifact from the same run,
   records GitHub build/SBOM attestations and publishes with short-lived OIDC
   credentials. PyPI publishing also generates PyPI publish attestations. There
   is no stored token, source checkout or build execution in the privileged job.
6. Verify the PyPI version, wheel install, command version/doctor, bundled assets
   and provenance before announcing availability. Add the PyPI badge only after
   publication. This workflow preserves Actions artifacts for 30 days; download
   and retain the SBOM for long-term release records. It does not create a GitHub
   Release or alter repository settings.

Verify GitHub provenance after downloading a distribution:

```sh
gh attestation verify finassist-0.3.0-py3-none-any.whl --repo EleutheroiEdge/finance-dev-assistant
```

The [GitHub attestation guide](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)
explains identity verification. Provenance establishes workflow identity and byte
binding; it does not establish correctness or freedom from vulnerabilities.

If publication is partial or uncertain, inspect PyPI and workflow evidence before
retrying. Version files on PyPI cannot be overwritten; do not delete or move tags
to hide a failed attempt. Fix through a new reviewed version when necessary.
