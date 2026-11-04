# GitHub Actions check gates

For the separate opt-in policy-approved model component, see
[Using finledgerpoli as a pre-merge gate](pre-merge-gate.md). The v1 check policy
and default Action mode described here retain their existing behavior.

Run finledgerpoli automatically on pull requests under a reviewed, pinned CI
policy. Version 1 supports deterministic checks in digest-pinned, network-disabled
Docker or Podman containers. The action emits a failing job for blocked or
unknown work and reports which obligations remain unmet. No developer prompt is
needed for work already authorized by that policy.

This is a check gate, not AI approval or full `verify-gate` readiness. A policy
with `review: "required"` is deliberately blocked with `ci_model_review_required`:
unattended model authorization, shared cross-job spending and imported model
evidence are not implemented in this version. Existing interactive request-hash
approvals and model-review readiness requirements remain unchanged.

## Trust and policy selection

The workflow owner supplies a repository-relative policy path and its exact
raw-byte SHA-256. The gate reads that file from the PR event's immutable **base
commit**, never the PR's working-tree copy. It checks the expected repository,
origin routing, event, target branch, head revision, fork policy, source coverage,
required recipes and check budgets before recording authorization or dispatch.
Policy events and executed plans are linked by hashes in the private audit log.

Version 1 accepts only `pull_request` events and a checkout of that event's exact
head SHA. `pull_request_target`, `workflow_run`, `push` and `merge_group` are
refused. The result describes the tested PR head, not a test-merge commit or
merge-queue candidate. Another normal CI job must test integration with the base.

The policy path, `.github/`, methodology references and configured `guard_paths`
are guarded. Changing them requires review and adoption through the protected
base; a PR cannot approve its own policy pin or silently change governing rules.
The guard compares both the PR change set and its tree against the current base.
A stale PR retaining superseded guarded checks or methodology is blocked until
those files match the reviewed base, even if the PR did not edit them directly.
Configure guard paths for trusted check implementations and fixtures as needed.
Check execution still uses candidate source: passing code can implement an
inadequate check, so financial semantics require independent review.

**Protect the CI wiring itself.** Use a pinned action from a trusted external
checkout and your organization's reviewed-workflow/ruleset/CODEOWNERS controls.
A PR-controlled workflow that removes this action or forges a successful job
cannot be secured by code that is never invoked. Do not use `./actions/gate` from
an untrusted PR checkout, or run PR-controlled host scripts/installations before
the gate. Repository administrators remain responsible for those controls.

## Configure one policy

Start with the [synthetic policy](../examples/github-actions/finassist-ci.json)
and [fixture project](https://github.com/EleutheroiEdge/finance-dev-assistant/tree/main/examples/github-actions/fixture).
Replace its repository, branches, methodology, image and approved recipes with
your project's reviewed values. The fictional cash rule is not tax, portfolio
or financial advice. Policy fields are strict; unknown keys/versions, duplicate
JSON keys and nonfinite numbers are refused.
Policy blobs are limited to 128,000 bytes and event JSON to 1,000,000 bytes.

| Field | Meaning |
| --- | --- |
| `schema_version` | Integer `1` |
| `repository` | Exact GitHub owner/repository |
| `events` | `["pull_request"]` |
| `base_branches` | Explicit allowed target branch names |
| `forks` | `deny` or `checks-only`; neither grants credentials or model access |
| `backend` | `docker` or `podman`; no host execution fallback |
| `review` | `not-requested`, or `required` which blocks until supported evidence exists |
| `guard_paths` | Exact paths or literal directory prefixes ending in `/` |
| `max_steps` | 1–64; a graph larger than this is blocked before dispatch |
| `max_check_seconds` | 1–3600; caps the sum of configured recipe timeouts |
| `config` | Existing configuration with offline provider, network/partial/local readiness disabled and no external profile files |
| `workflow` | Complete version-1 workflow template accounting for required recipes |

The check-time estimate is not an overall wall-clock limit: snapshot preparation,
container cleanup and startup add overhead. Set a separate Actions job timeout.
Budgets do not authorize model requests. There is no model-key input, provider
fallback or automatic image pulling by the gate. No target PR package is
installed on the host. Prepare the exact image through reviewed workflow setup.

After committing the reviewed policy to the protected base, calculate its pin:

```sh
python -c "import hashlib,subprocess; print(hashlib.sha256(subprocess.check_output(['git','show','main:finassist-ci.json'])).hexdigest())"
```

This hashes exact blob bytes without a shell text pipeline. Line endings and
whitespace matter. Inspect the policy and record the pin in the trusted workflow; do not
compute and approve a PR-supplied policy dynamically during the job.

## Install the action

The [reference workflow](https://github.com/EleutheroiEdge/finance-dev-assistant/blob/main/examples/github-actions/financial-gate.yml)
is a template, not an active workflow. Replace its action revision with a full
reviewed commit SHA and its policy pin with the reviewed hash. It checks out the
PR head with full history and no persistent checkout credentials, prepares the
example's pinned image, and invokes:

```yaml
- uses: EleutheroiEdge/finance-dev-assistant/actions/gate@FULL_REVIEWED_COMMIT_SHA
  with:
    policy-path: finassist-ci.json
    policy-sha256: FULL_REVIEWED_POLICY_BYTES_SHA256
```

The composite action initially supports Linux runners with Python 3.11+ and a
reviewed available container daemon. It bootstraps a fresh private environment
from the action's own pinned source, using isolated Python/pip and a hash-locked
runtime/build subset of the existing development lock. Installation downloads
those dependencies from PyPI; model/provider calls remain disabled. Target PR
packages are never installed on the host. Version-1 GitHub App/webhook publishing
and PR-comment writes are not included.

Use a stable job name, and have the repository owner select that check in branch
protection after testing it. Avoid conditional skips or `continue-on-error` on a
required gate. A successful skipped job must not be mistaken for completed
validation. No branch setting is changed by installing these files.

## CLI, results and retained state

The same adapter can be called by trusted CI wiring:

```sh
finassist ci gate --repo CHECKOUT --event EVENT_FILE --event-name pull_request \
  --repository OWNER/REPOSITORY --policy finassist-ci.json \
  --policy-sha256 REVIEWED_POLICY_HASH --state-dir PRIVATE_STATE --output NEW_REPORT
```

Global `--config` is refused: configuration must come from the pinned base
policy. The global `--audit-dir` can select the same private state root in place
of `--state-dir`. Event identity is a trusted-runner input, not cryptographic
proof of a GitHub event. Origin checking prevents accidental routing mistakes;
it cannot defeat a malicious runner rewriting all local metadata.

Exit 0 requires all obligations completed successfully with verified saved
results and unchanged source. Paused, failed, unknown, missing or incomplete
work never passes. Exit 1 means a known blocked result; exit 2 means refused
input, unavailable auditing/runtime or handled operational error. Reports expose
status, exact source/policy/configuration/plan hashes, required/completed counts,
model-review status and stable reason codes. They grant no merge/deploy authority.
Preflight refusals stop before packet creation or dispatch. A null `packet_hash`
means source coverage was not assessed; blocking reasons are not an exhaustive
inventory of problems in a refused candidate.

The action adds a reduced job summary and `status`, `report-hash`, `report-path`
outputs. Summary/output projection excludes PR bodies, raw source, recipe
arguments, test output and arbitrary exception text. The report is private under
`RUNNER_TEMP`; raw source/check artifacts are not uploaded automatically. Protect
retained artifacts and do not publish private audit files.

Per-job state records authorization, dispatch and outcomes with the existing
durable workflow ledger. Open reservations, unfinished commands or unfinished
workflows in a supplied state directory block new work. The action uses a fresh
private directory per invocation; this is not a cross-job billing coordinator or
an exactly-once service. Required-model policies remain blocked even if a key is
present. Do not erase state to make an uncertain attempt pass; inspect it through
normal workflow status/timeline and reconciliation commands.

Local unit tests use fake isolated-runner results. The installed-wheel smoke
exercises policy refusal without dispatch. The existing hosted container job
also exercises a passing fictional workflow and a seeded deposit-sign defect
that ordinary unit tests miss but the mandatory cash invariant blocks. It repeats
both cases through the full Action bootstrap, checking private report hashes,
job summaries and exit codes after installing the trusted action source. The
pilot supplies synthetic event metadata and changes no repository settings; it
does not claim deployment into a consumer repository. These
are synthetic control checks, not measured live model quality or certification.


## Synthetic fixture policy

Checks policies may opt into `fixture_roots` and `fixture_max_file_bytes` at the
policy top level, outside `config`. These fields are read from the hash-pinned
base policy only. See the [fixture policy contract](pre-merge-gate.md#policy-owned-synthetic-text-fixtures)
for structural roots, base-only `.finledgerpoli-synthetic` markers, literal scope,
the 48,000-byte default and 2,000,000-byte hard ceiling. This is a synthetic-data
attestation, never permission for client/private/data paths. Existing guard paths
still apply; the owner must review the intended fixture-change scope explicitly.
CI checks retain isolated execution and never gain model/network authority.


## Build and pin a consumer runner image

The runtime never installs project dependencies or pulls an image while executing
checks. Build a reviewed runner first, on a trusted build host, independently of
candidate PR code. The following example targets Linux x86-64 / Python 3.13 and
extends [examples/runner.Dockerfile](https://github.com/EleutheroiEdge/finance-dev-assistant/blob/main/examples/runner.Dockerfile). Its upstream
Python 3.13.7 image is already pinned there; this is an example baseline, not a
claim that the old pin is the latest patched image. Review base-image updates
and repeat validation before adopting a different pin.

Create `requirements-runner.in` in a dedicated build directory containing only
the Dockerfile and dependency files (no source checkout, credentials or data):

```text
pytest==9.2.0
clarabel==0.11.1
```

These are direct version pins, not a complete lock. With a reviewed resolver
(for example the repository's pinned uv 0.12.17), generate a lock for the target:

```sh
uv pip compile requirements-runner.in --python-version 3.13 \
  --python-platform x86_64-unknown-linux-gnu --no-build --generate-hashes \
  --output-file requirements-runner.lock
```

Inspect and retain the resulting exact versions and hashes of **all transitive
dependencies**, including NumPy/SciPy/CFFI as selected for Clarabel. Add the
consumer's other required packages to the input and regenerate/review the lock.
Do not copy this product's development lock and assume it contains consumer
packages. Resolution and installation need approved package access; check-time
network isolation does not make image preparation offline. No generated consumer
lock or verified consumer image is shipped by this example. Resolver target
flags are best-effort compatibility selection: build and test on the actual
CI platform. See [uv compilation](https://docs.astral.sh/uv/pip/compile/) and
[target resolution](https://docs.astral.sh/uv/concepts/resolution/).

Use this Dockerfile in that same small build directory:

```dockerfile
# Same reviewed Python baseline as examples/runner.Dockerfile.
FROM python@sha256:5f55cdf0c5d9dc1a415637a5ccc4a9e18663ad203673173b8cda8f8dcacef689
COPY requirements-runner.lock /tmp/requirements-runner.lock
RUN python -m pip install --no-cache-dir --require-hashes --only-binary=:all: -r /tmp/requirements-runner.lock
ENV PYTHONPATH=/workspace/src:/workspace
ENV PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
ENV PYTHONDONTWRITEBYTECODE=1
USER 65534:65534
WORKDIR /workspace
```

Missing compatible wheels fail the build; do not silently enable source builds
or install candidate packages on the host to get past that failure. Dependencies
must already exist in the image when the network-disabled check starts. If a
reviewed pytest plugin is required, pin it in the lock and explicitly load it
with `-p PLUGIN` in the recipe; automatic plugin loading stays disabled.

```sh
docker build --platform linux/amd64 --tag finassist-consumer-runner:reviewed .
docker image inspect --format '{{.Id}}' finassist-consumer-runner:reviewed
```

The second command returns a local `sha256:...` image ID accepted by
`runner_image` on that same daemon. A local ID is not a portable registry
manifest digest. To distribute the image, use your separately approved registry
publication process, then pull the reviewed registry reference on the target
runner and inspect `docker image ls --digests` or `RepoDigests`. Record the
matching `REGISTRY/REPOSITORY@sha256:...` reference, target platform, Dockerfile
and lock bytes. Never substitute a mutable tag or invent a digest from a
Dockerfile hash. Docker documents [digest pulls](https://docs.docker.com/reference/cli/docker/image/pull/)
and [digest listings](https://docs.docker.com/reference/cli/docker/image/ls/).
Prepare the exact pinned image in trusted CI setup; the gate uses `--pull=never`.

### Exact test IDs on a read-only workspace

This standalone configuration selects an existing synthetic fixture test by its
full pytest node ID and keeps the separate mandatory cash invariant. Save it as
`finassist.json` at the fixture project root for a local example. The all-`a`
image ID below is a **schema-test placeholder**, not an available image: replace
it with the actual inspected local ID or registry digest before execution.

```json
{
  "provider": "offline",
  "allow_network": false,
  "runner_image": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "timeout_seconds": 30,
  "recipes": {
    "unit": ["python", "-m", "pytest", "-q", "-p", "no:cacheprovider", "--basetemp=/tmp/pytest", "tests/test_unit.py::CashTests::test_no_activity"],
    "cash": ["python", "-m", "tests.check_cash"]
  },
  "required_recipes": ["unit", "cash"]
}
```

The fixture lives in `examples/github-actions/fixture`. For a consumer, replace
its node ID with reviewed IDs from that consumer's collected suite; each ID is
one argv element, including a complete `[parameter-id]` suffix if selecting a
parameterized case. Recipes are argv arrays, not shell strings. Selecting a
narrow reproduction must not remove required full-suite or financial checks.

`-p no:cacheprovider` prevents `.pytest_cache` writes; disabled bytecode prevents
`__pycache__` writes. `--basetemp=/tmp/pytest` uses the runner's per-container
writable `/tmp` tmpfs, not the read-only `/workspace`. Configure any coverage,
reporting or other plugin output explicitly under `/tmp`; flags cannot prevent
a test that writes into its source directory from failing. The runner retains
its non-root user, read-only filesystem/workspace, bounded tmpfs/resources and
network isolation. A Windows/macOS Docker client still needs a Linux-container
engine; this example does not describe native Windows containers.

For a CI policy, copy the reviewed `runner_image`, recipes and required recipe
names into its **config** object, and align workflow requirements/steps and time
budgets. Commit the policy and trusted tests to the protected base through review,
then recompute the exact policy-blob SHA256 as described above. Never generate a
new approved pin from candidate PR bytes. Validate configuration, run the exact
recipes in the pinned image with synthetic inputs and retain their results
before adopting it. The offline documentation test validates the JSON and node
ID against the fixture; it does not build an image, resolve packages, exercise
Clarabel or establish financial correctness.
